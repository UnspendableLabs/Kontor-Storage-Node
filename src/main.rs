mod bls;
mod cli;
mod clients;
mod config;
mod daemon;
mod database;
mod entities;
mod onboarding;
mod server;
mod tasks;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sea_orm::DatabaseConnection;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::{pin, signal, sync::oneshot};
use tracing_subscriber::{fmt, EnvFilter};

use cli::{Cli, Commands};
use clients::PortalClient;
use config::{Config, StorageMethod};
use daemon::{spawn_portal_daemon, StorageLimits};
use database::DBClient;
use tasks::downloadagreements::StorageBackend;

struct DaemonConfig {
    client: PortalClient,
    conn: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
    download_addr: SocketAddr,
    node_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    load_local_env()?;
    let cli = Cli::parse();
    let mut stdout = io::stdout();
    run(cli, &mut stdout).await
}

fn load_local_env() -> Result<()> {
    match std::fs::metadata(".env.local") {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(anyhow!("failed to load .env.local: path is a directory"));
            }

            let contents =
                std::fs::read_to_string(".env.local").context("failed to read .env.local")?;
            dotenvy::from_read(contents.as_bytes()).context("failed to load .env.local")?;
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).context("failed to stat .env.local"),
    }
}

async fn run(cli: Cli, writer: impl Write) -> Result<()> {
    run_with_shutdown(cli, writer, signal::ctrl_c()).await
}

async fn run_with_shutdown(
    cli: Cli,
    mut writer: impl Write,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let config = Config::from_cli(&cli)?;
    writeln!(writer, "Node ID: {}", config.node_id)?;
    writeln!(writer, "Portal URL: {}", config.portal_url)?;
    writeln!(writer, "Database URL: {}", config.database_url)?;
    writeln!(writer, "Storage method: {}", config.storage_method)?;
    if config.storage_method == StorageMethod::Gcs {
        let bucket = config
            .storage_gcs_bucket_name
            .as_deref()
            .unwrap_or("<missing bucket>");
        writeln!(writer, "GCS bucket name: {bucket}")?;
    } else {
        writeln!(writer, "Storage dir: {}", config.storage_dir.display())?;
    }
    match config.storage_capacity {
        Some(bytes) => writeln!(writer, "Storage capacity: {bytes} bytes")?,
        None => writeln!(writer, "Storage capacity: unlimited")?,
    }
    match config.storage_max_file_size {
        Some(bytes) => writeln!(writer, "Max file size: {bytes} bytes")?,
        None => writeln!(writer, "Max file size: unlimited")?,
    }
    match config.storage_max_files {
        Some(limit) => writeln!(writer, "Max stored files: {limit}")?,
        None => writeln!(writer, "Max stored files: unlimited")?,
    }
    writeln!(
        writer,
        "Portal polling interval: {}s",
        config.portal_polling_interval.as_secs()
    )?;

    std::fs::create_dir_all(&config.storage_dir).with_context(|| {
        format!(
            "failed to create storage directory {}",
            config.storage_dir.display()
        )
    })?;

    let client = PortalClient::new(&config.portal_url, &config.storage_dir);

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            writeln!(writer, "{body}")?;
        }
        Commands::Run => {
            // Perform node onboarding (verify registration and BLS key)
            let onboarding_config = onboarding::OnboardingConfig {
                bls_key_path: config.bls_key_path.clone(),
            };
            let onboarding_result = onboarding::perform_onboarding(
                &client,
                &config.node_id,
                &onboarding_config,
                &mut writer,
            )
            .await?;

            writeln!(writer)?;
            writeln!(writer, "Node onboarding complete. Starting services...")?;
            writeln!(writer)?;

            // Create authenticated client with the BLS keypair from onboarding
            let authenticated_client = PortalClient::with_auth(
                &config.portal_url,
                &config.storage_dir,
                Arc::new(onboarding_result.keypair),
                &config.node_id,
            );

            let db = DBClient::new(&config.database_url).await?;
            let conn = db.connection().clone();
            let storage_backend = StorageBackend::new(
                config.storage_method.clone(),
                config.storage_gcs_bucket_name.clone(),
                config
                    .storage_gcs_service_account_json
                    .as_ref()
                    .map(PathBuf::from),
            )
            .await?;

            let lock_path = config.storage_dir.join(".portal-daemon.lock");
            let download_addr: SocketAddr = config
                .server_address
                .parse()
                .context("invalid server address")?;

            let storage_limits = StorageLimits {
                capacity: config.storage_capacity,
                max_file_size: config.storage_max_file_size,
                max_files: config.storage_max_files,
            };
            run_daemon_command(
                DaemonConfig {
                    client: authenticated_client,
                    conn,
                    interval: config.portal_polling_interval,
                    lock_path,
                    storage_limits,
                    storage_backend,
                    storage_dir: config.storage_dir.clone(),
                    download_addr,
                    node_id: config.node_id.clone(),
                },
                shutdown,
            )
            .await?;
        }
    }

    Ok(())
}

async fn run_daemon_command(
    config: DaemonConfig,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let daemon_backend = config.storage_backend.clone();
    let handle = spawn_portal_daemon(
        config.client,
        config.conn.clone(),
        config.interval,
        config.lock_path,
        config.storage_limits,
        daemon_backend,
        config.storage_dir.clone(),
    );

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let server = server::serve(
        config.download_addr,
        server::DownloadServerState {
            db: config.conn,
            storage_dir: config.storage_dir,
            storage_backend: config.storage_backend,
            node_id: config.node_id,
        },
        async move {
            let _ = server_shutdown_rx.await;
        },
    );

    pin!(server);
    pin!(shutdown);

    let shutdown_result = tokio::select! {
        server_result = &mut server => {
            handle.abort();
            let _ = handle.await;
            return server_result;
        }
        shutdown_result = &mut shutdown => shutdown_result,
    };

    let _ = server_shutdown_tx.send(());

    let server_result = server.await;

    handle.abort();
    let _ = handle.await;

    server_result?;
    shutdown_result?;
    Ok(())
}

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let _ = fmt()
            .with_env_filter(filter)
            .with_target(true)
            .compact()
            .try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future;
    use serde_json::json;
    use std::env;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};
    use tokio::time::{sleep, Duration};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Environment variable used to override the app directory.
    /// This ensures tests don't write to the real application config directory.
    const APP_DIR_ENV_VAR: &str = "KONTOR_APP_DIR";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_storage_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_main_{prefix}_{id}"))
    }

    /// Returns a unique temporary directory for test app data to avoid conflicts.
    fn test_app_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("main")
            .join(format!("{prefix}_{id}"))
    }

    /// RAII guard that sets KONTOR_APP_DIR to a temporary directory and restores
    /// the original value when dropped. This works with both sync and async tests.
    struct TempAppDirGuard {
        previous: Option<String>,
        dir: PathBuf,
    }

    impl TempAppDirGuard {
        fn new(prefix: &str) -> Self {
            let dir = test_app_dir(prefix);
            // Clean up any leftover files from previous test runs
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test app dir");
            let previous = std::env::var(APP_DIR_ENV_VAR).ok();
            std::env::set_var(APP_DIR_ENV_VAR, &dir);
            Self { previous, dir }
        }
    }

    impl Drop for TempAppDirGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(val) => std::env::set_var(APP_DIR_ENV_VAR, val),
                None => std::env::remove_var(APP_DIR_ENV_VAR),
            }
            // Clean up the temp directory
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_writes_ping_output() {
        let _guard = TempAppDirGuard::new("ping_output");
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            node_id: Some("NODE-test123".to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/storage")),
            portal_polling_interval_secs: 5,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        run(cli, &mut buffer).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(
            output.contains("Node ID:"),
            "expected node id line in output"
        );
        assert!(
            output.contains("Portal URL:"),
            "expected portal url line in output"
        );
        assert!(
            output.contains("Database URL:"),
            "expected database url line in output"
        );
        assert!(
            output.contains("Storage method:"),
            "expected storage method line in output"
        );
        assert!(
            output.contains("Storage dir:"),
            "expected storage dir line in output"
        );
        assert!(
            output.contains("Storage capacity:"),
            "expected storage capacity line in output"
        );
        assert!(
            output.contains("pong"),
            "expected ping response in output, got {output}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_propagates_ping_error() {
        let _guard = TempAppDirGuard::new("ping_error");
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            node_id: Some("NODE-test456".to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/storage")),
            portal_polling_interval_secs: 5,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        let err = run(cli, &mut buffer).await.unwrap_err();

        assert!(
            err.to_string().contains("Portal ping failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_prints_gcs_bucket_when_storage_method_is_gcs() {
        let _guard = TempAppDirGuard::new("gcs_bucket");
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let service_account_path = unique_storage_dir("sa").join("service_account.json");
        std::fs::create_dir_all(service_account_path.parent().unwrap()).unwrap();
        std::fs::write(
            &service_account_path,
            r#"{"private_key":"dummy","client_email":"test@example.com"}"#,
        )
        .unwrap();

        let cli = Cli {
            node_id: Some("NODE-gcs-test".to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/storage")),
            portal_polling_interval_secs: 5,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "gcs".to_string(),
            storage_gcs_bucket_name: Some("my-bucket".to_string()),
            storage_gcs_service_account_json: Some(
                service_account_path.to_string_lossy().to_string(),
            ),
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        run(cli, &mut buffer).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(
            output.contains("Storage method: gcs"),
            "expected storage method to be printed, got {output}"
        );
        assert!(
            output.contains("GCS bucket name: my-bucket"),
            "expected gcs bucket line in output, got {output}"
        );
        assert!(
            !output.contains("Storage dir:"),
            "should not print storage dir when using gcs"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_prints_limits_when_configured() {
        let _guard = TempAppDirGuard::new("limits");
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("limits");
        let cli = Cli {
            node_id: Some("NODE-limits".to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir.clone()),
            portal_polling_interval_secs: 3,
            storage_capacity: Some("2GB".into()),
            storage_max_file_size: Some("50MB".into()),
            storage_max_files: Some(7),
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        run(cli, &mut buffer).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(
            output.contains("Storage capacity: 2000000000 bytes"),
            "expected capacity line, got {output}"
        );
        assert!(
            output.contains("Max file size: 50000000 bytes"),
            "expected max file size line, got {output}"
        );
        assert!(
            output.contains("Max stored files: 7"),
            "expected max files line, got {output}"
        );

        std::fs::remove_dir_all(storage_dir).ok();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_errors_when_storage_dir_is_file() {
        let _guard = TempAppDirGuard::new("dir_as_file");
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let storage_file = unique_storage_dir("dir_as_file");
        fs::create_dir_all(storage_file.parent().unwrap()).unwrap();
        fs::write(&storage_file, "not a directory").unwrap();

        let cli = Cli {
            node_id: Some("NODE-dirfile".to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_file.clone()),
            portal_polling_interval_secs: 5,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: None,
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        let err = run(cli, &mut buffer).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to create storage directory"),
            "expected storage dir creation error, got {err}"
        );

        std::fs::remove_file(storage_file).ok();
    }

    /// Helper to set up onboarding fixtures for tests.
    /// Creates a BLS key file and mocks the portal to return a matching node.
    async fn setup_onboarding_fixtures(
        mock_server: &MockServer,
        node_id: &str,
        storage_dir: &PathBuf,
    ) -> PathBuf {
        use crate::bls::BlsKeyPair;

        let password = "testpassword123";
        let key_path = storage_dir.join("bls_key.enc");

        // Generate and save BLS keypair
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        fs::create_dir_all(storage_dir).unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Set password in environment for non-interactive mode
        env::set_var(onboarding::BLS_PASSWORD_ENV, password);

        // Mock portal node check endpoint
        Mock::given(method("GET"))
            .and(path(format!("/api/nodes/{}/check", node_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": node_id,
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": public_key
            })))
            .mount(mock_server)
            .await;

        key_path
    }

    /// Cleanup onboarding environment after test.
    fn cleanup_onboarding_env() {
        env::remove_var(onboarding::BLS_PASSWORD_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_starts_daemon_and_aborts_on_shutdown() {
        let _guard = TempAppDirGuard::new("daemon");
        cleanup_onboarding_env(); // Ensure clean state
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("daemon");
        let node_id = "NODE-daemon";

        // Set up onboarding fixtures
        let bls_key_path = setup_onboarding_fixtures(&mock_server, node_id, &storage_dir).await;

        // Mock agreements endpoint
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            node_id: Some(node_id.to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir.clone()),
            portal_polling_interval_secs: 1,
            storage_capacity: Some("1GB".into()),
            storage_max_file_size: None,
            storage_max_files: Some(5),
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: Some(bls_key_path),
            command: Commands::Run,
        };

        let shutdown = async {
            sleep(Duration::from_millis(50)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        // Cleanup
        cleanup_onboarding_env();

        assert!(
            output.contains("Portal polling interval:"),
            "expected polling interval in output: {output}"
        );
        assert!(
            output.contains("Node onboarding complete"),
            "expected onboarding complete message: {output}"
        );

        let lock_path = storage_dir.join(".portal-daemon.lock");
        assert!(
            !lock_path.exists(),
            "lock file should be cleaned up after shutdown"
        );

        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            !requests.is_empty(),
            "daemon should poll the portal at least once"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_propagates_shutdown_error() {
        let _guard = TempAppDirGuard::new("shutdown_error");
        cleanup_onboarding_env(); // Ensure clean state
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("shutdown_error");
        let node_id = "NODE-shutdown";

        // Set up onboarding fixtures
        let bls_key_path = setup_onboarding_fixtures(&mock_server, node_id, &storage_dir).await;

        // Mock agreements endpoint
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            node_id: Some(node_id.to_string()),
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir.clone()),
            portal_polling_interval_secs: 1,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            bls_key_path: Some(bls_key_path),
            command: Commands::Run,
        };

        let shutdown = async { Err(io::Error::other("ctrlc failure")) };

        let mut buffer = Vec::new();
        let err = run_with_shutdown(cli, &mut buffer, shutdown)
            .await
            .unwrap_err();

        // Cleanup
        cleanup_onboarding_env();

        assert!(
            err.to_string().contains("ctrlc failure"),
            "expected shutdown error to be propagated, got {err}"
        );

        let lock_path = storage_dir.join(".portal-daemon.lock");
        assert!(
            !lock_path.exists(),
            "lock file should be cleaned even when shutdown fails"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    #[tokio::test]
    async fn run_daemon_command_returns_server_error_when_binding_fails() {
        let storage_dir = unique_storage_dir("bind_error");
        let lock_path = storage_dir.join(".portal-daemon.lock");
        let db = DBClient::new("sqlite::memory:").await.unwrap();
        let storage_backend = StorageBackend::local();
        let portal_client = PortalClient::new("http://localhost:0", storage_dir.clone());
        let storage_limits = StorageLimits {
            capacity: None,
            max_files: Some(0),
            max_file_size: None,
        };
        let shutdown = future::pending::<io::Result<()>>();

        let err = run_daemon_command(
            DaemonConfig {
                client: portal_client,
                conn: db.connection().clone(),
                interval: Duration::from_millis(10),
                lock_path: lock_path.clone(),
                storage_limits,
                storage_backend,
                storage_dir: storage_dir.clone(),
                download_addr: "127.0.0.1:1".parse().unwrap(),
                node_id: "NODE-TEST".to_string(),
            },
            shutdown,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("binding download server"),
            "expected download server bind error, got {err}"
        );

        std::fs::remove_file(&lock_path).ok();
        std::fs::remove_dir_all(&storage_dir).ok();
    }

    #[test]
    fn load_local_env_returns_ok_when_missing() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_missing");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let result = load_local_env();

        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();
        assert!(result.is_ok(), "missing .env.local should not error");
    }

    #[test]
    fn load_local_env_propagates_io_error() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_error");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let env_path = temp_dir.join(".env.local");
        std::fs::write(&env_path, "SHOULD_NOT_LOAD=1").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = load_local_env();

        #[cfg(unix)]
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).ok();
        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();

        assert!(
            result.is_err(),
            "directory at .env.local should cause an IO error"
        );
    }

    #[test]
    fn load_local_env_errors_when_env_is_directory() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_dir");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let env_dir = temp_dir.join(".env.local");
        std::fs::create_dir_all(&env_dir).unwrap();

        let result = load_local_env();

        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("path is a directory"),
            "expected directory .env.local to be rejected"
        );
    }

    #[test]
    fn load_local_env_reads_file_and_sets_vars() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_file");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        std::fs::write(temp_dir.join(".env.local"), "FOO=bar\nBAZ=qux").unwrap();
        env::remove_var("FOO");
        env::remove_var("BAZ");

        let result = load_local_env();

        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();

        assert!(result.is_ok());
        assert_eq!(env::var("FOO").unwrap(), "bar");
        assert_eq!(env::var("BAZ").unwrap(), "qux");
    }

    #[cfg(unix)]
    #[test]
    fn load_local_env_propagates_metadata_error() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_metadata");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let protected_dir = temp_dir.join("protected");
        std::fs::create_dir_all(&protected_dir).unwrap();
        std::fs::write(protected_dir.join("secret.env"), "FOO=bar").unwrap();
        std::fs::set_permissions(&protected_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let symlink_path = temp_dir.join(".env.local");
        symlink(protected_dir.join("secret.env"), &symlink_path).unwrap();

        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();
        let result = load_local_env();

        std::fs::set_permissions(&protected_dir, std::fs::Permissions::from_mode(0o700)).ok();
        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();

        assert!(
            result.is_err(),
            "metadata permission error should be propagated"
        );
    }

    #[test]
    fn init_logging_runs_once() {
        init_logging();
        init_logging();
    }
}
