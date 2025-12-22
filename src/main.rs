mod cli;
mod clients;
mod config;
mod daemon;
mod database;
mod entities;
mod server;
mod tasks;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sea_orm::DatabaseConnection;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;
use tokio::{pin, signal, sync::oneshot};
use tracing_subscriber::{fmt, EnvFilter};

use cli::{Cli, Commands};
use clients::PortalClient;
use config::{Config, StorageMethod};
use daemon::{spawn_portal_daemon, StorageLimits};
use database::DBClient;
use tasks::downloadagreements::StorageBackend;

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
    let client = PortalClient::new(
        &config.portal_url,
        &config.portal_api_key,
        &config.storage_dir,
    );
    let lock_path = config.storage_dir.join(".portal-daemon.lock");
    let download_addr: SocketAddr = config
        .server_address
        .parse()
        .context("invalid server address")?;

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            writeln!(writer, "{body}")?;
        }
        Commands::Run => {
            let storage_limits = StorageLimits {
                capacity: config.storage_capacity,
                max_file_size: config.storage_max_file_size,
                max_files: config.storage_max_files,
            };
            run_daemon_command(
                client,
                conn,
                config.portal_polling_interval,
                lock_path,
                storage_limits,
                storage_backend,
                config.storage_dir.clone(),
                download_addr,
                shutdown,
            )
            .await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_daemon_command(
    client: PortalClient,
    conn: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
    download_addr: SocketAddr,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let daemon_backend = storage_backend.clone();
    let handle = spawn_portal_daemon(
        client,
        conn.clone(),
        interval,
        lock_path,
        storage_limits,
        daemon_backend,
    );

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let server = server::serve(
        download_addr,
        server::DownloadServerState {
            db: conn,
            storage_dir,
            storage_backend,
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
    use serde_json::json;
    use std::env;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};
    use tokio::time::{sleep, Duration};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_storage_dir(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_main_{prefix}_{id}"))
    }

    #[tokio::test]
    async fn run_writes_ping_output() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            portal_url: mock_server.uri(),
            portal_api_key: "secret".to_string(),
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
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        run(cli, &mut buffer).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

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
    async fn run_propagates_ping_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            portal_url: mock_server.uri(),
            portal_api_key: "secret".to_string(),
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
    async fn run_prints_gcs_bucket_when_storage_method_is_gcs() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
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
            portal_url: mock_server.uri(),
            portal_api_key: "secret".to_string(),
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
    async fn run_starts_daemon_and_aborts_on_shutdown() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("daemon");
        let cli = Cli {
            portal_url: mock_server.uri(),
            portal_api_key: "secret".to_string(),
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
            command: Commands::Run,
        };

        let shutdown = async {
            sleep(Duration::from_millis(50)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(
            output.contains("Portal polling interval:"),
            "expected polling interval in output: {output}"
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
    async fn run_propagates_shutdown_error() {
        let mock_server = MockServer::start().await;

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

        let storage_dir = unique_storage_dir("shutdown_error");
        let cli = Cli {
            portal_url: mock_server.uri(),
            portal_api_key: "secret".to_string(),
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
            command: Commands::Run,
        };

        let shutdown = async { Err(io::Error::other("ctrlc failure")) };

        let mut buffer = Vec::new();
        let err = run_with_shutdown(cli, &mut buffer, shutdown)
            .await
            .unwrap_err();

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
}
