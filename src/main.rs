mod cli;
mod clients;
mod config;
mod daemon;
mod database;
mod entities;
mod tasks;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sea_orm::DatabaseConnection;
use std::future::Future;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::signal;

use cli::{Cli, Commands};
use clients::PortalClient;
use config::Config;
use daemon::{spawn_portal_daemon, StorageLimits};
use database::DBClient;
use tasks::downloadagreements::StorageBackend;

#[tokio::main]
async fn main() -> Result<()> {
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
    writeln!(writer, "Storage dir: {}", config.storage_dir.display())?;
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
                &mut writer,
                client,
                conn,
                config.portal_polling_interval,
                lock_path,
                storage_limits,
                storage_backend,
                shutdown,
            )
            .await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_daemon_command(
    mut writer: impl Write,
    client: PortalClient,
    conn: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let handle = spawn_portal_daemon(
        client,
        conn,
        interval,
        lock_path,
        storage_limits,
        storage_backend,
    );

    writeln!(
        writer,
        "Portal sync daemon running every {}s",
        interval.as_secs()
    )?;

    let shutdown_result = shutdown.await;
    handle.abort();
    let _ = handle.await;

    shutdown_result?;
    Ok(())
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
    use tokio::time::{sleep, Duration};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

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
            output.contains("Portal sync daemon running every"),
            "expected daemon startup message in output: {output}"
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
