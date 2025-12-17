mod cli;
mod clients;
mod config;
mod daemon;
mod database;
mod entities;
mod tasks;

use anyhow::{Context, Result};
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
use daemon::spawn_portal_daemon;
use database::DBClient;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut stdout = io::stdout();
    run(cli, &mut stdout).await
}

async fn run(cli: Cli, writer: impl Write) -> Result<()> {
    run_with_shutdown(cli, writer, signal::ctrl_c()).await
}

async fn run_with_shutdown(
    cli: Cli,
    mut writer: impl Write,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let config = Config::from(&cli);
    writeln!(writer, "Portal URL: {}", config.portal_url)?;
    writeln!(writer, "Database URL: {}", config.database_url)?;
    writeln!(writer, "Storage dir: {}", config.storage_dir.display())?;

    std::fs::create_dir_all(&config.storage_dir).with_context(|| {
        format!(
            "failed to create storage directory {}",
            config.storage_dir.display()
        )
    })?;

    let db = DBClient::new(&config.database_url).await?;
    let conn = db.connection().clone();
    let client = PortalClient::new(&config.portal_url, &config.storage_dir);
    let lock_path = config.storage_dir.join(".portal-daemon.lock");

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            writeln!(writer, "{body}")?;
        }
        Commands::Run => {
            run_daemon_command(
                &mut writer,
                client,
                conn,
                config.portal_polling_interval,
                lock_path,
                shutdown,
            )
            .await?;
        }
    }

    Ok(())
}

async fn run_daemon_command(
    mut writer: impl Write,
    client: PortalClient,
    conn: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<()> {
    let handle = spawn_portal_daemon(client, conn, interval, lock_path);

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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{sleep, Duration};
    use wiremock::matchers::{method, path, query_param};
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
            .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/storage")),
            portal_polling_interval_secs: 5,
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
            output.contains("pong"),
            "expected ping response in output, got {output}"
        );
    }

    #[tokio::test]
    async fn run_propagates_ping_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&mock_server)
            .await;

        let cli = Cli {
            portal_url: mock_server.uri(),
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(PathBuf::from("/tmp/storage")),
            portal_polling_interval_secs: 5,
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
            .and(path("/agreements"))
            .and(query_param("status", "ready"))
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
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir.clone()),
            portal_polling_interval_secs: 1,
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
            .and(path("/agreements"))
            .and(query_param("status", "ready"))
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
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir.clone()),
            portal_polling_interval_secs: 1,
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
}
