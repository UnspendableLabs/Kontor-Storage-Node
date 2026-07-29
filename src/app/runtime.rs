//! Application runtime and shutdown logic.
//!
//! Contains the main run loop, daemon configuration, and graceful shutdown handling.

use crate::app::cli::{Cli, Commands};
use crate::app::config::{Config, StorageMethod};
use crate::app::daemon::{spawn_portal_daemon, StorageLimits};
use crate::app::restart::{Outcome, RestartHandle};
use crate::app::tasks::downloadagreements::StorageBackend;
use crate::clients::PortalClient;
use crate::database::DBClient;
use crate::node;
use crate::server;
use crate::server::admin::{AdminState, NodeIdentity, RegisteredNode};
use anyhow::{Context, Result};
use sea_orm::DatabaseConnection;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{pin, signal, sync::oneshot};

/// Configuration for the daemon process.
pub struct DaemonConfig {
    pub client: PortalClient,
    pub conn: DatabaseConnection,
    pub interval: Duration,
    pub lock_path: PathBuf,
    pub storage_limits: StorageLimits,
    pub storage_backend: StorageBackend,
    pub storage_dir: PathBuf,
    pub download_addr: SocketAddr,
    pub node_id: Option<String>,
    pub admin: AdminState,
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
/// On Unix, this handles both signals; on other platforms, only SIGINT.
async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        let mut sigterm = unix_signal(SignalKind::terminate())?;
        tokio::select! {
            result = signal::ctrl_c() => result,
            _ = sigterm.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await
    }
}

/// Run the application with the default shutdown signal (SIGINT/SIGTERM).
///
/// The [`Outcome`] tells the caller whether to exit `0` or with
/// [`crate::app::restart::RESTART_EXIT_CODE`]; see [`crate::app::restart`].
pub async fn run(cli: Cli, writer: impl Write) -> Result<Outcome> {
    run_with_shutdown(cli, writer, shutdown_signal()).await
}

/// Print configuration information to the writer.
fn print_config_info(config: &Config, writer: &mut impl Write) -> Result<()> {
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
    writeln!(
        writer,
        "Filestorage contract: {}",
        config.kontor_contract_address
    )?;
    // Says which way the switch is set without ever naming the value: an
    // operator who forgot to set ADMIN_PASSWORD sees it here rather than at a
    // login screen that answers 503.
    writeln!(
        writer,
        "Admin UI: {}",
        if config.admin_password.is_empty() {
            "disabled (set ADMIN_PASSWORD to enable /admin)"
        } else {
            "enabled at /admin"
        }
    )?;

    Ok(())
}

/// Create the storage directory if it doesn't exist.
fn setup_storage_directory(config: &Config) -> Result<()> {
    std::fs::create_dir_all(&config.storage_dir).with_context(|| {
        format!(
            "failed to create storage directory {}",
            config.storage_dir.display()
        )
    })
}

/// What the HTTP server needs, independent of whether the node is registered.
///
/// Split out because an unregistered node still serves `/admin` — that is the
/// only place its registration can be repaired from — and so needs all of this
/// without ever building a daemon.
struct ServerParts {
    conn: DatabaseConnection,
    storage_backend: StorageBackend,
    download_addr: SocketAddr,
}

async fn build_server_parts(config: &Config) -> Result<ServerParts> {
    let db = DBClient::new(&config.database_url).await?;

    Ok(ServerParts {
        conn: db.connection().clone(),
        storage_backend: StorageBackend::new(
            config.storage_method.clone(),
            config.storage_gcs_bucket_name.clone(),
            config.storage_gcs_service_account_json.clone(),
        )?,
        download_addr: config
            .server_address
            .parse()
            .context("invalid server address")?,
    })
}

/// Build the daemon configuration from the app config and onboarding result.
async fn build_daemon_config(
    config: &Config,
    authenticated_client: PortalClient,
    node_id: String,
    identity: NodeIdentity,
) -> Result<DaemonConfig> {
    let parts = build_server_parts(config).await?;

    let storage_limits = StorageLimits {
        capacity: config.storage_capacity,
        max_file_size: config.storage_max_file_size,
        max_files: config.storage_max_files,
    };

    Ok(DaemonConfig {
        client: authenticated_client,
        conn: parts.conn,
        interval: config.portal_polling_interval,
        lock_path: config.storage_dir.join(".portal-daemon.lock"),
        storage_limits,
        storage_backend: parts.storage_backend,
        storage_dir: config.storage_dir.clone(),
        download_addr: parts.download_addr,
        node_id: Some(node_id),
        admin: AdminState::new(
            config.admin_password.clone(),
            RestartHandle::from_env(),
            Some(identity),
        ),
    })
}

/// How often an unregistered node re-checks whether the Portal has heard of it.
#[cfg(not(test))]
const UNREGISTERED_LOOKUP_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
const UNREGISTERED_LOOKUP_INTERVAL: Duration = Duration::from_millis(50);

/// Serve `/admin` on a node the Portal has never heard of.
///
/// No daemon, no announce, no faucet: none of them mean anything without a
/// `signer_id`. The server is up for one reason, which is to let an operator
/// register the BLS key from a browser that has Horizon Wallet — see
/// [`crate::server::admin::register`].
///
/// A background lookup runs alongside it so the node also recovers from a
/// registration made anywhere else. Either way the fix is the same: exit, and
/// let the supervisor start a process that onboards properly. Restarting is
/// only offered when a restarted process could get back up unattended, so a
/// node without `BLS_PASSWORD` stays here until a human intervenes — which is
/// the same node that would have stopped at a password prompt anyway.
///
/// A mnemonic node whose registration was refused has nobody to wait for. It
/// signed a complete registration during onboarding and the Portal declined it,
/// almost always because its address is not whitelisted yet; whitelisting it
/// does not register anything, and no browser can, since the Taproot key never
/// left this process. So `pending_registration` is replayed on the same tick as
/// the lookup, and the node comes up on its own the moment the Portal relents.
async fn run_unregistered(
    config: &Config,
    client: PortalClient,
    node: node::UnregisteredNode,
    writer: &mut impl Write,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Outcome> {
    let node::UnregisteredNode {
        keypair,
        bls_pubkey,
        derived,
        mut pending_registration,
    } = node;

    let parts = build_server_parts(config).await?;
    let restart = RestartHandle::from_env();
    let identity = NodeIdentity::new(Arc::new(keypair), client.clone(), None, derived);
    let admin = AdminState::new(
        config.admin_password.clone(),
        restart.clone(),
        Some(identity),
    );

    if admin.is_enabled() {
        writeln!(
            writer,
            "Serving /admin only until this node is registered.\n"
        )?;
    } else {
        writeln!(
            writer,
            "ADMIN_PASSWORD is unset, so /admin cannot be unlocked to register this key.\n\
             Set it and restart, or register the key from elsewhere — this node re-checks \
             every {}s.\n",
            UNREGISTERED_LOOKUP_INTERVAL.as_secs()
        )?;
    }

    // Nothing stops this loop but the abort below: a restart asked for from
    // `/admin` already woke the run loop, and one more lookup on the way out
    // costs less than a second flag to check.
    let watcher = tokio::spawn({
        let restart = restart.clone();
        async move {
            // Only the first refusal is worth a warning. After that the node is
            // waiting on a human, and repeating ourselves every 30s would bury
            // the line that says which address they have to whitelist.
            let mut announced: Option<String> = None;
            loop {
                tokio::time::sleep(UNREGISTERED_LOOKUP_INTERVAL).await;
                if client.lookup_node(&bls_pubkey).await.is_ok() {
                    tracing::info!("The Portal now knows this BLS key; restarting to onboard");
                    restart.request();
                    return;
                }

                let Some(request) = pending_registration.as_deref() else {
                    continue;
                };
                // Replaying costs nothing to get wrong: the request carries no
                // nonce and no timestamp, so a Portal that already has it
                // answers the same way twice, and the lookup above is what
                // actually decides the node is through.
                match client.register_node(request).await {
                    Ok(response) => {
                        tracing::info!(
                            node_id = %response.node_id,
                            "The Portal accepted the registration it had refused"
                        );
                        announced = None;
                    }
                    Err(e) if crate::node::registration::refusal_is_final(&e) => {
                        tracing::error!(
                            error = %format!("{e:#}"),
                            "The Portal rejected this node's registration outright, so offering \
                             it again cannot help; giving up on it. Still watching for a \
                             registration made elsewhere."
                        );
                        pending_registration = None;
                    }
                    Err(e) => {
                        let reason = format!("{e:#}");
                        if announced.as_ref() != Some(&reason) {
                            tracing::warn!(
                                error = %reason,
                                "The Portal is still refusing this node's registration; retrying \
                                 every {}s",
                                UNREGISTERED_LOOKUP_INTERVAL.as_secs()
                            );
                            announced = Some(reason);
                        }
                    }
                }
            }
        }
    });

    let outcome = serve_until_shutdown(
        parts.download_addr,
        server::DownloadServerState {
            db: parts.conn,
            storage_dir: config.storage_dir.clone(),
            storage_backend: parts.storage_backend,
            node_id: None,
            admin,
        },
        restart,
        shutdown,
    )
    .await;

    watcher.abort();
    let _ = watcher.await;

    outcome
}

/// Run the application with a custom shutdown signal.
pub async fn run_with_shutdown(
    cli: Cli,
    mut writer: impl Write,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Outcome> {
    let config = Config::from_cli(&cli)?;

    print_config_info(&config, &mut writer)?;
    setup_storage_directory(&config)?;

    let client = PortalClient::try_new(&config.portal_url, &config.storage_dir)?
        .with_contract_address(&config.kontor_contract_address);

    match cli.command {
        Commands::Ping => {
            let body = client.ping().await?;
            writeln!(writer, "{body}")?;
            Ok(Outcome::Shutdown)
        }
        Commands::Run => {
            // Onboard: load BLS key, Portal lookup by pubkey, challenge login, registry nonce
            let onboarding_config = node::OnboardingConfig {
                bls_key_path: config.bls_key_path.clone(),
                mnemonic: crate::crypto::MnemonicSettings::from_env()?,
                // `storage_dir` is the one directory a node has to keep across
                // restarts to be worth running, which is exactly the lifetime
                // the identity record needs.
                state_dir: Some(config.storage_dir.clone()),
            };
            let onboarding_result =
                match node::perform_onboarding(&client, &onboarding_config, &mut writer).await? {
                    node::OnboardingOutcome::Ready(result) => *result,
                    node::OnboardingOutcome::Unregistered(node) => {
                        return run_unregistered(&config, client, *node, &mut writer, shutdown)
                            .await;
                    }
                };

            tracing::debug!(
                next_nonce = onboarding_result.next_nonce,
                "onboarding registry nonce"
            );

            writeln!(writer)?;
            writeln!(writer, "Node onboarding complete. Starting services...")?;
            writeln!(writer)?;

            node::ensure_kor_balance(&client, onboarding_result.signer_id, &mut writer).await?;

            let node_id = onboarding_result.node_id;
            let keypair = Arc::new(onboarding_result.keypair);

            let authenticated_client = PortalClient::try_with_auth(
                &config.portal_url,
                &config.storage_dir,
                keypair.clone(),
                &node_id,
                onboarding_result.signer_id,
                onboarding_result.token,
                onboarding_result.next_nonce,
            )?
            .with_contract_address(&config.kontor_contract_address);

            if let Err(e) = authenticated_client.announce_node(&config.public_url).await {
                tracing::warn!("Failed to announce node URL: {e}");
            } else {
                writeln!(writer, "✓ Announced public URL: {}", config.public_url)?;
            }

            // The admin UI can re-register an already-registered node, so it
            // gets the same key and an unauthenticated client here as it would
            // on a node that never onboarded.
            let identity = NodeIdentity::new(
                keypair,
                client,
                Some(RegisteredNode {
                    node_id: node_id.clone(),
                    signer_id: onboarding_result.signer_id,
                }),
                onboarding_result.derived,
            );

            let daemon_config =
                build_daemon_config(&config, authenticated_client, node_id, identity).await?;
            run_daemon_command(daemon_config, shutdown).await
        }
    }
}

/// Run the daemon with the download server.
///
/// Stops on the shutdown signal, on the download server failing, or on an
/// operator asking for a restart from `/admin` — the last of which reports
/// [`Outcome::Restart`] so the caller can exit in a way the supervisor acts on.
pub async fn run_daemon_command(
    daemon: DaemonConfig,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Outcome> {
    let daemon_backend = daemon.storage_backend.clone();
    let restart = daemon.admin.restart().clone();
    let handle = spawn_portal_daemon(
        daemon.client,
        daemon.conn.clone(),
        daemon.interval,
        daemon.lock_path,
        daemon.storage_limits,
        daemon_backend,
        daemon.storage_dir.clone(),
    );

    let outcome = serve_until_shutdown(
        daemon.download_addr,
        server::DownloadServerState {
            db: daemon.conn,
            storage_dir: daemon.storage_dir,
            storage_backend: daemon.storage_backend,
            node_id: daemon.node_id,
            admin: daemon.admin,
        },
        restart,
        shutdown,
    )
    .await;

    handle.abort();
    let _ = handle.await;

    outcome
}

/// Run the HTTP server until something asks it to stop.
///
/// Shared by the daemon and by an unregistered node, which differ only in
/// whether there is a daemon alongside the server.
async fn serve_until_shutdown(
    addr: SocketAddr,
    state: server::DownloadServerState,
    restart: RestartHandle,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Outcome> {
    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let server = server::serve(addr, state, async move {
        let _ = server_shutdown_rx.await;
    });

    pin!(server);
    pin!(shutdown);

    // The restart arm is woken from inside a request handler, so the server is
    // necessarily still running when it fires. Everything below is the ordinary
    // shutdown path: the graceful shutdown flushes the reset's own response
    // before the process goes anywhere.
    let mut restart_requested = false;
    let shutdown_result = tokio::select! {
        server_result = &mut server => return server_result.map(|()| Outcome::Shutdown),
        shutdown_result = &mut shutdown => shutdown_result,
        () = restart.requested() => {
            tracing::info!("Restart requested from the admin UI; shutting down");
            restart_requested = true;
            Ok(())
        }
    };

    if server_shutdown_tx.send(()).is_err() {
        tracing::warn!("failed to send server shutdown signal: receiver dropped");
    }

    let server_result = server.await;

    server_result?;
    shutdown_result?;
    Ok(if restart_requested {
        Outcome::Restart
    } else {
        Outcome::Shutdown
    })
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::app::cli::{Cli, Commands};
    use crate::app::config::AdminPassword;
    use crate::crypto::mnemonic::{ACCOUNT_INDEX_ENV, MNEMONIC_ENV, NETWORK_ENV};
    use crate::crypto::{BitcoinNetwork, BlsKeyPair, MnemonicIdentity, MnemonicSettings};
    use crate::node::BLS_PASSWORD_ENV;
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
            command: Commands::Ping,
        };

        let mut buffer = Vec::new();
        let err = run(cli, &mut buffer).await.unwrap_err();

        assert!(
            err.to_string().contains("portal ping failed"),
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: None,
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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
    /// Creates a BLS key file and mocks Portal endpoints for the new onboarding flow.
    async fn setup_onboarding_fixtures(
        mock_server: &MockServer,
        node_id: &str,
        storage_dir: &PathBuf,
    ) -> PathBuf {
        let password = "testpassword123";
        let key_path = storage_dir.join("bls_key.enc");

        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        fs::create_dir_all(storage_dir).unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        env::set_var(BLS_PASSWORD_ENV, password);

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": node_id,
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "test-jwt-token",
                "user_id": node_id,
                "role": "node",
                "expires_in": 86400
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abc123",
                "bls_pubkey": public_key,
                "next_nonce": 7,
                "kor_balance": "10.0"
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/api/nodes/announce"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .mount(mock_server)
            .await;

        key_path
    }

    /// Cleanup onboarding environment after test.
    fn cleanup_onboarding_env() {
        env::remove_var(BLS_PASSWORD_ENV);
        for key in [MNEMONIC_ENV, ACCOUNT_INDEX_ENV, NETWORK_ENV] {
            env::remove_var(key);
        }
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
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let cli = Cli {
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: Some(bls_key_path),
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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

    /// A BLS key on disk and a password in the environment, with no Portal
    /// mocks: whatever the caller mounts for `/api/nodes/lookup` decides
    /// whether the node comes up registered.
    async fn setup_unregistered_fixtures(storage_dir: &PathBuf) -> PathBuf {
        let password = "testpassword123";
        let key_path = storage_dir.join("bls_key.enc");

        let keypair = BlsKeyPair::generate().unwrap();
        fs::create_dir_all(storage_dir).unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();
        env::set_var(BLS_PASSWORD_ENV, password);

        key_path
    }

    fn unregistered_cli(portal_url: String, storage_dir: PathBuf, bls_key_path: PathBuf) -> Cli {
        Cli {
            portal_url,
            database_url: "sqlite::memory:".to_string(),
            storage_dir: Some(storage_dir),
            portal_polling_interval_secs: 1,
            storage_capacity: None,
            storage_max_file_size: None,
            storage_max_files: None,
            storage_method: "local".to_string(),
            storage_gcs_bucket_name: None,
            storage_gcs_service_account_json: None,
            server_address: "127.0.0.1:0".to_string(),
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: Some(bls_key_path),
            admin_password: Some("correct horse battery staple".to_string()),
            kontor_contract_address: "filestorage_0_0".to_string(),
            command: Commands::Run,
        }
    }

    /// The whole point of the unregistered path: a node the Portal has never
    /// heard of used to exit here, taking `/admin` — the only place the
    /// registration can be repaired from — down with it.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_serves_admin_when_the_portal_does_not_know_the_key() {
        let _guard = TempAppDirGuard::new("unregistered");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("unregistered");
        let bls_key_path = setup_unregistered_fixtures(&storage_dir).await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_string("no such node"))
            .mount(&mock_server)
            .await;

        let cli = unregistered_cli(mock_server.uri(), storage_dir.clone(), bls_key_path);
        let shutdown = async {
            sleep(Duration::from_millis(150)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        let outcome = run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        cleanup_onboarding_env();

        assert_eq!(outcome, Outcome::Shutdown);
        assert!(
            output.contains("No node registered with this BLS public key"),
            "{output}"
        );
        assert!(output.contains("Serving /admin only"), "{output}");
        assert!(
            !output.contains("Node onboarding complete"),
            "nothing past the lookup should have run: {output}"
        );
        assert!(
            !storage_dir.join(".portal-daemon.lock").exists(),
            "no daemon should have started"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// The background lookup means a registration made anywhere — this node's
    /// `/admin`, or somebody else's — brings the node back without a human
    /// touching the container.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unregistered_node_restarts_once_the_portal_knows_the_key() {
        let _guard = TempAppDirGuard::new("late_registration");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("late_registration");
        let bls_key_path = setup_unregistered_fixtures(&storage_dir).await;

        // First mounted mock wins: onboarding gets the 404, the watcher then
        // sees the node appear.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_string("no such node"))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-late",
                "signer_id": null,
                "bls_public_key": "00"
            })))
            .mount(&mock_server)
            .await;

        let cli = unregistered_cli(mock_server.uri(), storage_dir.clone(), bls_key_path);
        // Long enough that the watcher, not the signal, is what stops the node.
        let shutdown = async {
            sleep(Duration::from_secs(30)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        let outcome = run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();

        cleanup_onboarding_env();

        assert_eq!(
            outcome,
            Outcome::Restart,
            "the supervisor has to start a process that can onboard"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// The canonical BIP-39 phrase; the derivation itself is pinned in
    /// `crypto::mnemonic`, so this test only cares that the retry reaches the
    /// Portal.
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";

    /// A mnemonic node that the Portal refused has nobody to wait for: nothing
    /// but this process holds the Taproot key, so if it stops offering the
    /// registration, whitelisting the address later changes nothing and the node
    /// sits at 404 until a human restarts the container.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_refused_mnemonic_node_retries_until_the_portal_relents() {
        let _guard = TempAppDirGuard::new("whitelist_retry");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("whitelist_retry");
        fs::create_dir_all(&storage_dir).unwrap();

        let identity = MnemonicIdentity::derive(&MnemonicSettings::new(
            TEST_PHRASE,
            BitcoinNetwork::Signet,
            2,
        ))
        .unwrap();
        let public_key = identity.bls_pubkey();

        // Onboarding's lookup and the watcher's first one both 404; the third
        // finds the row the retried registration wrote.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key.as_str()))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "signer_id": null,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/nodes/{}/check", identity.node_id)))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(&mock_server)
            .await;

        // The address is not whitelisted during onboarding, and is by the time
        // the watcher tries again — which is the whole scenario.
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {
                    "code": "ADDRESS_NOT_WHITELISTED",
                    "message": "Bitcoin address is not whitelisted for node registration"
                }
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "x_only_pubkey": hex::encode(identity.x_only),
                "bls_public_key": public_key
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mounted last so the sibling scan's probes fall through to it.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(&mock_server)
            .await;

        env::set_var(MNEMONIC_ENV, TEST_PHRASE);
        env::set_var(ACCOUNT_INDEX_ENV, "2");
        env::set_var(NETWORK_ENV, "signet");

        let cli = unregistered_cli(
            mock_server.uri(),
            storage_dir.clone(),
            storage_dir.join("unused_bls_key.enc"),
        );
        // Long enough that the watcher, not the signal, is what stops the node.
        let shutdown = async {
            sleep(Duration::from_secs(30)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        let outcome = run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        cleanup_onboarding_env();

        assert_eq!(
            outcome,
            Outcome::Restart,
            "the retry has to end in a process that can onboard: {output}"
        );
        assert!(output.contains("ADDRESS_NOT_WHITELISTED"), "{output}");
        assert!(
            output.contains("retrying the registration in the background"),
            "the node has to say what it will do, since nobody else can do it: {output}"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// The other half of the retry rule. A `409` means the Portal has already
    /// given this node's xpub to a different BLS key, and the request carries
    /// no nonce — so the same bytes get the same answer forever. Offering them
    /// every 30s for the life of the process would bury the one line that says
    /// what actually went wrong.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_registration_the_portal_rejects_outright_is_not_replayed() {
        let _guard = TempAppDirGuard::new("final_refusal");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("final_refusal");
        fs::create_dir_all(&storage_dir).unwrap();

        let identity = MnemonicIdentity::derive(&MnemonicSettings::new(
            TEST_PHRASE,
            BitcoinNetwork::Signet,
            2,
        ))
        .unwrap();

        Mock::given(method("GET"))
            .and(path(format!("/api/nodes/{}/check", identity.node_id)))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(&mock_server)
            .await;

        // Twice and no more: once from onboarding, once from the watcher's
        // first tick, after which it must stop offering it.
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {
                    "code": "NODE_ALREADY_REGISTERED",
                    "message": "this xpubkey is registered with another BLS key"
                }
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        // Nothing is ever registered, so the watcher keeps ticking to the end.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(&mock_server)
            .await;

        env::set_var(MNEMONIC_ENV, TEST_PHRASE);
        env::set_var(ACCOUNT_INDEX_ENV, "2");
        env::set_var(NETWORK_ENV, "signet");

        let cli = unregistered_cli(
            mock_server.uri(),
            storage_dir.clone(),
            storage_dir.join("unused_bls_key.enc"),
        );
        // Many ticks at the test interval, so a loop that kept retrying would
        // blow past the expectation above rather than pass by being too short.
        let shutdown = async {
            sleep(Duration::from_millis(1500)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        let outcome = run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        cleanup_onboarding_env();

        assert_eq!(outcome, Outcome::Shutdown, "{output}");
        assert!(
            output.contains("rejected the registration outright"),
            "the operator must not be sent away to wait for a retry that will never \
             happen: {output}"
        );

        // Verified on drop by wiremock: exactly the two calls above.
        drop(mock_server);

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// Without a password the operator cannot unlock the one page that would
    /// fix this, so the node has to say so rather than sit there silently.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unregistered_node_without_an_admin_password_says_so() {
        let _guard = TempAppDirGuard::new("unregistered_nopass");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("unregistered_nopass");
        let bls_key_path = setup_unregistered_fixtures(&storage_dir).await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_string("no such node"))
            .mount(&mock_server)
            .await;

        let mut cli = unregistered_cli(mock_server.uri(), storage_dir.clone(), bls_key_path);
        cli.admin_password = None;
        let shutdown = async {
            sleep(Duration::from_millis(150)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        run_with_shutdown(cli, &mut buffer, shutdown).await.unwrap();
        let output = String::from_utf8(buffer).unwrap();

        cleanup_onboarding_env();

        assert!(output.contains("ADMIN_PASSWORD is unset"), "{output}");

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
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let cli = Cli {
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: Some(bls_key_path),
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
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

    /// Inline version of setup_onboarding_fixtures that does NOT mount the
    /// /api/nodes/announce mock so callers can provide their own.
    async fn setup_onboarding_fixtures_no_announce(
        mock_server: &MockServer,
        node_id: &str,
        storage_dir: &PathBuf,
    ) -> PathBuf {
        let password = "testpassword123";
        let key_path = storage_dir.join("bls_key.enc");

        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        fs::create_dir_all(storage_dir).unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        env::set_var(BLS_PASSWORD_ENV, password);

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": node_id,
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "test-jwt-token",
                "user_id": node_id,
                "role": "node",
                "expires_in": 86400
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abc123",
                "bls_pubkey": public_key,
                "next_nonce": 7,
                "kor_balance": "10.0"
            })))
            .mount(mock_server)
            .await;

        key_path
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn run_continues_when_announce_node_fails() {
        // Cover the announce_node failure branch (line 195) by returning 500
        // from /api/nodes/announce. The daemon should still start and run.
        let _guard = TempAppDirGuard::new("announce_fail");
        cleanup_onboarding_env();
        let mock_server = MockServer::start().await;
        let storage_dir = unique_storage_dir("announce_fail");
        let node_id = "NODE-announce-fail";

        // Mount the announce-fail mock FIRST so it matches before any later mock.
        Mock::given(method("PUT"))
            .and(path("/api/nodes/announce"))
            .respond_with(ResponseTemplate::new(500).set_body_string("announce failed"))
            .mount(&mock_server)
            .await;

        let bls_key_path =
            setup_onboarding_fixtures_no_announce(&mock_server, node_id, &storage_dir).await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let cli = Cli {
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
            public_url: "http://localhost:8081".to_string(),
            bls_key_path: Some(bls_key_path),
            admin_password: None,
            kontor_contract_address: "filestorage_0_0".to_string(),
            command: Commands::Run,
        };

        let shutdown = async {
            sleep(Duration::from_millis(50)).await;
            Ok(())
        };

        let mut buffer = Vec::new();
        let result = run_with_shutdown(cli, &mut buffer, shutdown).await;
        cleanup_onboarding_env();
        let output = String::from_utf8(buffer).unwrap();

        assert!(
            result.is_ok(),
            "daemon should not fail when announce fails, got: {result:?}"
        );
        assert!(
            !output.contains("✓ Announced"),
            "should not show announced message when announce fails: {output}"
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
                node_id: Some("NODE-TEST".to_string()),
                admin: AdminState::disabled(),
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

    /// Builds a daemon that binds an ephemeral port and talks to nothing. The
    /// Portal calls its daemon task makes all fail, which is fine: they are
    /// logged inside the task, and what these tests watch is the run loop.
    async fn idle_daemon(label: &str, admin: AdminState) -> (DaemonConfig, PathBuf) {
        let storage_dir = unique_storage_dir(label);
        std::fs::create_dir_all(&storage_dir).unwrap();
        let db = DBClient::new("sqlite::memory:").await.unwrap();

        let config = DaemonConfig {
            client: PortalClient::new("http://localhost:0", storage_dir.clone()),
            conn: db.connection().clone(),
            interval: Duration::from_millis(10),
            lock_path: storage_dir.join(".portal-daemon.lock"),
            storage_limits: StorageLimits {
                capacity: None,
                max_files: Some(0),
                max_file_size: None,
            },
            storage_backend: StorageBackend::local(),
            storage_dir: storage_dir.clone(),
            download_addr: "127.0.0.1:0".parse().unwrap(),
            node_id: Some("NODE-TEST".to_string()),
            admin,
        };
        (config, storage_dir)
    }

    /// The operator UI asks for a restart by flipping a switch the run loop is
    /// waiting on. Reporting it is what lets `main` pick an exit code the
    /// supervisor acts on, so a plain `Shutdown` here would leave the node down.
    #[tokio::test]
    async fn run_daemon_command_reports_a_restart_the_admin_ui_asked_for() {
        let restart = RestartHandle::available();
        let (config, storage_dir) =
            idle_daemon("admin_restart", AdminState::with_restart(restart.clone())).await;

        let task = tokio::spawn(run_daemon_command(
            config,
            future::pending::<io::Result<()>>(),
        ));
        restart.request();

        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the run loop must stop once a restart is requested")
            .unwrap()
            .unwrap();

        assert_eq!(outcome, Outcome::Restart);
        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// Binds and releases a port so the server can claim it next. A racy way to
    /// learn a free port, and the usual one: the alternative is plumbing the
    /// bound address back out of `serve`.
    fn free_local_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// The whole design rests on the operator getting their report back: the
    /// restart is requested from inside the handler, and the graceful shutdown
    /// has to flush that response before the process goes anywhere. Proven over
    /// a real socket rather than argued about.
    #[tokio::test]
    async fn a_restart_is_answered_before_the_node_goes_down() {
        const PASSWORD: &str = "correct horse battery staple";
        crate::server::admin::session::reset_throttle_for_tests(Some(
            std::net::Ipv4Addr::LOCALHOST.into(),
        ));

        let addr = free_local_addr();
        let restart = RestartHandle::available();
        let (mut config, storage_dir) = idle_daemon(
            "restart_over_http",
            AdminState::new(AdminPassword::new(Some(PASSWORD)), restart.clone(), None),
        )
        .await;
        config.download_addr = addr;

        let run_loop = tokio::spawn(run_daemon_command(
            config,
            future::pending::<io::Result<()>>(),
        ));

        let http = reqwest::Client::new();
        let base = format!("http://{addr}");

        // The listener comes up asynchronously, so the first connections are
        // refused until it does.
        let token = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(response) = http
                    .post(format!("{base}/api/admin/login"))
                    .json(&json!({ "password": PASSWORD }))
                    .send()
                    .await
                {
                    let body: serde_json::Value = response.json().await.unwrap();
                    break body["token"].as_str().unwrap().to_string();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the admin API must come up");

        let body: serde_json::Value = http
            .post(format!("{base}/api/admin/reset-database"))
            .bearer_auth(&token)
            .json(&json!({ "confirm": "RESET", "restart": true }))
            .send()
            .await
            .expect("the reset must be answered even though it ends the process")
            .json()
            .await
            .unwrap();

        assert_eq!(body["restarting"], true);
        assert_eq!(body["total_rows_deleted"], 0);

        let outcome = tokio::time::timeout(Duration::from_secs(10), run_loop)
            .await
            .expect("the run loop must stop once the response is out")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, Outcome::Restart);
        assert!(restart.is_requested());

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// The signal path keeps its meaning: exiting on SIGTERM must not read as
    /// "start me again".
    #[tokio::test]
    async fn run_daemon_command_reports_a_plain_shutdown_as_shutdown() {
        let (config, storage_dir) = idle_daemon("plain_shutdown", AdminState::disabled()).await;

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            run_daemon_command(config, future::ready(Ok(()))),
        )
        .await
        .expect("a resolved shutdown signal must stop the run loop")
        .unwrap();

        assert_eq!(outcome, Outcome::Shutdown);
        std::fs::remove_dir_all(&storage_dir).ok();
    }

    #[test]
    fn load_local_env_returns_ok_when_missing() {
        let _guard = cwd_lock().lock().unwrap();
        let temp_dir = unique_storage_dir("load_env_missing");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let result = crate::load_local_env();

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

        let result = crate::load_local_env();

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

        let result = crate::load_local_env();

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

        let result = crate::load_local_env();

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
        let result = crate::load_local_env();

        std::fs::set_permissions(&protected_dir, std::fs::Permissions::from_mode(0o700)).ok();
        env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&temp_dir).ok();

        assert!(
            result.is_err(),
            "metadata permission error should be propagated"
        );
    }
}
