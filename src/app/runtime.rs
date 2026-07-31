//! Application runtime and shutdown logic.
//!
//! # The order things happen in, and why it changed
//!
//! A node used to answer every question about itself before it served anything:
//! load the key, ask the Portal who we are, build the daemon, and only then open
//! a socket. That works exactly as long as the answers are already on the
//! machine. It stops working the moment the answers are supposed to *arrive
//! through* the server — which is what a node configured from its own `/admin`
//! requires.
//!
//! So the order is inverted. [`serve`] starts the HTTP server first,
//! unconditionally, before any Portal contact and possibly before the node has a
//! key at all. A [`Supervisor`] task runs alongside it and moves the node
//! through [`Phase`]s as the material appears: an operator claims the UI,
//! provisions a key, unlocks a sealed one, gets an address whitelisted. Each of
//! those is an [`Activation`] the supervisor carries out **in this process** —
//! no exit, no restart, no supervisor-level bounce.
//!
//! That in-process activation is also what retires the old special case. Serving
//! `/admin` on an unregistered node used to need its own daemon-less run
//! function and an exit code to get back out of; it is now just a phase the
//! supervisor leaves when the Portal changes its mind.

use crate::app::cli::{Cli, Commands};
use crate::app::config::{Config, StorageMethod};
use crate::app::daemon::{spawn_portal_daemon, StorageLimits};
use crate::app::lifecycle::{Activation, NodeRuntime, Phase, SealStatus};
use crate::app::output::SharedWriter;
use crate::app::restart::{Outcome, RestartHandle};
use crate::app::tasks::downloadagreements::StorageBackend;
use crate::clients::PortalClient;
use crate::crypto::keystore::{Keystore, SealKey, SealKeySource};
use crate::database::DBClient;
use crate::node::{self, KeySource, NodeKeys};
use crate::server;
use crate::server::admin::credentials::AdminCredential;
use crate::server::admin::{AdminState, NodeIdentity, RegisteredNode};
use anyhow::{Context, Result};
use sea_orm::DatabaseConnection;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::{pin, signal, sync::oneshot};

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
///
/// # Errors
/// If the configuration is invalid, or the server cannot be started.
pub async fn run(cli: Cli, writer: SharedWriter) -> Result<Outcome> {
    run_with_shutdown(cli, writer, shutdown_signal()).await
}

/// Print configuration information to the writer.
fn print_config_info(config: &Config, writer: &mut impl Write) -> Result<()> {
    writeln!(writer, "Portal URL: {}", config.portal_url)?;
    writeln!(writer, "Database URL: {}", config.database_url)?;
    writeln!(writer, "App directory: {}", config.app_dir.display())?;
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

/// What the HTTP server needs, independent of what the node knows about itself.
#[derive(Clone)]
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

/// How often an unregistered node re-checks whether the Portal has heard of it.
#[cfg(not(test))]
const UNREGISTERED_LOOKUP_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(test)]
const UNREGISTERED_LOOKUP_INTERVAL: Duration = Duration::from_millis(50);

/// Run the application with a custom shutdown signal.
///
/// # Errors
/// If the configuration is invalid, or the server cannot be started.
pub async fn run_with_shutdown(
    cli: Cli,
    mut writer: SharedWriter,
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
        Commands::Run => serve(config, client, writer, shutdown).await,
    }
}

/// Bring the node up: server first, then whatever the volume allows.
async fn serve(
    config: Config,
    client: PortalClient,
    mut writer: SharedWriter,
    shutdown: impl Future<Output = io::Result<()>>,
) -> Result<Outcome> {
    let parts = build_server_parts(&config).await?;

    // Reading the keys can fail — a corrupt keystore, a seal key that does not
    // open it — and that failure is fatal by design: it means there *is* an
    // identity here and we cannot reach it, which is the one situation where
    // carrying on and offering the setup wizard would provision a second one
    // over the top of the first.
    let source = resolve_keys(&config, &mut writer).await?;

    let (phase, seal, opened) = match source {
        KeySource::Open {
            keystore,
            keys,
            seal_key,
            seal_source,
        } => (
            Phase::Activating,
            // Filled in below rather than here: the status and the key that
            // produced it are published in one call, so `/admin` can never be
            // shown one without the other.
            SealStatus::default(),
            Some((keystore, keys, seal_key, seal_source)),
        ),
        KeySource::Sealed { keystore } => {
            writeln!(
                writer,
                "\nThis node has a keystore but nothing here can open it.\n  \
                   slots: {}\n  \
                 Set {} to the key for one of them, restore the seal key file, or unlock \
                 it from /admin.",
                keystore
                    .slots()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                crate::crypto::keystore::SEAL_KEY_ENV,
            )?;
            (Phase::Sealed, SealStatus::locked(&keystore), None)
        }
        KeySource::Uninitialized => {
            writeln!(
                writer,
                "\nThis node has no keys yet. Open /admin to set it up."
            )?;
            (Phase::Uninitialized, SealStatus::default(), None)
        }
    };

    let runtime = NodeRuntime::new(phase, seal);

    // The key this boot opened the keystore with, published before the server
    // is: `/admin` reseals with it, and a request can arrive before the
    // supervisor task has had a chance to run.
    if let Some((keystore, _, seal_key, seal_source)) = opened.as_ref() {
        runtime.opened(keystore, seal_key, *seal_source);
    }

    // A restart is only ever offered where a restarted process could come back
    // on its own. That used to mean "a password is in the environment"; it now
    // means the keystore has a slot the machine can supply. A node whose only
    // slot is a passphrase would come back up sealed and wait for a human, so
    // restarting it is not a recovery, it is an outage.
    let restart = RestartHandle::new(
        opened
            .as_ref()
            .is_some_and(|(keystore, ..)| keystore.can_boot_unattended()),
    );
    let credential =
        AdminCredential::load_or_bootstrap(&config.app_dir, &config.admin_password).await?;
    let setup_notice = credential.startup_notice();
    let admin = AdminState::new(
        credential,
        config.app_dir.clone(),
        restart.clone(),
        runtime.clone(),
    );

    // Printed after everything else, so on a fresh node the last thing an
    // operator sees is the one action that unblocks all the others.
    match setup_notice {
        Some(notice) => writeln!(writer, "\n{notice}\n")?,
        None => writeln!(
            writer,
            "\nAdmin UI: {}",
            if admin.is_enabled() {
                "enabled at /admin"
            } else {
                "disabled"
            }
        )?,
    }

    let config = Arc::new(config);
    let supervisor = tokio::spawn(
        Supervisor {
            config: config.clone(),
            client,
            parts: parts.clone(),
            runtime: runtime.clone(),
            writer,
            daemon: None,
            watcher: None,
            keystore: None,
        }
        .run(opened),
    );

    let outcome = serve_until_shutdown(
        parts.download_addr,
        server::DownloadServerState {
            db: parts.conn,
            storage_dir: config.storage_dir.clone(),
            storage_backend: parts.storage_backend,
            runtime,
            admin,
        },
        restart,
        shutdown,
    )
    .await;

    supervisor.abort();
    let _ = supervisor.await;

    outcome
}

/// Open the keystore, migrating a legacy node into one if that is what this
/// volume turns out to be.
async fn resolve_keys(config: &Config, writer: &mut SharedWriter) -> Result<KeySource> {
    let key_path = node::onboarding::key_management::get_key_path(config.bls_key_path.as_deref())?;
    let password_reader = node::onboarding::get_password_reader();

    node::open_or_migrate(
        &config.app_dir,
        &key_path,
        crate::crypto::MnemonicSettings::from_env()?.as_ref(),
        writer,
        password_reader.as_ref(),
    )
    .await
}

/// The task that moves the node between phases.
///
/// It owns everything activation needs, so a test can drive it against a mock
/// Portal without going near [`run_with_shutdown`] or a real socket.
struct Supervisor {
    config: Arc<Config>,
    /// Unauthenticated client. Onboarding builds the signed one.
    client: PortalClient,
    parts: ServerParts,
    runtime: NodeRuntime,
    writer: SharedWriter,
    daemon: Option<JoinHandle<()>>,
    watcher: Option<JoinHandle<()>>,
    /// Kept so the node can be onboarded again without the operator supplying
    /// anything: unsealing a raw slot is one AEAD open, so re-deriving the keys
    /// is cheaper than keeping a `NodeKeys` alive across every await.
    keystore: Option<(Box<Keystore>, SealKey, SealKeySource)>,
}

type Opened = (Box<Keystore>, Box<NodeKeys>, SealKey, SealKeySource);

impl Supervisor {
    async fn run(mut self, opened: Option<Opened>) {
        if let Some((keystore, keys, seal_key, seal_source)) = opened {
            self.keystore = Some((keystore, seal_key, seal_source));
            self.activate(*keys).await;
        }

        loop {
            match self.runtime.next().await {
                Activation::Open {
                    keystore,
                    seal_key,
                    source,
                } => {
                    match keystore.unseal(&seal_key) {
                        Ok(keypair) => {
                            let keys = NodeKeys::Sealed(Box::new(node::SealedKeys {
                                keypair,
                                public: keystore.public().cloned(),
                            }));
                            // Announced only once it has worked. A key that did
                            // not open the keystore is not the key `/admin`
                            // should go on to reseal with, and a status saying
                            // otherwise would offer an operator a slot change
                            // that cannot succeed.
                            self.runtime.opened(&keystore, &seal_key, source);
                            self.keystore = Some((keystore, seal_key, source));
                            self.activate(keys).await;
                        }
                        Err(e) => self.fail("could not open the keystore", &e),
                    }
                }
                Activation::Reonboard => match self.reopen() {
                    Ok(keys) => self.activate(keys).await,
                    Err(e) => self.fail("could not reopen the keystore", &e),
                },
            }
        }
    }

    /// Derive the keys again from the keystore this node was opened with.
    fn reopen(&self) -> Result<NodeKeys> {
        let (keystore, seal_key, _) = self
            .keystore
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("this node has no keystore to reopen"))?;

        Ok(NodeKeys::Sealed(Box::new(node::SealedKeys {
            keypair: keystore.unseal(seal_key)?,
            public: keystore.public().cloned(),
        })))
    }

    /// Onboard, then start serving — or land in a phase that says why not.
    async fn activate(&mut self, keys: NodeKeys) {
        self.stop_daemon().await;
        self.stop_watcher().await;
        self.runtime.set_notice(None);
        self.runtime.enter(Phase::Activating);

        let outcome = node::perform_onboarding(
            &self.client,
            keys,
            Some(&self.config.storage_dir),
            &mut self.writer,
        )
        .await;

        match outcome {
            Ok(node::OnboardingOutcome::Ready(result)) => {
                if let Err(e) = self.start_running(*result).await {
                    self.fail("the node onboarded but could not start serving", &e);
                }
            }
            Ok(node::OnboardingOutcome::Unregistered(node)) => self.wait_for_registration(*node),
            Err(e) => self.fail("onboarding failed", &e),
        }
    }

    /// Announce, fund, publish the identity, and start the daemon.
    async fn start_running(&mut self, result: node::OnboardingResult) -> Result<()> {
        let node::OnboardingResult {
            keypair,
            node_id,
            signer_id,
            token,
            next_nonce,
            public,
        } = result;

        let keypair = Arc::new(keypair);
        let authenticated = PortalClient::try_with_auth(
            &self.config.portal_url,
            &self.config.storage_dir,
            keypair.clone(),
            &node_id,
            signer_id,
            token,
            next_nonce,
        )?
        .with_contract_address(&self.config.kontor_contract_address);

        if let Err(e) = authenticated.announce_node(&self.config.public_url).await {
            tracing::warn!("Failed to announce node URL: {e}");
        } else {
            writeln!(
                self.writer,
                "✓ Announced public URL: {}",
                self.config.public_url
            )?;
        }

        node::ensure_kor_balance(&authenticated, signer_id, &mut self.writer).await?;

        // The admin UI can re-register an already-registered node, so it gets
        // the same key and an unauthenticated client here as it would on a node
        // that never onboarded.
        self.runtime.set_identity(NodeIdentity::new(
            keypair,
            self.client.clone(),
            Some(RegisteredNode { node_id, signer_id }),
            public,
        ));

        self.daemon = Some(spawn_portal_daemon(
            authenticated,
            self.parts.conn.clone(),
            self.config.portal_polling_interval,
            self.config.storage_dir.join(".portal-daemon.lock"),
            StorageLimits {
                capacity: self.config.storage_capacity,
                max_file_size: self.config.storage_max_file_size,
                max_files: self.config.storage_max_files,
            },
            self.parts.storage_backend.clone(),
            self.config.storage_dir.clone(),
        ));

        writeln!(
            self.writer,
            "\nNode onboarding complete. Services started.\n"
        )?;
        self.runtime.enter(Phase::Running);
        Ok(())
    }

    /// Sit in [`Phase::Unregistered`], watching for the Portal to change its
    /// mind.
    ///
    /// Two things can end this wait and the loop covers both: a registration
    /// made somewhere else, which the lookup notices, and this node's own
    /// pending registration finally being accepted once an admin whitelists its
    /// address. Neither needs the process to exit any more — the watcher asks
    /// the supervisor to onboard again, in place.
    fn wait_for_registration(&mut self, node: node::UnregisteredNode) {
        let node::UnregisteredNode {
            keypair,
            bls_pubkey,
            public,
            mut pending_registration,
        } = node;

        self.runtime.set_identity(NodeIdentity::new(
            Arc::new(keypair),
            self.client.clone(),
            None,
            public,
        ));
        self.runtime.set_notice(Some(
            "The Portal does not know this node's key yet. If its Taproot address is not \
             whitelisted, ask a Portal admin to whitelist it — the node keeps offering its \
             registration and starts on its own once they have."
                .to_string(),
        ));
        self.runtime.enter(Phase::Unregistered);

        let client = self.client.clone();
        let runtime = self.runtime.clone();
        self.watcher = Some(tokio::spawn(async move {
            // The last outcome reported, so a Portal that keeps giving the same
            // answer is logged once rather than every tick — which would bury
            // the line that says which address has to be whitelisted.
            let mut announced: Option<String> = None;
            loop {
                tokio::time::sleep(UNREGISTERED_LOOKUP_INTERVAL).await;

                if client.lookup_node(&bls_pubkey).await.is_ok() {
                    tracing::info!("The Portal now knows this BLS key; onboarding");
                    runtime.request(Activation::Reonboard);
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
                        let reason = format!("accepted as {}", response.node_id);
                        if announced.as_ref() != Some(&reason) {
                            tracing::info!(
                                node_id = %response.node_id,
                                "The Portal accepted the registration it had refused; \
                                 waiting for the node to appear in its lookup"
                            );
                            announced = Some(reason);
                        }
                    }
                    Err(e) if node::registration::refusal_is_final(&e) => {
                        tracing::error!(
                            error = %format!("{e:#}"),
                            "The Portal rejected this node's registration outright, so \
                             offering it again cannot help; giving up on it. Still \
                             watching for a registration made elsewhere."
                        );
                        pending_registration = None;
                    }
                    Err(e) => {
                        let reason = format!("{e:#}");
                        if announced.as_ref() != Some(&reason) {
                            tracing::warn!(
                                error = %reason,
                                "The Portal is still refusing this node's registration; \
                                 retrying every {}s",
                                UNREGISTERED_LOOKUP_INTERVAL.as_secs()
                            );
                            announced = Some(reason);
                        }
                    }
                }
            }
        }));
    }

    /// Land in [`Phase::Failed`] with the reason on record.
    ///
    /// Never fatal to the process. The server is the only way an operator can
    /// see the reason or do anything about it, so taking it down with the
    /// activation would remove the fix along with the problem.
    fn fail(&self, what: &str, error: &anyhow::Error) {
        let detail = format!("{error:#}");
        tracing::error!(error = %detail, "{what}");
        let _ = writeln!(self.writer.clone(), "\n{what}: {detail}\n");
        self.runtime.set_notice(Some(format!("{what}: {detail}")));
        self.runtime.enter(Phase::Failed);
    }

    /// Stop the daemon and **wait for it to be gone**.
    ///
    /// The await is the whole point. `abort()` only schedules cancellation, and
    /// the daemon holds its lock until its guard drops; re-spawning before that
    /// lands means the new daemon finds the old one's lock genuinely held,
    /// reports "another daemon is already running" into a log line, and quietly
    /// never runs. A node that serves files while proving nothing looks healthy
    /// from outside, which is the worst way to fail.
    async fn stop_daemon(&mut self) {
        if let Some(handle) = self.daemon.take() {
            handle.abort();
            let _ = handle.await;
        }
    }

    async fn stop_watcher(&mut self) {
        if let Some(handle) = self.watcher.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

/// Run the HTTP server until something asks it to stop.
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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        run(cli, writer).await.unwrap();
        let output = captured.text();

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
            app_dir: None,
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

        let (writer, _captured) = SharedWriter::buffer();
        let err = run(cli, writer).await.unwrap_err();

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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        run(cli, writer).await.unwrap();
        let output = captured.text();

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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        run(cli, writer).await.unwrap();
        let output = captured.text();

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
            app_dir: None,
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

        let (writer, _captured) = SharedWriter::buffer();
        let err = run(cli, writer).await.unwrap_err();

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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        run_with_shutdown(cli, writer, shutdown).await.unwrap();
        let output = captured.text();

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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        let outcome = run_with_shutdown(cli, writer, shutdown).await.unwrap();
        let output = captured.text();

        cleanup_onboarding_env();

        assert_eq!(outcome, Outcome::Shutdown);
        assert!(
            output.contains("No node registered with this BLS public key"),
            "{output}"
        );
        assert!(output.contains("Open /admin"), "{output}");
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
        let (writer, captured) = SharedWriter::buffer();

        // Stopped by the assertion below rather than by a timer: what is being
        // tested is that the node gets there at all, in one process.
        let shutdown = async {
            let onboarded = captured
                .wait_for("Looking up node identity", Duration::from_secs(30))
                .await;
            assert!(onboarded, "the watcher must onboard without a restart");
            Ok(())
        };

        let outcome = run_with_shutdown(cli, writer, shutdown).await.unwrap();

        cleanup_onboarding_env();

        // The point of in-process activation: a node whose registration finally
        // lands comes up without the supervisor having to restart it. Before
        // this, the only way out of the unregistered phase was `Outcome::Restart`
        // and an exit code — which meant a container bounce for a state change
        // the process was perfectly able to make on its own.
        assert_eq!(
            outcome,
            Outcome::Shutdown,
            "the node must onboard in place rather than exiting to be restarted"
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
        let (writer, captured) = SharedWriter::buffer();

        // Stopped by the retry succeeding, not by a timer.
        let shutdown = {
            let captured = captured.clone();
            async move {
                // The line only a *successful* lookup produces, so seeing it
                // proves the replayed registration was accepted and the node
                // onboarded again — in this process, with no restart.
                let onboarded = captured
                    .wait_for("not yet confirmed", Duration::from_secs(30))
                    .await;
                assert!(
                    onboarded,
                    "the retry has to end in a node that onboards: {}",
                    captured.text()
                );
                Ok(())
            }
        };

        let outcome = run_with_shutdown(cli, writer, shutdown).await.unwrap();
        let output = captured.text();

        cleanup_onboarding_env();

        // No restart: the whitelisting lands, the node's own retry is accepted,
        // and it onboards in the process that was already waiting.
        assert_eq!(
            outcome,
            Outcome::Shutdown,
            "the retry must not need a restart: {output}"
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

        let (writer, captured) = SharedWriter::buffer();
        let outcome = run_with_shutdown(cli, writer, shutdown).await.unwrap();
        let output = captured.text();

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

    /// Without `ADMIN_PASSWORD` an unregistered node used to be a dead end: the
    /// one page that could fix it could not be unlocked, and all the node could
    /// do was say so. It now mints a setup token instead, which is the whole
    /// point of the claim flow — the operator gets in with what the node itself
    /// printed, having configured nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unregistered_node_without_an_admin_password_can_still_be_claimed() {
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

        let (writer, captured) = SharedWriter::buffer();
        run_with_shutdown(cli, writer, shutdown).await.unwrap();
        let output = captured.text();

        cleanup_onboarding_env();

        assert!(output.contains("has not been claimed yet"), "{output}");
        assert!(output.contains("setup token"), "{output}");

        // The token is on the volume as well as in the logs, so an operator who
        // scrolled past it is not locked out.
        let recorded = std::fs::read_to_string(
            _guard
                .dir
                .join(crate::server::admin::credentials::SETUP_TOKEN_FILE),
        )
        .expect("the token must be written down too");
        assert!(output.contains(recorded.trim()), "{output}");

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
            app_dir: None,
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

        let (writer, _captured) = SharedWriter::buffer();
        let err = run_with_shutdown(cli, writer, shutdown).await.unwrap_err();

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
            app_dir: None,
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

        let (writer, captured) = SharedWriter::buffer();
        let result = run_with_shutdown(cli, writer, shutdown).await;
        cleanup_onboarding_env();
        let output = captured.text();

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

    /// A server that cannot bind must report that, rather than sitting in a
    /// phase nobody is watching.
    #[tokio::test]
    async fn serving_returns_the_bind_error() {
        let (state, storage_dir) = idle_state("bind_error", AdminState::disabled()).await;

        let err = serve_until_shutdown(
            "127.0.0.1:1".parse().unwrap(),
            state,
            RestartHandle::unavailable(),
            future::pending::<io::Result<()>>(),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("binding download server"),
            "expected download server bind error, got {err}"
        );

        std::fs::remove_dir_all(&storage_dir).ok();
    }

    /// Server state for a node that talks to nothing. The Portal calls anything
    /// downstream might make all fail, which is fine: what these tests watch is
    /// the run loop's outcome.
    async fn idle_state(label: &str, admin: AdminState) -> (server::DownloadServerState, PathBuf) {
        let storage_dir = unique_storage_dir(label);
        std::fs::create_dir_all(&storage_dir).unwrap();
        let db = DBClient::new("sqlite::memory:").await.unwrap();

        let state = server::DownloadServerState {
            db: db.connection().clone(),
            storage_dir: storage_dir.clone(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(Some("NODE-TEST"), None),
            admin,
        };
        (state, storage_dir)
    }

    /// The operator UI asks for a restart by flipping a switch the run loop is
    /// waiting on. Reporting it is what lets `main` pick an exit code the
    /// supervisor acts on, so a plain `Shutdown` here would leave the node down.
    #[tokio::test]
    async fn serving_reports_a_restart_the_admin_ui_asked_for() {
        let restart = RestartHandle::available();
        let (state, storage_dir) =
            idle_state("admin_restart", AdminState::with_restart(restart.clone())).await;

        let task = tokio::spawn(serve_until_shutdown(
            "127.0.0.1:0".parse().unwrap(),
            state,
            restart.clone(),
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
        let (state, storage_dir) = idle_state(
            "restart_over_http",
            AdminState::new(
                crate::server::admin::credentials::AdminCredential::Env(AdminPassword::new(Some(
                    PASSWORD,
                ))),
                PathBuf::new(),
                restart.clone(),
                crate::app::lifecycle::NodeRuntime::for_tests(Some("NODE-TEST"), None),
            ),
        )
        .await;

        let run_loop = tokio::spawn(serve_until_shutdown(
            addr,
            state,
            restart.clone(),
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
    async fn serving_reports_a_plain_shutdown_as_shutdown() {
        let (state, storage_dir) = idle_state("plain_shutdown", AdminState::disabled()).await;

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            serve_until_shutdown(
                "127.0.0.1:0".parse().unwrap(),
                state,
                RestartHandle::unavailable(),
                future::ready(Ok(())),
            ),
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
