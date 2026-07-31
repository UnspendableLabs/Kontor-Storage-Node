use crate::app::tasks::computeproofs::compute_and_submit_proofs;
use crate::app::tasks::downloadagreements::{download_agreements, rebuild_ledger, StorageBackend};
use crate::app::tasks::getactivechallenges::sync_active_challenges;
use crate::app::tasks::getnewagreements::sync_ready_agreements;
use crate::app::tasks::reconcile;
use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

/// Maximum backoff duration (5 minutes).
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Default)]
pub struct StorageLimits {
    pub capacity: Option<u64>,
    pub max_files: Option<u64>,
    pub max_file_size: Option<u64>,
}

/// Starts the portal synchronization daemon that periodically fetches agreements
/// ready to be signed, stores the new ones locally, and downloads their files.
pub fn spawn_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run_portal_daemon(
            portal_client,
            database,
            interval,
            lock_path,
            storage_limits,
            storage_backend,
            storage_dir,
        )
        .await
        {
            error!("portal daemon stopped with error: {err:#}");
        }
    })
}

async fn run_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
) -> Result<()> {
    // Ensure only a single daemon instance runs at a time.
    let _lock =
        LockFileGuard::acquire(lock_path).context("failed to acquire portal daemon lock")?;

    if let Some(node_id) = portal_client.node_id() {
        // Startup reconcile: ignore the failed-transitions counter. The nonce
        // was just freshly read from the registry during onboarding, so there
        // is no desync window to recover from at this point.
        let _ = reconcile::reconcile_from_portal(
            &portal_client,
            &database,
            node_id,
            &storage_backend,
            &storage_dir,
            true,
        )
        .await
        .context("startup reconciliation failed")?;
    }

    // Run immediately, then on each tick.
    sync_portal_once(
        &portal_client,
        &database,
        storage_limits,
        &storage_backend,
        &storage_dir,
    )
    .await
    .context("initial portal sync failed")?;

    let mut current_backoff = interval;
    loop {
        time::sleep(current_backoff).await;
        match sync_portal_once(
            &portal_client,
            &database,
            storage_limits,
            &storage_backend,
            &storage_dir,
        )
        .await
        {
            Ok(()) => {
                // Reset backoff on success
                if current_backoff != interval {
                    info!("portal sync succeeded, resetting backoff to {:?}", interval);
                }
                current_backoff = interval;
            }
            Err(err) => {
                error!("portal sync failed: {err:#}");
                // Apply exponential backoff, capped at MAX_BACKOFF
                let next_backoff = (current_backoff * 2).min(MAX_BACKOFF);
                if next_backoff != current_backoff {
                    warn!(
                        "applying exponential backoff: next retry in {:?}",
                        next_backoff
                    );
                }
                current_backoff = next_backoff;
            }
        }
    }
}

async fn sync_portal_once(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
    storage_backend: &StorageBackend,
    storage_dir: &std::path::Path,
) -> Result<()> {
    if let Some(max_files) = storage_limits.max_files {
        let downloaded = downloaded_files_count(database).await?;
        if downloaded >= max_files {
            info!(
                "Max stored files limit ({max_files}) reached; skipping agreement fetch and downloads"
            );
            return Ok(());
        }
    }

    // Resync the nonce from Kontor's registry at the start of every cycle so
    // that the local counter always reflects the confirmed on-chain state before
    // any new signed ops are submitted.
    if portal_client.node_id().is_some() {
        if let Err(e) = portal_client.resync_nonce().await {
            warn!("failed to resync nonce at start of sync cycle: {e:#}");
        }
    }

    let mut failed_count: usize = 0;

    if let Some(node_id) = portal_client.node_id() {
        failed_count += reconcile::reconcile_from_portal(
            portal_client,
            database,
            node_id,
            storage_backend,
            storage_dir,
            false,
        )
        .await
        .context("reconciling agreements with Portal")?;
    }

    sync_ready_agreements(portal_client, database)
        .await
        .context("fetching new agreements failed")?;
    download_agreements(portal_client, database, storage_limits, storage_backend)
        .await
        .context("downloading agreements failed")?;

    failed_count += sync_active_challenges(portal_client, database)
        .await
        .context("syncing active challenges failed")?;

    // Refresh the aggregated ledger before proving: this pass may have
    // downloaded new files or learned the contract-assigned `ledger_index` of
    // ones stored earlier, and a proof is only verifiable if the file sits at
    // that exact slot.
    //
    // A failure here is logged rather than propagated: it costs this cycle's
    // proofs (each challenge fails individually against the previous
    // `ledger.bin`, which is left untouched) but downloads, agreement sync and
    // file serving must keep running.
    if let Err(err) = rebuild_ledger(database, storage_dir).await {
        warn!("rebuilding the file ledger failed, proofs may be skipped this cycle: {err:#}");
    }

    compute_and_submit_proofs(portal_client, database, storage_backend, storage_dir)
        .await
        .context("computing and submitting proofs failed")?;

    if failed_count > 0 {
        if let Err(e) = portal_client.resync_nonce().await {
            warn!(
                "failed to resync nonce after observing {failed_count} on-chain failure(s): {e:#}"
            );
        }
    }

    Ok(())
}

async fn downloaded_files_count(database: &DatabaseConnection) -> Result<u64> {
    let count = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(database)
        .await?;
    Ok(count)
}

/// How many times [`LockFileGuard::take`] re-reads the path when it is replaced
/// underneath the handle it just locked. Each retry is one lost race against a
/// daemon shutting down, which happens at most once per acquisition.
#[cfg(unix)]
const LOCK_ATTEMPTS: usize = 3;

/// Filesystem lock preventing two daemons from running against one storage
/// directory.
///
/// # Why the lock is `flock` and not the existence of the file
///
/// The obvious implementation — create the file exclusively, delete it on the
/// way out — has one failure mode, and it is the one that actually happens: a
/// `SIGKILL` runs no destructor, so an out-of-memory kill leaves the file
/// behind and *every subsequent boot* reads "another daemon is already running"
/// about a daemon that died days ago. The node then serves files while quietly
/// proving nothing, which looks healthy from outside.
///
/// Recording the holder's pid and testing it with `kill(pid, 0)` does not fix
/// that in the place it matters. In a container the node is pid 1, so the pid a
/// dead daemon wrote is the pid the process reading it was just assigned —
/// every restart concludes the corpse is alive, which is precisely backwards.
///
/// `flock` has no such gap. The lock belongs to the open file description, and
/// the kernel releases it when the last descriptor closes — on `exit`, on
/// `SIGKILL`, on the whole container going away. "Is the holder alive" stops
/// being something to infer.
///
/// The pid is still written, because it is worth reading in a log; nothing
/// decides anything from it any more.
#[derive(Debug)]
struct LockFileGuard {
    path: PathBuf,
    /// File handle kept open to hold the lock; dropped when guard is dropped.
    _file: std::fs::File,
}

impl LockFileGuard {
    fn acquire(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("unable to create lock directory {}", parent.display()))?;
        }

        let mut file = Self::take(&path)?;

        // Truncated first: the file may still carry a previous holder's pid, and
        // a shorter one written over it would leave that one's trailing digits
        // in place.
        if let Err(e) = file
            .set_len(0)
            .and_then(|()| writeln!(file, "pid={}", process::id()))
        {
            warn!("failed to write pid to lock file: {e}");
        }

        Ok(Self { path, _file: file })
    }

    /// Take the lock, or report that a live daemon holds it.
    #[cfg(unix)]
    fn take(path: &Path) -> Result<std::fs::File> {
        use std::os::unix::fs::MetadataExt;

        for _ in 0..LOCK_ATTEMPTS {
            // `create`, not `create_new`: the file left by a killed daemon is
            // not the lock, so finding one is not a refusal. `flock` below is
            // what decides.
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .with_context(|| format!("unable to open the daemon lock at {}", path.display()))?;

            if !flock_exclusive(&file)? {
                return Err(anyhow!(
                    "another daemon is already running (lock at {})",
                    path.display()
                ));
            }

            // The lock lives on the inode, not on the name. A daemon shutting
            // down unlinks the name it locked, so a handle opened a moment
            // earlier can end up holding an uncontested lock on a file nothing
            // points at — while the next daemon creates a fresh one and locks
            // that. Comparing what was locked against what the name resolves to
            // now is what closes that window.
            let locked = file.metadata().context("inspecting the daemon lock")?;
            match fs::metadata(path) {
                Ok(named) if named.dev() == locked.dev() && named.ino() == locked.ino() => {
                    return Ok(file)
                }
                // Unlinked or replaced under us. Dropping the handle releases
                // its lock; go around again against whatever the name means now.
                _ => drop(file),
            }
        }

        Err(anyhow!(
            "the daemon lock at {} was replaced {LOCK_ATTEMPTS} times while being taken",
            path.display()
        ))
    }

    /// Off Unix there is no `flock`, so the file's existence has to be the lock
    /// and a recorded pid is the only way to tell a dead holder from a live one
    /// — with every weakness described on [`LockFileGuard`]. Production is
    /// Linux; this exists so the crate still builds and behaves sanely
    /// elsewhere.
    #[cfg(not(unix))]
    fn take(path: &Path) -> Result<std::fs::File> {
        if let Err(e) = Self::reclaim_if_stale(path) {
            warn!(
                error = %format!("{e:#}"),
                "could not check whether the daemon lock is stale; treating it as held"
            );
        }

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| {
                format!(
                    "another daemon may already be running (lock at {})",
                    path.display()
                )
            })
    }

    /// Remove a lock left behind by a process that is no longer running.
    ///
    /// Deliberately conservative. Anything short of "this pid is definitely not
    /// alive" leaves the lock alone, because two daemons polling the same Portal
    /// with the same key is a worse failure than one that will not start: a
    /// missing lock is loud, and a duplicated one desynchronises the nonce.
    #[cfg(not(unix))]
    fn reclaim_if_stale(path: &Path) -> Result<()> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).context("reading the daemon lock"),
        };

        let Some(pid) = contents
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid="))
            .and_then(|pid| pid.trim().parse::<u32>().ok())
        else {
            // A lock with no readable pid was truncated mid-write. Nothing to
            // test, so nothing to reclaim.
            return Ok(());
        };

        if pid == process::id() {
            return Ok(());
        }

        warn!(
            pid,
            lock = %path.display(),
            "reclaiming a daemon lock left by a process that is gone; it was almost \
             certainly killed rather than shut down"
        );
        fs::remove_file(path).context("removing the stale daemon lock")?;
        Ok(())
    }
}

/// Take an exclusive advisory lock without blocking.
///
/// `Ok(false)` means another open file description holds it, and that is the
/// only thing it can mean: these locks are released by the kernel when the last
/// descriptor closes, so a `false` here is a *live* holder rather than a
/// question about one.
#[cfg(unix)]
fn flock_exclusive(file: &std::fs::File) -> Result<bool> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `flock` takes a file descriptor and a flag word, shares no memory
    // with the caller, and the descriptor is owned by `file`, which outlives the
    // call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    // `EAGAIN` and `EWOULDBLOCK` are the same value on Linux and macOS, and
    // matching on the pair is what keeps that from being an assumption.
    if matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
    ) {
        return Ok(false);
    }

    // Anything else — a filesystem with no `flock`, a descriptor problem — is
    // not "the lock is free", so it must not be treated as one.
    Err(anyhow::Error::new(error).context("locking the daemon lock file"))
}

impl Drop for LockFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;

    /// The failure the lock exists to survive. A `SIGKILL` — an out-of-memory
    /// kill on a hosting platform — runs no destructor, so the file outlives the
    /// process that made it. The next daemon must take it rather than read it as
    /// a daemon that is still running.
    #[cfg(unix)]
    #[test]
    fn a_lock_left_by_a_killed_daemon_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");

        // Exactly what a killed daemon leaves: the file, with its pid in it, and
        // nothing holding the lock.
        std::fs::write(&path, b"pid=4242\n").unwrap();

        let guard = LockFileGuard::acquire(path.clone()).expect("a lock nobody holds must be free");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            format!("pid={}", process::id()),
            "the new holder must be recorded, with none of the old pid left behind"
        );
        drop(guard);
        assert!(!path.exists());
    }

    /// The container case, which is the whole reason a recorded pid cannot be
    /// the test. The node runs as pid 1, so the pid a killed daemon wrote is the
    /// pid the process reading it was just assigned — and `kill(pid, 0)` on it
    /// answers "alive" about a corpse. `flock` never asks.
    #[cfg(unix)]
    #[test]
    fn a_lock_recording_this_very_pid_is_still_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");

        std::fs::write(&path, format!("pid={}\n", process::id())).unwrap();

        let guard = LockFileGuard::acquire(path.clone())
            .expect("a pid collision across container restarts must not strand the daemon");
        drop(guard);
    }

    /// The other direction, which matters more: two daemons on one key would
    /// desynchronise the nonce. A lock something is really holding is refused —
    /// see `lock_file_guard_prevents_double_acquire` for the message that says
    /// so — and it becomes free again the moment the holder lets go.
    #[test]
    fn a_released_lock_can_be_taken_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");

        let guard = LockFileGuard::acquire(path.clone()).unwrap();
        assert!(path.exists());
        assert!(
            LockFileGuard::acquire(path.clone()).is_err(),
            "a held lock must not be handed out twice"
        );
        drop(guard);
        assert!(!path.exists());

        // And it can be taken again afterwards, which is what a restart does.
        let again = LockFileGuard::acquire(path.clone()).unwrap();
        drop(again);
    }

    /// `flock` is what the whole design rests on, so its two answers are pinned
    /// directly: free, and held by another open file description.
    #[cfg(unix)]
    #[test]
    fn flock_reports_free_then_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flock-probe");

        let first = std::fs::File::create(&path).unwrap();
        assert!(flock_exclusive(&first).unwrap(), "an unheld lock is free");

        let second = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(
            !flock_exclusive(&second).unwrap(),
            "a second descriptor must not get the same lock"
        );

        drop(first);
        assert!(
            flock_exclusive(&second).unwrap(),
            "closing the holder must release it — this is what a SIGKILL does for free"
        );
    }

    use crate::entities::agreements;
    use crate::entities::prelude::Agreements;
    use crate::testutils::{setup_in_memory_db, unique_test_path};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
    use serde_json::json;
    use serial_test::serial;
    use std::fs;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn lock_file_guard_creates_and_cleans_lock_file() {
        let lock_path = unique_test_path("lock_basic");
        let _ = fs::remove_file(&lock_path);

        {
            let guard = LockFileGuard::acquire(lock_path.clone()).unwrap();
            assert!(lock_path.exists(), "lock file should be created");
            let contents = fs::read_to_string(&lock_path).unwrap();
            assert!(
                contents.contains("pid="),
                "lock file should record the process id"
            );
            drop(guard);
        }

        assert!(
            !lock_path.exists(),
            "lock file should be removed when guard is dropped"
        );
    }

    #[test]
    fn lock_file_guard_prevents_double_acquire() {
        let lock_path = unique_test_path("lock_conflict");
        let _ = fs::remove_file(&lock_path);

        let guard = LockFileGuard::acquire(lock_path.clone()).unwrap();
        let error = LockFileGuard::acquire(lock_path.clone()).unwrap_err();
        assert!(
            error.to_string().contains("another daemon is already"),
            "acquiring a held lock should fail, got: {error}"
        );
        drop(guard);

        assert!(
            !lock_path.exists(),
            "lock file should be cleaned after the original guard is dropped"
        );
    }

    #[tokio::test]
    async fn run_portal_daemon_returns_error_when_initial_sync_fails() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_test_path("lock_error");
        let storage_dir = unique_test_path("storage_error");

        let error = run_portal_daemon(
            PortalClient::new(mock_server.uri(), storage_dir.clone()),
            database,
            Duration::from_millis(5),
            lock_path.clone(),
            StorageLimits::default(),
            StorageBackend::local(),
            storage_dir,
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("initial portal sync failed"),
            "initial sync errors should be surfaced"
        );
        assert!(
            !lock_path.exists(),
            "lock file should be removed even when an error occurs"
        );
    }

    #[tokio::test]
    async fn skips_portal_calls_when_max_files_reached() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_test_path("lock_max_files");
        let storage_dir = unique_test_path("storage_max_files");
        fs::remove_dir_all(&storage_dir).ok();

        let already_downloaded = agreements::ActiveModel {
            agreement_id: Set("AGREEMENT-downloaded".into()),
            user_id: Set("user_1".into()),
            file_id: Set("FILE-downloaded".into()),
            filename: Set("downloaded.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(123),
            nodes: Set(json!(["NODE-1"])),
            root: Set(None),
            padded_len: Set(None),
            object_id: Set(None),
            ledger_index: Set(None),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        };
        already_downloaded.insert(&database).await.unwrap();

        let handle = spawn_portal_daemon(
            PortalClient::new(mock_server.uri(), storage_dir.clone()),
            database.clone(),
            Duration::from_millis(10),
            lock_path.clone(),
            StorageLimits {
                capacity: None,
                max_file_size: None,
                max_files: Some(1),
            },
            StorageBackend::local(),
            storage_dir.clone(),
        );

        time::sleep(Duration::from_millis(30)).await;
        handle.abort();
        let _ = handle.await;

        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "daemon should not call portal when max files limit is reached"
        );
        assert!(
            !lock_path.exists(),
            "lock file should be cleaned up when daemon task is dropped"
        );
    }

    #[tokio::test]
    async fn run_portal_daemon_logs_when_daemon_task_fails() {
        // Force the daemon spawned via spawn_portal_daemon to hit the error
        // logging branch (line 52) by making the initial sync fail.
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_test_path("lock_spawn_error");
        let storage_dir = unique_test_path("storage_spawn_error");
        fs::remove_file(&lock_path).ok();

        let handle = spawn_portal_daemon(
            PortalClient::new(mock_server.uri(), storage_dir.clone()),
            database,
            Duration::from_millis(5),
            lock_path.clone(),
            StorageLimits::default(),
            StorageBackend::local(),
            storage_dir,
        );

        // Wait for the daemon to fail and exit on its own. The spawned task
        // should complete because run_portal_daemon returns Err on initial sync failure.
        let res = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            res.is_ok(),
            "daemon task should exit after logging the error"
        );
        assert!(
            !lock_path.exists(),
            "lock file should be cleaned up after daemon exits"
        );
    }

    fn create_authenticated_portal_client(
        mock_server_uri: &str,
        storage_dir: PathBuf,
    ) -> PortalClient {
        use crate::crypto::BlsKeyPair;
        let keypair = std::sync::Arc::new(BlsKeyPair::generate().unwrap());
        PortalClient::with_auth(
            mock_server_uri,
            storage_dir,
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        )
    }

    #[tokio::test]
    async fn spawn_portal_daemon_recovers_from_transient_sync_failure() {
        // Exercise both backoff branches (lines 108, 113, 115-122) by
        // having the initial sync succeed, then a subsequent sync fail (triggers
        // backoff), then succeed again (triggers backoff reset).
        let mock_server = MockServer::start().await;

        // First call (initial sync) succeeds with empty list.
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Second call (after first sleep) fails to trigger backoff (lines 113, 115-122).
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Subsequent calls succeed to trigger the reset-backoff branch (line 108).
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

        // Get node challenges endpoint always returns empty (paginated).
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "challenges": []
            })))
            .mount(&mock_server)
            .await;

        // For auth-enabled clients, reconcile is invoked on startup and
        // fetches /api/agreements?nodes=NODE-test which we serve as empty.
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("nodes", "NODE-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_test_path("lock_backoff_recover");
        let storage_dir = unique_test_path("storage_backoff_recover");
        fs::remove_file(&lock_path).ok();
        fs::remove_dir_all(&storage_dir).ok();
        fs::create_dir_all(&storage_dir).ok();

        let handle = spawn_portal_daemon(
            create_authenticated_portal_client(&mock_server.uri(), storage_dir.clone()),
            database,
            Duration::from_millis(10),
            lock_path.clone(),
            StorageLimits::default(),
            StorageBackend::local(),
            storage_dir.clone(),
        );

        // Wait long enough for the daemon to: 1) initial sync (success),
        // 2) sleep, 3) fail sync (backoff applied), 4) sleep, 5) success (backoff reset).
        // The expected /api/agreements call count is at least 3.
        let start = time::Instant::now();
        let mut req_count = 0usize;
        while start.elapsed() < Duration::from_secs(10) {
            time::sleep(Duration::from_millis(100)).await;
            req_count = mock_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/api/agreements")
                .count();
            if req_count >= 3 {
                break;
            }
        }

        handle.abort();
        let _ = handle.await;

        assert!(
            req_count >= 3,
            "expected initial+fail+retry path to make at least 3 attempts, got {req_count}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn spawn_portal_daemon_syncs_initially_and_on_interval() {
        let mock_server = MockServer::start().await;
        let response_body = json!({
            "offset": 0,
            "limit": 20,
            "total": 1,
            "agreements": [{
                "agreement_id": "AGREEMENT-test",
                "user_id": "user_1",
                "file_id": "FILE-abc",
                "filename": "contract.pdf",
                "mime_type": "application/pdf",
                "original_size": 1024,
                "nodes": [{"node_id": "NODE-1", "status": "valid"}],
                "transaction_id": null,
                "curation": {},
                "status": "ready",
                "created_at": "2024-01-15T10:30:00Z"
            }]
        });
        let download_url = format!("{}/files/contract.pdf", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/agreements/AGREEMENT-test/download"))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/files/contract.pdf"))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_test_path("lock_loop");
        let storage_dir = unique_test_path("storage_loop");
        fs::remove_file(&lock_path).ok();
        fs::remove_dir_all(&storage_dir).ok();

        let handle = spawn_portal_daemon(
            PortalClient::new(mock_server.uri(), storage_dir.clone()),
            database.clone(),
            Duration::from_millis(10),
            lock_path.clone(),
            StorageLimits::default(),
            StorageBackend::local(),
            storage_dir.clone(),
        );

        // Wait for the daemon to download the agreement at least once. Give it
        // generous time to finish a full sync cycle, since the download involves
        // hashing, ledger writes, and metadata persistence.
        let start = time::Instant::now();
        let mut downloaded = false;
        while start.elapsed() < Duration::from_secs(20) {
            time::sleep(Duration::from_millis(50)).await;
            if let Some(agreement) = Agreements::find().one(&database).await.unwrap() {
                if agreement.downloaded {
                    downloaded = true;
                    break;
                }
            }
        }

        handle.abort();
        let _ = handle.await;

        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            requests.len() >= 2,
            "initial sync plus at least one ticked sync should run"
        );

        let stored = Agreements::find().count(&database).await.unwrap();
        assert_eq!(stored, 1, "agreement should be inserted exactly once");

        let agreement = Agreements::find().one(&database).await.unwrap().unwrap();
        assert!(
            downloaded && agreement.downloaded,
            "download task should mark agreements as downloaded"
        );
        let contents = fs::read_to_string(storage_dir.join("FILE-abc")).unwrap();
        assert_eq!(contents, "file-body");

        assert!(
            !lock_path.exists(),
            "lock file should be cleaned up when daemon task is dropped"
        );
    }

    fn portal_client_with_nonce(
        mock_server_uri: &str,
        storage_dir: PathBuf,
        initial_nonce: u64,
    ) -> PortalClient {
        use crate::crypto::BlsKeyPair;
        let keypair = std::sync::Arc::new(BlsKeyPair::generate().unwrap());
        PortalClient::with_auth(
            mock_server_uri,
            storage_dir,
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            initial_nonce,
        )
    }

    async fn mount_empty_ready_agreements(mock_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(mock_server)
            .await;
    }

    async fn mount_empty_challenges(mock_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "challenges": []
            })))
            .mount(mock_server)
            .await;
    }

    fn agreement_payload(agreement_id: &str, file_id: &str, status: &str) -> serde_json::Value {
        json!({
            "agreement_id": agreement_id,
            "user_id": "user_1",
            "file_id": file_id,
            "filename": "test.bin",
            "mime_type": "application/octet-stream",
            "original_size": 123,
            "nodes": [{"node_id": "NODE-test", "status": "valid"}],
            "transaction_id": null,
            "curation": {},
            "status": status,
            "created_at": "2024-01-01T00:00:00Z"
        })
    }

    #[tokio::test]
    async fn sync_portal_once_resyncs_nonce_after_failed_transition() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGR-failed-nonce";
        let file_id = "FILE-AGR-failed-nonce";

        // Reconcile endpoint: agreement transitions to failed.
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("nodes", "NODE-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "agreements": [agreement_payload(agreement_id, file_id, "failed")]
            })))
            .mount(&mock_server)
            .await;

        mount_empty_ready_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;

        // Registry endpoint is hit twice: once at startup resync, once after
        // observing the failed transition.
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abcd",
                "bls_pubkey": null,
                "next_nonce": 99
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_resync");
        fs::create_dir_all(&storage_dir).ok();

        // Seed the agreement locally with status=ready so reconcile detects the
        // remote `failed` as a fresh transition.
        let seeded = agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("test.bin".into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(123),
            nodes: Set(json!([{"node_id": "NODE-test", "status": "valid"}])),
            root: Set(None),
            padded_len: Set(None),
            object_id: Set(None),
            ledger_index: Set(None),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        };
        seeded.insert(&database).await.unwrap();

        let portal_client = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 5);
        assert_eq!(portal_client.current_nonce(), Some(5));

        sync_portal_once(
            &portal_client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
        )
        .await
        .expect("sync_portal_once should succeed");

        assert_eq!(
            portal_client.current_nonce(),
            Some(99),
            "nonce should be resynced from registry after observing failed transition"
        );
    }

    #[tokio::test]
    async fn sync_portal_once_resyncs_nonce_at_start_of_every_cycle() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("nodes", "NODE-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        mount_empty_ready_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;

        // Registry endpoint is now hit once per cycle (startup resync), even
        // without any failed transitions.
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abcd",
                "bls_pubkey": null,
                "next_nonce": 99
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_resync_each_cycle");
        fs::create_dir_all(&storage_dir).ok();

        let portal_client = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 5);

        sync_portal_once(
            &portal_client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
        )
        .await
        .expect("sync_portal_once should succeed");

        assert_eq!(
            portal_client.current_nonce(),
            Some(99),
            "nonce should be resynced from registry at the start of each sync cycle"
        );
    }
}
