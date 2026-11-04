use crate::app::tasks::computeproofs::{compute_and_submit_proofs, ProofRetries};
use crate::app::tasks::downloadagreements::{
    download_agreements_gated, rebuild_ledger, StorageBackend,
};
use crate::app::tasks::getactivechallenges::sync_active_challenges;
use crate::app::tasks::getnewagreements::{sync_ready_agreements, ReadyListing};
use crate::app::tasks::reconcile;
use crate::app::tasks::stake::{
    exit_inputs, manage_stake, persist_withdrawal_start, refresh_memberships,
    restore_withdrawal_start, settle_pending_joins, JoinBudget, StakeTracker,
};
use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, error, info, warn};

/// Maximum backoff duration (5 minutes).
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Default)]
pub struct StorageLimits {
    pub capacity: Option<u64>,
    pub max_files: Option<u64>,
    pub max_file_size: Option<u64>,
}

/// What the daemon carries from one cycle to the next.
#[derive(Debug, Default)]
pub(crate) struct DaemonMemory {
    /// The bond, and the stake ops and joins still waiting to land. Shared
    /// with `/admin`, and with the onboarding step that queued the first
    /// top-up before this daemon started.
    pub staking: Arc<StakeTracker>,
    /// How often each challenge has been proved, so a proof Kontor keeps
    /// rejecting is not recomputed every cycle until its deadline.
    pub proofs: ProofRetries,
}

/// Starts the portal synchronization daemon that periodically fetches agreements
/// ready to be signed, stores the new ones locally, and downloads their files.
///
/// `staking` is the bond tracker the node's runtime owns, shared with `/admin`
/// and with the onboarding step that may already have an op in flight.
// Eight plain inputs, each from a different part of the configuration;
// bundling them would only move the list into a struct used exactly here.
#[allow(clippy::too_many_arguments)]
pub fn spawn_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
    staking: Arc<StakeTracker>,
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
            staking,
        )
        .await
        {
            error!("portal daemon stopped with error: {err:#}");
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
    storage_limits: StorageLimits,
    storage_backend: StorageBackend,
    storage_dir: PathBuf,
    staking: Arc<StakeTracker>,
) -> Result<()> {
    let memory = DaemonMemory {
        staking,
        proofs: ProofRetries::default(),
    };

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
        &memory,
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
            &memory,
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

/// One daemon cycle.
///
/// The order is the point: the stake is read first, because every join
/// decision of the cycle is made against it; agreements are taken on next;
/// proofs come after, so a full node or a refused join never costs one; and
/// the stake op goes out last, holding the highest nonce of the cycle — if it
/// ever collides with another op on a nonce it is the one that loses, and a
/// lost top-up is retried next cycle where a lost proof is a slash.
async fn sync_portal_once(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
    storage_backend: &StorageBackend,
    storage_dir: &std::path::Path,
    memory: &DaemonMemory,
) -> Result<()> {
    // A node at its file limit takes on nothing new, but keeps proving what it
    // already stores, and still downloads the files of memberships it holds:
    // skipping the whole cycle here used to mean every challenge on a full node
    // expired, and an expired challenge — like one on a file the node never
    // fetched — is slashed at 30× the agreement's collateral.
    let at_file_limit = match storage_limits.max_files {
        Some(max_files) if downloaded_files_count(database).await? >= max_files => {
            info!(
                "Max stored files limit ({max_files}) reached; not fetching new agreements, \
                 only the files of memberships this node holds"
            );
            true
        }
        _ => false,
    };

    // Read Kontor's registry entry at the start of every cycle. The local nonce
    // counter is only ever moved *up* to its `next_nonce` (see
    // `resynced_nonce`): ops signed last cycle are usually still queued at the
    // Portal, and signing at their nonces again is what collided. The same read
    // carries the bond, so the cycle's staking decisions share its snapshot.
    if portal_client.node_id().is_some() {
        // The start of a withdrawal delay an earlier process recorded, read
        // once before this process acts on its own reads; and after each read,
        // the start as this process counts it, written for the next one.
        if !memory.staking.withdrawal_start_restored() {
            if let Err(err) =
                restore_withdrawal_start(database, &memory.staking, Instant::now()).await
            {
                warn!("could not read when the withdrawal delay started: {err:#}");
            }
        }
        let entry = match portal_client.resync_from_registry().await {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!("failed to resync nonce at start of sync cycle: {e:#}");
                None
            }
        };
        memory.staking.observe(entry.as_ref(), Instant::now());
        if let Err(err) = persist_withdrawal_start(database, &memory.staking).await {
            warn!("could not record when the withdrawal delay started: {err:#}");
        }
    }

    if let Some(node_id) = portal_client.node_id() {
        reconcile::reconcile_from_portal_with(
            portal_client,
            database,
            node_id,
            storage_backend,
            storage_dir,
            false,
            |agreements| {
                let now = Instant::now();
                for agreement in agreements {
                    memory
                        .staking
                        .note_collateral(agreement.required_collateral.as_deref(), now);
                }
            },
        )
        .await
        .context("reconciling agreements with Portal")?;
    }

    // At the limit the listing stays empty, and the download step's own limit
    // check keeps any agreement not held yet from being fetched or joined.
    let listing = if at_file_limit {
        ReadyListing::new()
    } else {
        let listing = sync_ready_agreements(portal_client, database)
            .await
            .context("fetching new agreements failed")?;
        let now = Instant::now();
        for agreement in listing.values() {
            memory
                .staking
                .note_collateral(agreement.required_collateral.as_deref(), now);
        }
        listing
    };
    // Joins that will never execute give their collateral back before the
    // budget is drawn up: the listing just read shows which of this node's
    // rows the Portal has invalidated, and the rows which agreements are no
    // longer open to joins.
    if let Some(node_id) = portal_client.node_id() {
        if let Err(err) = settle_pending_joins(database, &memory.staking, node_id, &listing).await {
            warn!("could not settle the pending joins this cycle: {err:#}");
        }
    }
    let mut budget = if portal_client.node_id().is_some() {
        memory.staking.join_budget(Instant::now())
    } else {
        JoinBudget::unmetered()
    };
    download_agreements_gated(
        portal_client,
        database,
        storage_limits,
        storage_backend,
        &listing,
        &mut budget,
        Some(&memory.staking),
    )
    .await
    .context("downloading agreements failed")?;

    sync_active_challenges(portal_client, database)
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

    compute_and_submit_proofs(
        portal_client,
        database,
        storage_backend,
        storage_dir,
        &memory.proofs,
    )
    .await
    .context("computing and submitting proofs failed")?;

    // The exit, once the operator's unstake has executed, is worked out from
    // the node's own rows: which memberships it holds and which challenges
    // are still open. Those rows are first brought up to date with the Portal
    // — once per process, and again after a withdrawal that did not take —
    // so a leave is not paid for a membership an earlier process already
    // left. A failure of either only postpones the next exit step.
    let exit = match portal_client.node_id() {
        Some(node_id) if memory.staking.exiting() => {
            let current = if memory.staking.memberships_need_refresh() {
                match refresh_memberships(portal_client, database, node_id).await {
                    Ok(()) => {
                        memory.staking.memberships_refreshed();
                        true
                    }
                    Err(err) => {
                        warn!("could not re-read the memberships for the exit this cycle: {err:#}");
                        false
                    }
                }
            } else {
                true
            };
            match exit_inputs(database, node_id).await {
                Ok(exit) if current => Some(exit),
                Ok(_) => None,
                Err(err) => {
                    warn!("could not read memberships for the exit this cycle: {err:#}");
                    None
                }
            }
        }
        _ => None,
    };
    manage_stake(portal_client, &memory.staking, exit.as_ref()).await;

    Ok(())
}

async fn downloaded_files_count(database: &DatabaseConnection) -> Result<u64> {
    let count = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(database)
        .await?;
    Ok(count)
}

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
///
/// # Why the file is never deleted
///
/// Because the file is not the lock — the lock is on the inode, and the kernel
/// holds it whether or not any name still points there. Unlinking on the way
/// out is therefore not cleanup; it is a way to lose the lock. A daemon that
/// removes the name a successor has already created and locked leaves that
/// successor holding an anonymous inode, and a third daemon can then create a
/// fresh file, lock *that*, and run alongside it. Two daemons on one key
/// desynchronise the nonce, which is the failure this whole guard exists to
/// prevent.
///
/// So the file simply stays. It costs one inode, it carries the last holder's
/// pid for whoever is reading logs, and its presence means nothing at all —
/// which is exactly the property that made `SIGKILL` survivable in the first
/// place. Off Unix there is no `flock`, so there the file's existence *is* the
/// lock and it has to be removed; see [`LockFileGuard::take`].
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
    ///
    /// One open, one `flock`, no retry and no inode comparison: nothing ever
    /// unlinks this path, so the name and the inode behind it cannot come
    /// apart. That is the simplification the "never deleted" rule on
    /// [`LockFileGuard`] buys, and the reason it is worth having.
    #[cfg(unix)]
    fn take(path: &Path) -> Result<std::fs::File> {
        // `create`, not `create_new`: the file left by a killed daemon is not
        // the lock, so finding one is not a refusal. `flock` below is what
        // decides.
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

        Ok(file)
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
        // Off Unix the file's existence *is* the lock, so there it has to go.
        // On Unix it deliberately stays: closing the handle is the whole
        // release, and unlinking a name a successor may already have created
        // and locked is how two daemons end up running. See [`LockFileGuard`].
        #[cfg(not(unix))]
        let _ = fs::remove_file(&self.path);

        debug!(lock = %self.path.display(), "released the daemon lock");
    }
}

/// Whether something currently holds the daemon lock at `path`.
///
/// Test-only, and it exists because the file no longer answers that question:
/// it outlives every holder, so "is the lock free" has to be asked of the
/// kernel. Probing takes the lock and immediately drops it, which is safe
/// precisely because nothing unlinks the name.
#[cfg(all(test, unix))]
pub(crate) fn lock_is_held(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        // No file at all means nothing ever locked it here.
        return false;
    };
    !flock_exclusive(&file).unwrap_or(false)
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

        // The name stays; the lock does not. That asymmetry is the design: the
        // file is a place to read a pid, and the kernel is the authority on
        // whether anything holds it.
        assert!(path.exists(), "the lock file is never unlinked");
        assert!(!lock_is_held(&path), "dropping the guard releases the lock");
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

        // And it can be taken again afterwards, which is what a restart does.
        let again = LockFileGuard::acquire(path.clone()).unwrap();
        drop(again);
    }

    /// The reason the file is never unlinked, as a test rather than a comment.
    /// A guard that removed its own path on the way out would take a
    /// successor's file with it — leaving that successor holding an anonymous
    /// inode while a third daemon creates a fresh name, locks it, and runs
    /// alongside. Two daemons on one key desynchronise the nonce.
    #[cfg(unix)]
    #[test]
    fn releasing_a_lock_never_removes_a_successor_s_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");

        let outgoing = LockFileGuard::acquire(path.clone()).unwrap();
        drop(outgoing);

        let incoming = LockFileGuard::acquire(path.clone()).unwrap();
        // A second release of the outgoing guard cannot happen, but the shape
        // it would have — an unlink of this path — must not be something the
        // successor's lock depends on surviving. It does not: the name is still
        // the inode the successor holds, and the lock is still held.
        assert!(path.exists());
        assert!(lock_is_held(&path), "the successor still holds it");
        assert!(
            LockFileGuard::acquire(path.clone()).is_err(),
            "and nobody else can take it"
        );
        drop(incoming);
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
    use crate::testutils::{setup_in_memory_db, unique_test_path, AgreementFixture};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
    use serde_json::json;
    use serial_test::serial;
    use std::fs;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[cfg(unix)]
    #[test]
    fn lock_file_guard_records_its_holder_and_releases_on_drop() {
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
            assert!(lock_is_held(&lock_path));
            drop(guard);
        }

        assert!(
            !lock_is_held(&lock_path),
            "the lock should be free once the guard is dropped"
        );
        let _ = fs::remove_file(&lock_path);
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

        LockFileGuard::acquire(lock_path.clone())
            .expect("the lock should be free after the original guard is dropped");
        let _ = fs::remove_file(&lock_path);
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
            Arc::new(StakeTracker::default()),
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("initial portal sync failed"),
            "initial sync errors should be surfaced"
        );
        assert!(
            !lock_is_held(&lock_path),
            "the lock should be released even when an error occurs"
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
            Arc::new(StakeTracker::default()),
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
            !lock_is_held(&lock_path),
            "the lock should be released when the daemon task is dropped"
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
            Arc::new(StakeTracker::default()),
        );

        // Wait for the daemon to fail and exit on its own. The spawned task
        // should complete because run_portal_daemon returns Err on initial sync failure.
        let res = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            res.is_ok(),
            "daemon task should exit after logging the error"
        );
        assert!(
            !lock_is_held(&lock_path),
            "the lock should be released after the daemon exits"
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
            Arc::new(StakeTracker::default()),
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
            Arc::new(StakeTracker::default()),
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
            !lock_is_held(&lock_path),
            "the lock should be released when the daemon task is dropped"
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

    /// An op that failed on chain used to rewind the counter to Kontor's
    /// `next_nonce` — onto the nonces of ops still queued at the Portal. It now
    /// leaves the counter where it is.
    #[tokio::test]
    async fn an_on_chain_failure_does_not_rewind_the_nonce() {
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

        // Read once, at the start of the cycle; the failure costs no second read.
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

        // Ahead of Kontor: ops signed since its last block, still queued.
        let portal_client = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 120);

        sync_portal_once(
            &portal_client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
            &DaemonMemory::default(),
        )
        .await
        .expect("sync_portal_once should succeed");

        assert_eq!(
            portal_client.current_nonce(),
            Some(120),
            "a failure on chain must not move the nonce back onto queued ops"
        );
    }

    /// Every cycle reads Kontor's `next_nonce` and moves the counter up to it
    /// — but never back down onto ops the Portal still has queued.
    #[tokio::test]
    async fn every_cycle_moves_the_nonce_up_to_kontors_and_never_down() {
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

        // Hit once per cycle, even without any failed transitions.
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abcd",
                "bls_pubkey": null,
                "next_nonce": 99
            })))
            .expect(3)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_resync_each_cycle");
        fs::create_dir_all(&storage_dir).ok();
        let memory = DaemonMemory::default();

        let behind = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 5);
        let ahead = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 120);
        for client in [&behind, &ahead, &ahead] {
            sync_portal_once(
                client,
                &database,
                StorageLimits::default(),
                &StorageBackend::local(),
                &storage_dir,
                &memory,
            )
            .await
            .expect("sync_portal_once should succeed");
        }

        assert_eq!(behind.current_nonce(), Some(99), "moved up to Kontor's");
        assert_eq!(
            ahead.current_nonce(),
            Some(120),
            "kept ahead of Kontor's, cycle after cycle"
        );
    }

    async fn mount_no_node_agreements(mock_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("nodes", "NODE-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 20, "total": 0, "agreements": []
            })))
            .mount(mock_server)
            .await;
    }

    /// A full node used to skip its whole cycle, proofs included — and every
    /// challenge it then missed is now slashed at 30× the collateral. At the
    /// limit it stops taking on agreements and keeps proving.
    #[tokio::test]
    async fn a_node_at_its_file_limit_still_syncs_its_challenges() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42, "x_only_pubkey": "abcd", "bls_pubkey": null, "next_nonce": 0
            })))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        AgreementFixture {
            downloaded: true,
            ..AgreementFixture::new("AGR-full", "FILE-full")
        }
        .into_active_model()
        .insert(&database)
        .await
        .unwrap();
        let storage_dir = unique_test_path("daemon_full_node");
        fs::create_dir_all(&storage_dir).ok();

        sync_portal_once(
            &portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 0),
            &database,
            StorageLimits {
                max_files: Some(1),
                ..StorageLimits::default()
            },
            &StorageBackend::local(),
            &storage_dir,
            &DaemonMemory::default(),
        )
        .await
        .unwrap();

        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.url.path() == "/api/nodes/NODE-test/challenges"),
            "challenges must still be synced at the file limit"
        );
    }

    /// At the limit, a membership the node holds but has no file for is still
    /// downloaded — that file is what its next challenge is slashed for — and
    /// nothing new is fetched or joined.
    #[tokio::test]
    async fn a_node_at_its_file_limit_still_downloads_what_it_holds() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42, "x_only_pubkey": "abcd", "bls_pubkey": null, "next_nonce": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-held/download"))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": format!("{}/files/held", mock_server.uri())
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/held"))
            .respond_with(ResponseTemplate::new(200).set_body_string("held-body"))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-other/download"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        AgreementFixture {
            downloaded: true,
            ..AgreementFixture::new("AGR-full", "FILE-full")
        }
        .into_active_model()
        .insert(&database)
        .await
        .unwrap();
        AgreementFixture::new("AGR-held", "FILE-held")
            .into_active_model()
            .insert(&database)
            .await
            .unwrap();
        AgreementFixture {
            nodes: json!([]),
            ..AgreementFixture::new("AGR-other", "FILE-other")
        }
        .into_active_model()
        .insert(&database)
        .await
        .unwrap();
        let storage_dir = unique_test_path("daemon_full_node_held");
        fs::create_dir_all(&storage_dir).ok();

        sync_portal_once(
            &portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 0),
            &database,
            StorageLimits {
                max_files: Some(1),
                ..StorageLimits::default()
            },
            &StorageBackend::local(),
            &storage_dir,
            &DaemonMemory::default(),
        )
        .await
        .unwrap();

        let held = Agreements::find_by_id("AGR-held")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(held.downloaded, "the held membership's file was fetched");
        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            !requests.iter().any(|r| r.url.path().ends_with("/join")),
            "nothing joined at the limit"
        );
    }

    /// The registry entry of a new node the faucet just funded.
    fn funded_entry(next_nonce: u64) -> serde_json::Value {
        json!({
            "signer_id": 42,
            "x_only_pubkey": "abcd",
            "bls_pubkey": null,
            "next_nonce": next_nonce,
            "kor_balance": "1000",
            "stake": "0",
            "stake_reserved": "0",
            "stake_available": "0",
            "stake_withdrawal_height": null,
            "bond_cleanup_pending": false,
            "reward_balance": "0"
        })
    }

    /// The top-up goes out at the end of the cycle — after every join and
    /// proof, holding the cycle's highest nonce — and is not sent again while
    /// Kontor has not executed it.
    #[tokio::test]
    async fn the_stake_top_up_goes_out_last_and_once_until_it_lands() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_ready_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(funded_entry(3)))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(wiremock::matchers::body_partial_json(json!({
                "op": "add_stake",
                "amount": "995",
                "nonce": 3
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": "add_stake", "status": "queued", "nonce": 3
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_stake_last");
        fs::create_dir_all(&storage_dir).ok();
        let client = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 0);
        let memory = DaemonMemory::default();

        for _ in 0..2 {
            sync_portal_once(
                &client,
                &database,
                StorageLimits::default(),
                &StorageBackend::local(),
                &storage_dir,
                &memory,
            )
            .await
            .unwrap();
        }

        let requests = mock_server.received_requests().await.unwrap();
        let first_cycle_end = requests
            .iter()
            .position(|r| r.url.path() == "/api/nodes/NODE-test/ops")
            .expect("the top-up was sent");
        assert!(
            requests[..first_cycle_end]
                .iter()
                .any(|r| r.url.path() == "/api/nodes/NODE-test/challenges"),
            "the cycle's other work came before the top-up"
        );
        assert_eq!(memory.staking.status()["in_flight"]["nonce"], 3);
    }

    /// Onboarding queues the first top-up at Kontor's `next_nonce`, N. The
    /// first cycle reads the same N — the top-up waits for a block — and used to
    /// rewind the counter to it, signing that cycle's first op at N again.
    #[tokio::test]
    async fn the_first_cycle_does_not_re_sign_the_bootstrap_nonce() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_ready_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(funded_entry(3)))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": "add_stake", "status": "queued", "nonce": 3
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_bootstrap_nonce");
        fs::create_dir_all(&storage_dir).ok();
        let client = portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 3);
        let memory = DaemonMemory::default();

        crate::app::tasks::stake::bootstrap_stake(&client, &memory.staking, &mut Vec::new())
            .await
            .unwrap();
        assert_eq!(client.current_nonce(), Some(4), "the top-up took nonce 3");

        sync_portal_once(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
            &memory,
        )
        .await
        .unwrap();
        assert_eq!(
            client.current_nonce(),
            Some(4),
            "Kontor still says 3, and the next op must not be signed at it"
        );
    }

    /// Joins are gated on the bond the cycle just read: an agreement whose
    /// collateral the stake cannot cover is not even downloaded.
    #[tokio::test]
    async fn a_cycle_does_not_download_what_its_stake_cannot_cover() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        let mut ready = agreement_payload("AGR-costly", "FILE-costly", "ready");
        ready["nodes"] = json!([]);
        ready["required_collateral"] = json!("500");
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 20, "total": 1, "agreements": [ready]
            })))
            .mount(&mock_server)
            .await;
        let mut entry = funded_entry(3);
        entry["kor_balance"] = json!("5");
        entry["stake"] = json!("100");
        entry["stake_available"] = json!("100");
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(entry))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-costly/download"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_test_path("daemon_gate");
        fs::create_dir_all(&storage_dir).ok();

        sync_portal_once(
            &portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 0),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
            &DaemonMemory::default(),
        )
        .await
        .unwrap();

        let stored = Agreements::find_by_id("AGR-costly")
            .one(&database)
            .await
            .unwrap()
            .expect("still recorded as ready, for a later cycle");
        assert!(!stored.downloaded);
    }

    /// Once the operator's unstake has executed, the cycle's op is the exit:
    /// a `leave_agreement` for a membership the node's own rows hold.
    #[tokio::test]
    async fn an_executed_unstake_turns_the_cycle_s_op_into_a_leave() {
        let mock_server = MockServer::start().await;
        mount_no_node_agreements(&mock_server).await;
        mount_empty_ready_agreements(&mock_server).await;
        mount_empty_challenges(&mock_server).await;
        let mut entry = funded_entry(4);
        entry["kor_balance"] = json!("5");
        entry["stake"] = json!("100");
        entry["stake_available"] = json!("70");
        entry["stake_withdrawal_height"] = json!(9000);
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(entry))
            .mount(&mock_server)
            .await;
        // The exit's first step in a process re-reads each membership from
        // the Portal, which is the only place a leave made by an earlier
        // process shows (as `left`).
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-held"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agreement_id": "AGR-held",
                "user_id": "user_1",
                "file_id": "FILE-held",
                "filename": "test.bin",
                "mime_type": "application/octet-stream",
                "original_size": 123,
                "nodes": [{"node_id": "NODE-test", "status": "valid"}],
                "transaction_id": null,
                "status": "confirmed",
                "created_at": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(wiremock::matchers::body_partial_json(json!({
                "op": "leave_agreement",
                "agreement_id": "AGR-held",
                "nonce": 4
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": "leave_agreement", "status": "queued", "nonce": 4
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        AgreementFixture {
            status: "confirmed".into(),
            downloaded: true,
            nodes: json!([{"node_id": "NODE-test", "status": "valid"}]),
            ..AgreementFixture::new("AGR-held", "FILE-held")
        }
        .into_active_model()
        .insert(&database)
        .await
        .unwrap();
        let storage_dir = unique_test_path("daemon_exit");
        fs::create_dir_all(&storage_dir).ok();
        let memory = DaemonMemory::default();

        sync_portal_once(
            &portal_client_with_nonce(&mock_server.uri(), storage_dir.clone(), 0),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &storage_dir,
            &memory,
        )
        .await
        .unwrap();

        let status = memory.staking.status();
        assert_eq!(status["in_flight"]["op"], "leave_agreement");
        assert_eq!(status["exit"]["memberships_left"], json!(["AGR-held"]));
    }
}
