use crate::clients::PortalClient;
use crate::tasks::getnewagreements::sync_ready_agreements;
use anyhow::{Context, Result};
use sea_orm::DatabaseConnection;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;

/// Starts the portal synchronization daemon that periodically fetches agreements
/// ready to be signed and stores the new ones locally.
pub fn spawn_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = run_portal_daemon(portal_client, database, interval, lock_path).await {
            eprintln!("portal daemon stopped with error: {err:#}");
        }
    })
}

async fn run_portal_daemon(
    portal_client: PortalClient,
    database: DatabaseConnection,
    interval: Duration,
    lock_path: PathBuf,
) -> Result<()> {
    // Ensure only a single daemon instance runs at a time.
    let _lock =
        LockFileGuard::acquire(lock_path).context("failed to acquire portal daemon lock")?;

    // Run immediately, then on each tick.
    sync_ready_agreements(&portal_client, &database)
        .await
        .context("initial agreements sync failed")?;

    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(err) = sync_ready_agreements(&portal_client, &database).await {
            eprintln!("failed to sync agreements: {err:#}");
        }
    }
}

/// Simple filesystem-based lock to prevent multiple daemon instances.
struct LockFileGuard {
    path: PathBuf,
    #[allow(dead_code)]
    file: std::fs::File,
}

impl LockFileGuard {
    fn acquire(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("unable to create lock directory {}", parent.display()))?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "another daemon may already be running (lock at {})",
                    path.display()
                )
            })?;

        writeln!(file, "pid={}", process::id()).ok();

        Ok(Self { path, file })
    }
}

impl Drop for LockFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
