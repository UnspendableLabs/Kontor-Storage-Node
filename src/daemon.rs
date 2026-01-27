use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use crate::tasks::computeproofs::compute_and_submit_proofs;
use crate::tasks::downloadagreements::{download_agreements, StorageBackend};
use crate::tasks::getactivechallenges::sync_active_challenges;
use crate::tasks::getnewagreements::sync_ready_agreements;
use anyhow::{Context, Result};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info};

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

    let mut ticker = time::interval(interval);
    loop {
        ticker.tick().await;
        if let Err(err) = sync_portal_once(
            &portal_client,
            &database,
            storage_limits,
            &storage_backend,
            &storage_dir,
        )
        .await
        {
            error!("portal sync failed: {err:#}");
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

    sync_ready_agreements(portal_client, database)
        .await
        .context("fetching new agreements failed")?;
    download_agreements(portal_client, database, storage_limits, storage_backend)
        .await
        .context("downloading agreements failed")?;

    sync_active_challenges(portal_client, database)
        .await
        .context("syncing active challenges failed")?;

    compute_and_submit_proofs(portal_client, database, storage_backend, storage_dir)
        .await
        .context("computing and submitting proofs failed")?;

    Ok(())
}

async fn downloaded_files_count(database: &DatabaseConnection) -> Result<u64> {
    let count = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(database)
        .await?;
    Ok(count)
}

/// Simple filesystem-based lock to prevent multiple daemon instances.
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::agreements;
    use crate::entities::prelude::Agreements;
    use chrono::DateTime;
    use sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, DatabaseBackend, EntityTrait, PaginatorTrait,
        Schema, Set,
    };
    use serde_json::json;
    use serial_test::serial;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_path(prefix: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_daemon_test_{prefix}_{id}"))
    }

    async fn setup_in_memory_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DatabaseBackend::Sqlite);
        let agreements_stmt = schema.create_table_from_entity(Agreements);
        db.execute(&agreements_stmt).await.unwrap();
        db
    }

    #[test]
    fn lock_file_guard_creates_and_cleans_lock_file() {
        let lock_path = unique_path("lock_basic");
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
        let lock_path = unique_path("lock_conflict");
        let _ = fs::remove_file(&lock_path);

        let guard = LockFileGuard::acquire(lock_path.clone()).unwrap();
        let error = LockFileGuard::acquire(lock_path.clone()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another daemon may already be running"),
            "acquiring an existing lock should fail"
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
            .and(query_param("status", "new|ready"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_path("lock_error");
        let storage_dir = unique_path("storage_error");

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
            .and(query_param("status", "new|ready"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let lock_path = unique_path("lock_max_files");
        let storage_dir = unique_path("storage_max_files");
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
                "nodes": ["NODE-1"],
                "transaction_id": null,
                "curation": {},
                "status": "new",
                "created_at": "2024-01-15T10:30:00Z"
            }]
        });
        let download_url = format!("{}/files/contract.pdf", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
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
        let lock_path = unique_path("lock_loop");
        let storage_dir = unique_path("storage_loop");
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
}
