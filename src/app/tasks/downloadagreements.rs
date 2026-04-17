use crate::app::config::StorageMethod;
use crate::app::daemon::StorageLimits;
use crate::clients::{GcsClient, PortalClient};
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use kontor_crypto::{api, FileLedger, FileMetadata as CryptoFileMetadata};
use sea_orm::sea_query::Expr;
#[cfg(test)]
use sea_orm::DbErr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, ExprTrait, PaginatorTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

#[cfg(test)]
use self::tests::should_fail_commit;

/// RAII guard for cleaning up resources on error during download processing.
///
/// This guard ensures that local files and GCS objects are cleaned up if an error
/// occurs during the download workflow. Call `defuse()` on success to prevent cleanup.
struct CleanupGuard<'a> {
    local_path: PathBuf,
    gcs_client: Option<&'a Arc<GcsClient>>,
    file_id: String,
    uploaded_to_gcs: bool,
    defused: bool,
}

impl<'a> CleanupGuard<'a> {
    fn new(local_path: PathBuf, gcs_client: Option<&'a Arc<GcsClient>>, file_id: String) -> Self {
        Self {
            local_path,
            gcs_client,
            file_id,
            uploaded_to_gcs: false,
            defused: false,
        }
    }

    /// Mark that the file has been uploaded to GCS.
    fn mark_gcs_uploaded(&mut self) {
        self.uploaded_to_gcs = true;
    }

    /// Prevent cleanup on drop (call this on success).
    fn defuse(mut self) {
        self.defused = true;
    }

    /// Perform async cleanup. This is called explicitly before drop for async operations.
    async fn cleanup(&mut self) {
        if self.defused {
            return;
        }

        // Clean up GCS object if uploaded
        if self.uploaded_to_gcs {
            if let Some(gcs) = self.gcs_client {
                if let Err(err) = gcs.delete_object(&self.file_id).await {
                    warn!(
                        "failed to delete {} from GCS during cleanup: {err}",
                        self.file_id
                    );
                }
            }
        }

        // Clean up local file
        if self.local_path.exists() {
            if let Err(err) = fs::remove_file(&self.local_path).await {
                warn!(
                    "failed to remove local file {} during cleanup: {err}",
                    self.local_path.display()
                );
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum PostProcessError {
    Prepare(anyhow::Error),
    Metadata(anyhow::Error),
    Ledger(anyhow::Error),
}

impl fmt::Display for PostProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(err) => write!(f, "prepare_file failed: {err}"),
            Self::Metadata(err) => write!(f, "metadata persistence failed: {err}"),
            Self::Ledger(err) => write!(f, "ledger update failed: {err}"),
        }
    }
}

impl std::error::Error for PostProcessError {}

#[derive(Clone, Debug)]
pub struct StorageBackend {
    pub method: StorageMethod,
    pub(crate) gcs_client: Option<Arc<GcsClient>>,
}

impl StorageBackend {
    /// Create a local storage backend (used in tests).
    #[cfg(test)]
    pub fn local() -> Self {
        Self {
            method: StorageMethod::Local,
            gcs_client: None,
        }
    }

    /// Access the configured GCS client when storage method is GCS.
    pub fn gcs_client(&self) -> Option<Arc<GcsClient>> {
        self.gcs_client.clone()
    }

    /// Build a storage backend, initializing the GCS client once when needed.
    ///
    /// When `STORAGE_METHOD=gcs`, `gcs_service_account_json` is either a path to a JSON key file,
    /// or inline JSON (same as Horizon Portal: value trimmed to start with `{`, with `[n]` as newline escapes).
    pub fn new(
        method: StorageMethod,
        gcs_bucket_name: Option<String>,
        gcs_service_account_json: Option<String>,
    ) -> Result<Self> {
        let gcs_client = match method {
            StorageMethod::Local => None,
            StorageMethod::Gcs => {
                let bucket = gcs_bucket_name.clone().ok_or_else(|| {
                    anyhow!("STORAGE_GCS_BUCKET_NAME is required when STORAGE_METHOD is gcs")
                })?;
                let raw = gcs_service_account_json.clone().ok_or_else(|| {
                    anyhow!(
                        "STORAGE_GCS_SERVICE_ACCOUNT_JSON is required when STORAGE_METHOD is gcs"
                    )
                })?;

                Some(Arc::new(
                    GcsClient::from_path_or_inline_json(bucket, &raw)
                        .context("initializing GCS client")?,
                ))
            }
        };

        Ok(Self { method, gcs_client })
    }
}

/// Result of checking storage limits for a single agreement.
enum StorageLimitCheck {
    /// Storage limits allow this download.
    Allowed,
    /// Max files limit reached.
    MaxFilesReached,
    /// Capacity would be exceeded.
    CapacityExceeded,
}

/// Check if storage limits allow downloading this agreement.
///
/// # Arguments
/// * `agreement` - The agreement to check
/// * `storage_limits` - The configured storage limits
/// * `used_bytes` - Current total bytes used by downloaded files
/// * `downloaded_files` - Current count of downloaded files
///
/// # Returns
/// `StorageLimitCheck` indicating whether the download is allowed
fn check_storage_limits(
    agreement: &agreements::Model,
    storage_limits: &StorageLimits,
    used_bytes: u64,
    downloaded_files: u64,
    original_size: u64,
) -> StorageLimitCheck {
    if let Some(max_files) = storage_limits.max_files {
        if downloaded_files >= max_files {
            info!(
                "Skipping download for {} - max stored files {} reached",
                agreement.agreement_id, max_files
            );
            return StorageLimitCheck::MaxFilesReached;
        }
    }

    if let Some(capacity) = storage_limits.capacity {
        match used_bytes.checked_add(original_size) {
            Some(next) if next <= capacity => {}
            _ => {
                info!(
                    "Skipping download for {} ({} bytes) - capacity {} bytes would be exceeded",
                    agreement.agreement_id, original_size, capacity
                );
                return StorageLimitCheck::CapacityExceeded;
            }
        }
    }

    StorageLimitCheck::Allowed
}

/// Download an agreement file and join it on the Portal.
///
/// # Arguments
/// * `portal_client` - The Portal client for API calls
/// * `agreement` - The agreement to download
///
/// # Returns
/// The downloaded file data on success
async fn download_and_join_agreement(
    portal_client: &PortalClient,
    agreement: &agreements::Model,
) -> Result<crate::clients::portal::DownloadedFile> {
    let downloaded = portal_client
        .download_file(&agreement.agreement_id, &agreement.file_id)
        .await
        .with_context(|| format!("downloading file for agreement {}", agreement.agreement_id))?;

    // Join the agreement on Portal after successful download.
    // This is idempotent - Portal returns created=false if already joined.
    // Skip if client is not authenticated (e.g., in legacy tests).
    if portal_client.node_id().is_some() {
        let join_response = portal_client
            .join_agreement(&agreement.agreement_id)
            .await
            .with_context(|| format!("joining agreement {}", agreement.agreement_id))?;

        if join_response.created {
            info!(
                "Joined agreement {} as node {}",
                agreement.agreement_id, join_response.node_id
            );
        } else {
            info!(
                "Already joined agreement {} (idempotent)",
                agreement.agreement_id
            );
        }
    } else {
        warn!(
            "Skipping join for agreement {} - client not authenticated",
            agreement.agreement_id
        );
    }

    Ok(downloaded)
}

/// Store an agreement file to the configured storage backend and update the database.
///
/// This function handles:
/// - Uploading to GCS if configured
/// - Processing the downloaded file (metadata extraction, ledger update)
/// - Marking the agreement as downloaded in the database
/// - Transaction management and cleanup on error
///
/// # Arguments
/// * `downloaded` - The downloaded file data
/// * `agreement` - The agreement being processed
/// * `database` - Database connection
/// * `gcs_client` - Optional GCS client if using GCS storage
/// * `storage_backend` - The configured storage backend
///
/// # Returns
/// `Ok(())` on success, error on failure (cleanup is handled internally)
async fn store_agreement_file(
    downloaded: &crate::clients::portal::DownloadedFile,
    agreement: &agreements::Model,
    database: &DatabaseConnection,
    gcs_client: Option<&Arc<GcsClient>>,
    storage_backend: &StorageBackend,
) -> Result<()> {
    let txn = database.begin().await?;

    // Create cleanup guard to handle resource cleanup on error
    let mut cleanup_guard = CleanupGuard::new(
        downloaded.path.clone(),
        gcs_client,
        agreement.file_id.clone(),
    );

    if let Some(gcs) = gcs_client {
        if let Err(err) = gcs
            .upload_bytes(
                &agreement.file_id,
                downloaded.bytes.as_ref(),
                Some(agreement.mime_type.as_str()),
            )
            .await
        {
            cleanup_guard.cleanup().await;
            txn.rollback().await.ok();
            return Err(
                anyhow!(err).context(format!("uploading {} to GCS bucket", agreement.file_id))
            );
        }
        info!(
            "Uploaded {} to GCS ({} bytes)",
            agreement.file_id, agreement.original_size
        );
        cleanup_guard.mark_gcs_uploaded();
    }

    // If post-processing fails, cleanup guard will handle resource cleanup
    if let Err(err) = process_downloaded_file(
        downloaded.path.as_path(),
        &downloaded.bytes,
        agreement,
        &txn,
    )
    .await
    {
        cleanup_guard.cleanup().await;
        txn.rollback().await.ok();
        return Err(anyhow!(err));
    }

    let model = agreements::ActiveModel {
        agreement_id: Set(agreement.agreement_id.clone()),
        downloaded: Set(true),
        ..Default::default()
    };
    model
        .update(&txn)
        .await
        .context("marking agreement as downloaded failed")?;

    #[cfg(test)]
    let commit_result = if should_fail_commit() {
        Err(DbErr::Custom("simulated commit failure".to_string()))
    } else {
        txn.commit().await
    };

    #[cfg(not(test))]
    let commit_result = txn.commit().await;

    if let Err(err) = commit_result {
        cleanup_guard.cleanup().await;
        return Err(err.into());
    }

    // Success - defuse the guard and handle final GCS cleanup
    cleanup_guard.defuse();

    if storage_backend.method == StorageMethod::Gcs && downloaded.path.exists() {
        if let Err(err) = fs::remove_file(&downloaded.path).await {
            warn!(
                "failed to remove local file {} after GCS upload: {err}",
                downloaded.path.display()
            );
        }
    }

    Ok(())
}

/// Download agreement files that are not yet stored locally.
///
/// This function orchestrates the download workflow:
/// 1. Queries for pending agreements respecting storage limits
/// 2. For each agreement, checks storage limits
/// 3. Downloads the file and joins the agreement on Portal
/// 4. Stores the file to the configured backend (local or GCS)
/// 5. Updates the database to mark the agreement as downloaded
pub async fn download_agreements(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
    storage_backend: &StorageBackend,
) -> Result<()> {
    let gcs_client = match storage_backend.method {
        StorageMethod::Local => None,
        StorageMethod::Gcs => Some(
            storage_backend
                .gcs_client
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("GCS storage backend is not initialized"))?,
        ),
    };

    let mut used_bytes = match storage_limits.capacity {
        Some(_) => current_used_capacity(database).await?,
        None => 0,
    };
    let mut downloaded_files = match storage_limits.max_files {
        Some(_) => current_downloaded_count(database).await?,
        None => 0,
    };

    let mut query = Agreements::find().filter(agreements::Column::Downloaded.eq(false));
    if let Some(max_file_size) = storage_limits.max_file_size {
        let max_file_size: i64 = max_file_size
            .try_into()
            .map_err(|_| anyhow!("max file size exceeds trackable range"))?;
        query = query.filter(agreements::Column::OriginalSize.lte(max_file_size));
    }

    let pending = query
        .all(database)
        .await
        .context("failed to load agreements to download")?;

    let mut downloaded_count = 0usize;

    for agreement in pending {
        let original_size: u64 = agreement
            .original_size
            .try_into()
            .context("original_size does not fit into u64")?;

        // Check storage limits before downloading
        match check_storage_limits(
            &agreement,
            &storage_limits,
            used_bytes,
            downloaded_files,
            original_size,
        ) {
            StorageLimitCheck::Allowed => {}
            StorageLimitCheck::MaxFilesReached | StorageLimitCheck::CapacityExceeded => continue,
        }

        // Download file and join agreement
        let downloaded = download_and_join_agreement(portal_client, &agreement).await?;

        // Store file to backend and update database
        store_agreement_file(
            &downloaded,
            &agreement,
            database,
            gcs_client.as_ref(),
            storage_backend,
        )
        .await?;

        used_bytes = used_bytes.saturating_add(original_size);
        downloaded_files = downloaded_files.saturating_add(1);
        downloaded_count += 1;
    }

    if downloaded_count > 0 {
        info!("Downloaded {} agreements", downloaded_count);
    }

    Ok(())
}

async fn current_used_capacity(database: &DatabaseConnection) -> Result<u64> {
    // Compute the sum at the database level rather than streaming every downloaded row
    // into memory. `SELECT SUM(original_size) ... ` always returns one row, but the
    // value is NULL when no rows match (empty result set), which surfaces here as
    // `Some(None)` from `into_tuple::<Option<i64>>().one(...)`. `.flatten()` collapses
    // that to a single `Option<i64>`, and `unwrap_or(0)` handles the empty-table case.
    let total: Option<i64> = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .select_only()
        .column_as(Expr::col(agreements::Column::OriginalSize).sum(), "total")
        .into_tuple::<Option<i64>>()
        .one(database)
        .await
        .context("failed to compute total used capacity")?
        .flatten();
    let total = total.unwrap_or(0);
    let total: u64 = total
        .try_into()
        .context("total used capacity overflowed u64")?;
    Ok(total)
}

async fn current_downloaded_count(database: &DatabaseConnection) -> Result<u64> {
    let count = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(database)
        .await?;
    Ok(count)
}

pub(crate) async fn process_downloaded_file(
    saved_path: &Path,
    file_bytes: &[u8],
    agreement: &agreements::Model,
    transaction: &DatabaseTransaction,
) -> Result<(), PostProcessError> {
    let metadata = prepare_file_metadata(file_bytes, &agreement.filename)
        .map_err(PostProcessError::Prepare)?;
    let storage_root = saved_path
        .parent()
        .and_then(|parent| {
            if parent.as_os_str().is_empty() {
                None
            } else {
                Some(parent)
            }
        })
        .ok_or_else(|| {
            anyhow!(
                "downloaded file path {} does not have a parent directory",
                saved_path.display()
            )
        })
        .map_err(PostProcessError::Prepare)?;
    // Persist metadata first within the transaction so DB writes roll back if ledger fails.
    persist_file_metadata(transaction, agreement, &metadata)
        .await
        .map_err(PostProcessError::Metadata)?;

    update_ledger(storage_root, &metadata)
        .await
        .map_err(PostProcessError::Ledger)?;

    Ok(())
}

/// Persist post-download metadata for an agreement, mark it as downloaded, and
/// commit in a single transaction.
///
/// On any error the transaction is rolled back, `local_path` is removed if it
/// exists, and the original error is returned wrapped with context. On success
/// the local file is preserved so the caller can decide what to do with it
/// (e.g. delete after a successful GCS upload, or keep for local storage).
///
/// The caller is responsible for any non-DB cleanup such as rolling back a
/// previously uploaded GCS object. This helper is also intended for
/// `store_agreement_file` once its `CleanupGuard`/GCS-rollback wiring can be
/// refactored to interleave with the helper cleanly.
pub(crate) async fn finalize_downloaded_bytes(
    database: &DatabaseConnection,
    agreement: &agreements::Model,
    local_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let txn = database.begin().await?;

    if let Err(err) = process_downloaded_file(local_path, bytes, agreement, &txn).await {
        txn.rollback().await.ok();
        let _ = fs::remove_file(local_path).await;
        return Err(anyhow!(err).context(format!(
            "post-processing downloaded file for agreement {}",
            agreement.agreement_id
        )));
    }

    let model = agreements::ActiveModel {
        agreement_id: Set(agreement.agreement_id.clone()),
        downloaded: Set(true),
        ..Default::default()
    };
    if let Err(err) = model.update(&txn).await {
        txn.rollback().await.ok();
        let _ = fs::remove_file(local_path).await;
        return Err(anyhow!(err).context("marking agreement as downloaded"));
    }

    if let Err(err) = txn.commit().await {
        let _ = fs::remove_file(local_path).await;
        return Err(err.into());
    }

    Ok(())
}

fn prepare_file_metadata(bytes: &[u8], filename: &str) -> Result<CryptoFileMetadata> {
    let (_prepared, metadata) =
        api::prepare_file(bytes, filename).context("preparing file with kontor_crypto")?;
    Ok(metadata)
}

async fn persist_file_metadata(
    database: &impl ConnectionTrait,
    agreement: &agreements::Model,
    metadata: &CryptoFileMetadata,
) -> Result<()> {
    let original_size: i64 = metadata
        .original_size
        .try_into()
        .context("file metadata original_size exceeds i64")?;
    let padded_len: i64 = metadata
        .padded_len
        .try_into()
        .context("file metadata padded_len exceeds i64")?;

    let root_hex = hex::encode(metadata.root.to_repr());

    let active = agreements::ActiveModel {
        agreement_id: Set(agreement.agreement_id.clone()),
        original_size: Set(original_size),
        root: Set(Some(root_hex)),
        padded_len: Set(Some(padded_len)),
        ..Default::default()
    };

    active
        .update(database)
        .await
        .context("persisting file metadata onto agreement")?;

    Ok(())
}

async fn update_ledger(storage_root: &Path, metadata: &CryptoFileMetadata) -> Result<()> {
    let ledger_path = ledger_path(storage_root);
    if let Some(parent) = ledger_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating ledger directory {}", parent.display()))?;
    }

    let mut ledger = if ledger_path.exists() {
        FileLedger::load(&ledger_path)
            .with_context(|| format!("loading ledger from {}", ledger_path.display()))?
    } else {
        FileLedger::new()
    };

    if !ledger.files.contains_key(&metadata.file_id) {
        ledger
            .add_file(metadata)
            .map_err(|err| anyhow!(err).context("adding file to ledger"))?;
    }

    ledger
        .save(&ledger_path)
        .with_context(|| format!("saving ledger to {}", ledger_path.display()))
}

fn ledger_path(storage_root: &Path) -> PathBuf {
    storage_root.join("ledger.bin")
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::crypto::BlsKeyPair;
    use crate::entities::prelude::Agreements;
    use crate::testutils::{
        setup_agreements_db, unique_storage_dir, AgreementFixture, TEST_PRIVATE_KEY,
    };
    use halo2curves::pasta::Fq;
    use sea_orm::{EntityTrait, PaginatorTrait};
    use serde_json::json;
    use std::fs as stdfs;
    use std::path::Path;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;
    use std::thread::ThreadId;
    use tokio::fs;
    use wiremock::matchers::{body_bytes, header, header_exists, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    async fn create_authenticated_client(
        mock_server: &MockServer,
        storage_dir: PathBuf,
    ) -> PortalClient {
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        PortalClient::with_auth(
            mock_server.uri(),
            storage_dir,
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        )
    }

    /// Helper to mount the join_agreement mock for a specific agreement.
    async fn mount_join_agreement_mock(mock_server: &MockServer, agreement_id: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/api/agreements/{agreement_id}/join")))
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "agreement_id": agreement_id,
                "node_id": "NODE-test",
                "bls_signature": "0xabcdef",
                "joined_at": "2025-01-01T00:00:00Z",
                "created": true
            })))
            .mount(mock_server)
            .await;
    }

    static FAIL_COMMIT_THREAD: OnceLock<Mutex<Option<ThreadId>>> = OnceLock::new();

    pub(crate) struct CommitFailGuard;

    fn fail_commit_slot() -> &'static Mutex<Option<ThreadId>> {
        FAIL_COMMIT_THREAD.get_or_init(|| Mutex::new(None))
    }

    pub(crate) fn simulate_commit_failure_once() -> CommitFailGuard {
        let tid = thread::current().id();
        let slot = fail_commit_slot();
        *slot.lock().expect("commit fail mutex poisoned") = Some(tid);
        CommitFailGuard
    }

    impl Drop for CommitFailGuard {
        fn drop(&mut self) {
            let slot = fail_commit_slot();
            let _ = slot.lock().ok().and_then(|mut guard| guard.take());
        }
    }

    pub(super) fn should_fail_commit() -> bool {
        let tid = thread::current().id();
        let slot = fail_commit_slot();
        let mut guard = slot.lock().expect("commit fail mutex poisoned");
        if guard.is_some_and(|t| t == tid) {
            guard.take();
            true
        } else {
            false
        }
    }

    #[tokio::test]
    async fn storage_backend_new_requires_bucket_for_gcs() {
        let err = StorageBackend::new(StorageMethod::Gcs, None, Some("/tmp/sa.json".to_string()))
            .unwrap_err();

        assert!(
            err.to_string().contains("STORAGE_GCS_BUCKET_NAME"),
            "expected bucket validation error, got {err}"
        );
    }

    #[tokio::test]
    async fn storage_backend_new_requires_service_account_for_gcs() {
        let err = StorageBackend::new(StorageMethod::Gcs, Some("bucket".into()), None).unwrap_err();

        assert!(
            err.to_string().contains("STORAGE_GCS_SERVICE_ACCOUNT_JSON"),
            "expected service account validation error, got {err}"
        );
    }

    #[tokio::test]
    async fn downloads_ready_agreements_and_marks_flag() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-download";
        let file_id = "FILE-1";
        let filename = "contract.pdf";
        let download_path = "/files/contract.pdf";
        let download_url = format!("{}{}", mock_server.uri(), download_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        mount_join_agreement_mock(&mock_server, agreement_id).await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("download");
        stdfs::remove_dir_all(&storage_dir).ok();
        let backend = StorageBackend::local();
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = filename.into();
        fx.mime_type = "application/pdf".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        download_agreements(&client, &database, StorageLimits::default(), &backend)
            .await
            .unwrap();

        let stored = fs::read_to_string(storage_dir.join(file_id)).await.unwrap();
        assert_eq!(stored, "file-body");

        let downloaded = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(downloaded.downloaded, "downloaded flag should be set");

        assert!(
            downloaded.root.is_some(),
            "metadata root should be persisted on the agreement"
        );
        assert_eq!(
            downloaded.original_size,
            "file-body".len() as i64,
            "original_size should reflect prepared file bytes"
        );
        assert!(
            downloaded.padded_len.is_some(),
            "padded_len should be stored on the agreement"
        );
        assert_eq!(downloaded.filename, filename);
        assert_eq!(downloaded.file_id, file_id);

        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger file should be created alongside downloads"
        );
    }

    #[tokio::test]
    async fn uploads_to_gcs_and_removes_local_file_after_success() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-upload";
        let file_id = "FILE-gcs-upload";
        let filename = "gcs.bin";
        let download_path = "/files/gcs.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-gcs";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .and(header("authorization", "Bearer token-gcs"))
            .and(header("content-type", "application/octet-stream"))
            .and(body_bytes("file-body"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("gcs_backend");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = filename.into();
        fx.into_active_model().insert(&database).await.unwrap();

        mount_join_agreement_mock(&mock_server, agreement_id).await;

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        download_agreements(&client, &database, StorageLimits::default(), &backend)
            .await
            .unwrap();

        assert!(
            !storage_dir.join(file_id).exists(),
            "local file should be removed after GCS upload"
        );
        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger should still be written when using the GCS backend"
        );

        let downloaded = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(downloaded.downloaded, "downloaded flag should be set");
        assert!(
            downloaded.root.is_some(),
            "metadata root should be persisted after GCS upload"
        );
    }

    #[tokio::test]
    async fn gcs_upload_error_rolls_back_and_cleans_local_file() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-fail";
        let file_id = "FILE-gcs-fail";
        let download_path = "/files/gcs-fail.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-gcs-fail";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("gcs_upload_error");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "gcs.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let err = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("uploading FILE-gcs-fail to GCS bucket"),
            "expected upload failure to be surfaced, got {err}"
        );
        assert!(
            !storage_dir.join(file_id).exists(),
            "local file should be removed after GCS upload failure"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain undownloaded after rollback"
        );
    }

    #[tokio::test]
    async fn gcs_upload_error_logs_cleanup_failure() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-cleanup-fail";
        let file_id = "FILE-gcs-cleanup-fail";
        let download_path = "/files/gcs-cleanup.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-gcs-cleanup";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("gcs_cleanup_fail");
        stdfs::remove_dir_all(&storage_dir).ok();
        let file_path = storage_dir.join(file_id);
        let file_path_for_mock = file_path.clone();

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(move |_req: &Request| {
                let _ = stdfs::remove_file(&file_path_for_mock);
                let _ = stdfs::create_dir_all(&file_path_for_mock);
                ResponseTemplate::new(500).set_body_string("boom")
            })
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "gcs.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let err = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("uploading FILE-gcs-cleanup-fail to GCS bucket"),
            "upload failure should surface"
        );
        assert!(
            file_path.is_dir(),
            "cleanup failure should leave directory behind for coverage"
        );
    }

    #[tokio::test]
    async fn rerun_is_idempotent_and_keeps_single_metadata_row() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-idempotent";
        let file_id = "FILE-idempotent";
        let filename = "contract.pdf";
        let download_path = "/files/contract-idempotent.pdf";
        let download_url = format!("{}{}", mock_server.uri(), download_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("idempotent");
        stdfs::remove_dir_all(&storage_dir).ok();
        let backend = StorageBackend::local();
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = filename.into();
        fx.mime_type = "application/pdf".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let client = PortalClient::new(mock_server.uri(), storage_dir.clone());

        download_agreements(&client, &database, StorageLimits::default(), &backend)
            .await
            .unwrap();

        // Simulate a retry after metadata is already present by resetting the downloaded flag.
        let mut stored: agreements::ActiveModel = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .into();
        stored.downloaded = Set(false);
        stored.update(&database).await.unwrap();

        download_agreements(&client, &database, StorageLimits::default(), &backend)
            .await
            .unwrap();

        let agreement_after_retry = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(agreement_after_retry.downloaded);
        assert!(
            agreement_after_retry.root.is_some(),
            "root should remain set after retry"
        );
        assert!(
            agreement_after_retry.padded_len.is_some(),
            "padded_len should remain set after retry"
        );
        assert_eq!(
            agreement_after_retry.original_size,
            "file-body".len() as i64,
            "original_size reflects prepared file bytes"
        );

        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger should remain persisted after retry"
        );
    }

    #[tokio::test]
    async fn skips_when_nothing_to_download() {
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("empty");

        download_agreements(
            &PortalClient::new("http://localhost:1", storage_dir),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        let count = Agreements::find().count(&database).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn skips_download_when_capacity_would_be_exceeded() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-capacity";
        let file_id = "FILE-capacity";
        let download_path = "/files/too-big";
        let download_url = format!("{}{}", mock_server.uri(), download_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("capacity_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut already_downloaded =
            AgreementFixture::new("AGREEMENT-downloaded", "FILE-downloaded");
        already_downloaded.filename = "downloaded.pdf".into();
        already_downloaded.mime_type = "application/pdf".into();
        already_downloaded.original_size = 900;
        already_downloaded.downloaded = true;
        already_downloaded.created_at =
            chrono::DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z").unwrap();
        already_downloaded
            .into_active_model()
            .insert(&database)
            .await
            .unwrap();

        let mut pending = AgreementFixture::new(agreement_id, file_id);
        pending.filename = "pending.pdf".into();
        pending.mime_type = "application/pdf".into();
        pending.original_size = 200;
        pending.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-03T00:00:00Z").unwrap();
        pending.into_active_model().insert(&database).await.unwrap();

        // Capacity is below the sum of downloaded (900) + pending (200).
        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: Some(1000),
                max_file_size: None,
                max_files: None,
            },
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        assert!(
            !storage_dir.join(file_id).exists(),
            "file should not be downloaded when over capacity"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(
            !stored.downloaded,
            "downloaded flag should remain false when skipping"
        );
    }

    #[tokio::test]
    async fn skips_downloads_over_max_file_size() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-too-large";
        let file_id = "FILE-too-large";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("max_file_size_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut pending = AgreementFixture::new(agreement_id, file_id);
        pending.filename = "pending.pdf".into();
        pending.mime_type = "application/pdf".into();
        pending.original_size = 2_000;
        pending.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-03T00:00:00Z").unwrap();
        pending.into_active_model().insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: None,
                max_file_size: Some(1_000),
                max_files: None,
            },
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        assert!(
            !storage_dir.join(file_id).exists(),
            "file should not be downloaded when above max file size"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(
            !stored.downloaded,
            "downloaded flag should remain false when skipping oversized file"
        );
    }

    #[tokio::test]
    async fn stops_downloading_when_capacity_reached_mid_batch() {
        let mock_server = MockServer::start().await;
        let agreements = vec![
            ("AGREEMENT-1", "FILE-1", "/files/one", "one"),
            ("AGREEMENT-2", "FILE-2", "/files/two", "two"),
        ];

        for (agreement_id, _, path_suffix, body) in &agreements {
            let download_url = format!("{}{}", mock_server.uri(), path_suffix);
            Mock::given(method("GET"))
                .and(path(format!("/api/agreements/{agreement_id}/download")))
                .and(query_param("no_redirect", "true"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "download_url": download_url
                })))
                .mount(&mock_server)
                .await;

            Mock::given(method("GET"))
                .and(path(*path_suffix))
                .respond_with(ResponseTemplate::new(200).set_body_string(*body))
                .mount(&mock_server)
                .await;
        }

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("capacity_mid_batch");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut first = AgreementFixture::new(agreements[0].0, agreements[0].1);
        first.filename = "one.txt".into();
        first.mime_type = "text/plain".into();
        first.original_size = 600;
        first.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-04T00:00:00Z").unwrap();
        first.into_active_model().insert(&database).await.unwrap();

        let mut second = AgreementFixture::new(agreements[1].0, agreements[1].1);
        second.filename = "two.txt".into();
        second.mime_type = "text/plain".into();
        second.original_size = 500;
        second.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-05T00:00:00Z").unwrap();
        second.into_active_model().insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: Some(1000),
                max_file_size: None,
                max_files: None,
            },
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        let downloaded_one = fs::read_to_string(storage_dir.join(agreements[0].1))
            .await
            .unwrap();
        assert_eq!(downloaded_one, "one");
        assert!(
            !storage_dir.join(agreements[1].1).exists(),
            "second file should not be downloaded when capacity is exceeded after first"
        );

        let records = Agreements::find().all(&database).await.unwrap();
        let first_record = records
            .iter()
            .find(|a| a.agreement_id == agreements[0].0)
            .unwrap();
        let second_record = records
            .iter()
            .find(|a| a.agreement_id == agreements[1].0)
            .unwrap();

        assert!(
            first_record.downloaded,
            "first agreement should be marked downloaded"
        );
        assert!(
            !second_record.downloaded,
            "second agreement should remain pending when capacity exceeded"
        );
    }

    #[tokio::test]
    async fn skips_downloads_when_max_files_reached() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-max-files";
        let file_id = "FILE-max-files";
        let download_path = "/files/max";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": format!("{}{}", mock_server.uri(), download_path)
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("max_files_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut already_downloaded =
            AgreementFixture::new("AGREEMENT-downloaded", "FILE-downloaded");
        already_downloaded.filename = "downloaded.pdf".into();
        already_downloaded.mime_type = "application/pdf".into();
        already_downloaded.original_size = 100;
        already_downloaded.downloaded = true;
        already_downloaded.created_at =
            chrono::DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z").unwrap();
        already_downloaded
            .into_active_model()
            .insert(&database)
            .await
            .unwrap();

        let mut pending = AgreementFixture::new(agreement_id, file_id);
        pending.filename = "pending.pdf".into();
        pending.mime_type = "application/pdf".into();
        pending.original_size = 200;
        pending.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-03T00:00:00Z").unwrap();
        pending.into_active_model().insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: None,
                max_file_size: None,
                max_files: Some(1),
            },
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        assert!(
            !storage_dir.join(file_id).exists(),
            "file should not be downloaded once the max files limit is reached"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(
            !stored.downloaded,
            "downloaded flag should remain false when skipping due to max files"
        );
    }

    #[tokio::test]
    async fn stops_downloading_when_max_files_reached_mid_batch() {
        let mock_server = MockServer::start().await;
        let agreements = vec![
            ("AGREEMENT-1", "FILE-1", "/files/one", "one"),
            ("AGREEMENT-2", "FILE-2", "/files/two", "two"),
        ];

        for (agreement_id, _, path_suffix, body) in &agreements {
            let download_url = format!("{}{}", mock_server.uri(), path_suffix);
            Mock::given(method("GET"))
                .and(path(format!("/api/agreements/{agreement_id}/download")))
                .and(query_param("no_redirect", "true"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "download_url": download_url
                })))
                .mount(&mock_server)
                .await;

            Mock::given(method("GET"))
                .and(path(*path_suffix))
                .respond_with(ResponseTemplate::new(200).set_body_string(*body))
                .mount(&mock_server)
                .await;
        }

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("max_files_mid_batch");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut first = AgreementFixture::new(agreements[0].0, agreements[0].1);
        first.filename = "one.txt".into();
        first.mime_type = "text/plain".into();
        first.original_size = 10;
        first.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-04T00:00:00Z").unwrap();
        first.into_active_model().insert(&database).await.unwrap();

        let mut second = AgreementFixture::new(agreements[1].0, agreements[1].1);
        second.filename = "two.txt".into();
        second.mime_type = "text/plain".into();
        second.original_size = 10;
        second.created_at = chrono::DateTime::parse_from_rfc3339("2024-01-05T00:00:00Z").unwrap();
        second.into_active_model().insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: None,
                max_file_size: None,
                max_files: Some(1),
            },
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        let downloaded_one = fs::read_to_string(storage_dir.join(agreements[0].1))
            .await
            .unwrap();
        assert_eq!(downloaded_one, "one");
        assert!(
            !storage_dir.join(agreements[1].1).exists(),
            "second file should not be downloaded once the max files limit is reached"
        );

        let records = Agreements::find().all(&database).await.unwrap();
        let first_record = records
            .iter()
            .find(|a| a.agreement_id == agreements[0].0)
            .unwrap();
        let second_record = records
            .iter()
            .find(|a| a.agreement_id == agreements[1].0)
            .unwrap();

        assert!(
            first_record.downloaded,
            "first agreement should be marked downloaded"
        );
        assert!(
            !second_record.downloaded,
            "second agreement should remain pending after hitting the max"
        );
    }

    #[tokio::test]
    async fn errors_when_ledger_cannot_be_written() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-ledger-error";
        let file_id = "FILE-ledger-error";
        let filename = "contract.pdf";
        let download_path = "/files/bad-ledger.pdf";
        let download_url = format!("{}{}", mock_server.uri(), download_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("ledger_error");
        stdfs::remove_dir_all(&storage_dir).ok();
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = filename.into();
        fx.mime_type = "application/pdf".into();
        fx.into_active_model().insert(&database).await.unwrap();

        // Create a directory where the ledger file should be written to force a failure.
        let ledger_dir = storage_dir.join("ledger.bin");
        stdfs::create_dir_all(&ledger_dir).unwrap();

        let result = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
        )
        .await;

        assert!(result.is_err(), "ledger write failure should bubble up");
        assert!(
            !storage_dir.join(file_id).exists(),
            "downloaded file should be removed when post-processing fails"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain unprepared when ledger fails"
        );
        assert!(
            stored.root.is_none(),
            "metadata should not be persisted when ledger fails"
        );
    }

    #[tokio::test]
    async fn process_downloaded_file_errors_when_path_missing_parent() {
        let database = setup_agreements_db().await;
        let txn = database.begin().await.unwrap();
        let agreement = agreements::Model {
            agreement_id: "AGREEMENT-no-parent".into(),
            user_id: "user_1".into(),
            file_id: "FILE-no-parent".into(),
            filename: "file.pdf".into(),
            mime_type: "application/pdf".into(),
            original_size: 10,
            nodes: json!(["NODE-1"]),
            root: None,
            padded_len: None,
            downloaded: false,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let result =
            process_downloaded_file(Path::new("orphaned_file"), b"file-body", &agreement, &txn)
                .await;

        assert!(
            matches!(result, Err(PostProcessError::Prepare(_))),
            "expected missing parent path to be reported as prepare error"
        );

        txn.rollback().await.unwrap();

        let agreement_rows = Agreements::find().count(&database).await.unwrap();
        assert_eq!(agreement_rows, 0, "no agreements should be persisted");
    }

    #[test]
    fn post_process_error_display_is_readable() {
        let prepare_err = PostProcessError::Prepare(anyhow!("prep"));
        let metadata_err = PostProcessError::Metadata(anyhow!("meta"));
        let ledger_err = PostProcessError::Ledger(anyhow!("ledger"));

        assert!(
            prepare_err.to_string().contains("prepare_file failed"),
            "prepare variant should mention prepare failure"
        );
        assert!(
            metadata_err
                .to_string()
                .contains("metadata persistence failed"),
            "metadata variant should mention persistence failure"
        );
        assert!(
            ledger_err.to_string().contains("ledger update failed"),
            "ledger variant should mention ledger failure"
        );
    }

    #[tokio::test]
    async fn persist_file_metadata_rejects_overflow_sizes() {
        let database = setup_agreements_db().await;
        let metadata = CryptoFileMetadata {
            root: Fq::one(),
            file_id: "FILE-overflow".into(),
            padded_len: usize::MAX,
            original_size: usize::MAX,
            filename: "huge.bin".into(),
        };

        let agreement = agreements::Model {
            agreement_id: "AGREEMENT-overflow".into(),
            user_id: "user_1".into(),
            file_id: "FILE-overflow".into(),
            filename: "huge.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 1,
            nodes: json!(["NODE-1"]),
            root: None,
            padded_len: None,
            downloaded: false,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let err = persist_file_metadata(&database, &agreement, &metadata)
            .await
            .expect_err("overflowing metadata should return an error");

        assert!(
            err.to_string().contains("exceeds i64"),
            "error should mention i64 overflow"
        );

        let agreement_rows = Agreements::find().count(&database).await.unwrap();
        assert_eq!(
            agreement_rows, 0,
            "overflowing metadata should not be stored"
        );
    }

    #[tokio::test]
    async fn storage_backend_new_initializes_gcs_client_with_valid_config() {
        // Write a valid service account file
        let storage_dir = unique_storage_dir("gcs_backend_new");
        stdfs::create_dir_all(&storage_dir).unwrap();
        let sa_path = storage_dir.join("sa.json");
        stdfs::write(
            &sa_path,
            serde_json::json!({
                "private_key": TEST_PRIVATE_KEY,
                "client_email": "svc@example.com",
                "token_uri": "https://oauth2.googleapis.com/token"
            })
            .to_string(),
        )
        .unwrap();

        let backend = StorageBackend::new(
            StorageMethod::Gcs,
            Some("my-bucket".into()),
            Some(sa_path.to_string_lossy().to_string()),
        )
        .expect("should initialize GCS backend");

        assert_eq!(backend.method, StorageMethod::Gcs);
        assert!(
            backend.gcs_client.is_some(),
            "gcs_client should be initialized"
        );
    }

    #[test]
    fn storage_backend_new_initializes_gcs_client_with_inline_json() {
        let inline = serde_json::json!({
            "private_key": TEST_PRIVATE_KEY.replace('\n', "[n]"),
            "client_email": "svc@example.com",
            "token_uri": "https://oauth2.googleapis.com/token"
        })
        .to_string();

        let backend =
            StorageBackend::new(StorageMethod::Gcs, Some("my-bucket".into()), Some(inline))
                .expect("inline GCS backend should initialize");

        assert_eq!(backend.method, StorageMethod::Gcs);
        assert!(backend.gcs_client.is_some());
    }

    #[tokio::test]
    async fn download_error_is_propagated_with_context() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-download-error";
        let file_id = "FILE-download-error";

        // Mock the download URL endpoint to return successfully
        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": format!("{}/files/error.bin", mock_server.uri())
            })))
            .mount(&mock_server)
            .await;

        // Mock the actual file download to fail
        Mock::given(method("GET"))
            .and(path("/files/error.bin"))
            .respond_with(ResponseTemplate::new(500).set_body_string("download failed"))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("download_error");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "error.bin".into();
        fx.original_size = 100;
        fx.into_active_model().insert(&database).await.unwrap();

        let err = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("downloading file for agreement AGREEMENT-download-error"),
            "error should contain context about the agreement, got: {err}"
        );
    }

    #[tokio::test]
    async fn post_processing_error_cleans_up_gcs_object() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-postprocess-fail";
        let file_id = "FILE-gcs-postprocess-fail";
        let download_path = "/files/postprocess-fail.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-postprocess-fail";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        // GCS upload succeeds
        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // GCS delete should be called when post-processing fails
        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("gcs_postprocess_fail");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "postprocess.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        // Create a directory where the ledger should be to force post-processing failure
        let ledger_dir = storage_dir.join("ledger.bin");
        stdfs::create_dir_all(&ledger_dir).unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let result = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await;

        assert!(result.is_err(), "post-processing failure should bubble up");
        assert!(
            !storage_dir.join(file_id).exists(),
            "local file should be cleaned up after post-processing failure"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain undownloaded after post-processing failure"
        );
    }

    #[tokio::test]
    async fn post_processing_error_logs_gcs_delete_failure() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-delete-fail";
        let file_id = "FILE-gcs-delete-fail";
        let download_path = "/files/delete-fail.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-delete-fail";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        // GCS upload succeeds
        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // GCS delete fails
        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(ResponseTemplate::new(500).set_body_string("delete failed"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("gcs_delete_fail");
        stdfs::remove_dir_all(&storage_dir).ok();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "delete-fail.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        // Create a directory where the ledger should be to force post-processing failure
        let ledger_dir = storage_dir.join("ledger.bin");
        stdfs::create_dir_all(&ledger_dir).unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        // This should still fail (post-processing error) but GCS delete failure is logged
        let result = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await;

        assert!(
            result.is_err(),
            "post-processing failure should still bubble up even when GCS delete fails"
        );
    }

    #[tokio::test]
    async fn ledger_directory_is_created_when_missing() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-ledger-dir";
        let file_id = "FILE-ledger-dir";
        let download_path = "/files/ledger-dir.pdf";
        let download_url = format!("{}{}", mock_server.uri(), download_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        // Use a deeply nested directory that doesn't exist
        let storage_dir = unique_storage_dir("ledger_dir_create")
            .join("nested")
            .join("deep");
        stdfs::remove_dir_all(&storage_dir).ok();
        // Don't pre-create the directory - let the code create it

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "ledger.pdf".into();
        fx.mime_type = "application/pdf".into();
        fx.into_active_model().insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
        )
        .await
        .unwrap();

        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger file should be created in the nested directory"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .expect("agreement should exist");
        assert!(
            stored.downloaded,
            "agreement should be marked as downloaded"
        );
    }

    #[tokio::test]
    async fn commit_error_triggers_cleanup_paths() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-commit-fail";
        let file_id = "FILE-commit-fail";
        let download_path = "/files/commit-fail.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-commit-fail";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("commit_fail_cleanup");
        stdfs::remove_dir_all(&storage_dir).ok();
        let file_path = storage_dir.join(file_id);
        let file_path_for_mock = file_path.clone();

        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(move |_req: &Request| {
                let _ = stdfs::remove_file(&file_path_for_mock);
                let _ = stdfs::create_dir_all(&file_path_for_mock);
                ResponseTemplate::new(500).set_body_string("delete failed")
            })
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "commit-fail.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let _guard = simulate_commit_failure_once();
        let err = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("simulated commit failure"),
            "commit error should be surfaced"
        );
        assert!(
            file_path.is_dir(),
            "cleanup removal should fail when file path becomes a directory"
        );
        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain undownloaded after commit failure"
        );
    }

    #[tokio::test]
    async fn post_processing_error_handles_cleanup_failures() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-post-cleanup";
        let file_id = "FILE-post-cleanup";
        let download_path = "/files/post-cleanup.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-post-cleanup";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("post_cleanup");
        stdfs::remove_dir_all(&storage_dir).ok();
        let ledger_dir = storage_dir.join("ledger.bin");
        stdfs::create_dir_all(&ledger_dir).unwrap();
        let file_path = storage_dir.join(file_id);
        let file_path_for_mock = file_path.clone();

        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(move |_req: &Request| {
                let _ = stdfs::remove_file(&file_path_for_mock);
                let _ = stdfs::create_dir_all(&file_path_for_mock);
                ResponseTemplate::new(500).set_body_string("delete boom")
            })
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "cleanup.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        let err = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("ledger update failed"),
            "post-processing failure should bubble up"
        );
        assert!(
            file_path.is_dir(),
            "cleanup failure should leave directory behind after delete failure"
        );
    }

    #[tokio::test]
    async fn removal_error_after_successful_gcs_upload_is_logged() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-gcs-remove-error";
        let file_id = "FILE-gcs-remove-error";
        let download_path = "/files/gcs-remove.bin";
        let download_url = format!("{}{}", mock_server.uri(), download_path);
        let bucket = "bucket-remove-error";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs"
            })))
            .mount(&mock_server)
            .await;

        let storage_dir = unique_storage_dir("gcs_remove_error");
        stdfs::remove_dir_all(&storage_dir).ok();
        let file_path = storage_dir.join(file_id);
        let file_path_for_mock = file_path.clone();

        Mock::given(method("POST"))
            .and(path(format!("/upload/storage/v1/b/{bucket}/o")))
            .and(query_param("uploadType", "media"))
            .and(query_param("name", file_id))
            .respond_with(move |_req: &Request| {
                let _ = stdfs::remove_file(&file_path_for_mock);
                let _ = stdfs::create_dir_all(&file_path_for_mock);
                ResponseTemplate::new(200)
            })
            .mount(&mock_server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "gcs-remove.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let gcs_client = GcsClient::with_test_endpoints(
            bucket,
            "svc@example.com",
            TEST_PRIVATE_KEY,
            format!("{}/token", mock_server.uri()),
            mock_server.uri(),
        );
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(gcs_client)),
        };

        download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &backend,
        )
        .await
        .unwrap();

        assert!(
            file_path.is_dir(),
            "removal failure should leave directory behind for logging branch"
        );
        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.downloaded,
            "agreement should still be marked downloaded"
        );
    }

    #[tokio::test]
    async fn storage_backend_local_does_not_initialize_gcs() {
        let backend = StorageBackend::new(StorageMethod::Local, None, None)
            .expect("local backend should succeed without GCS params");

        assert_eq!(backend.method, StorageMethod::Local);
        assert!(
            backend.gcs_client.is_none(),
            "gcs_client should be None for local backend"
        );
    }

    #[tokio::test]
    async fn finalize_downloaded_bytes_succeeds_for_normal_path() {
        // Cover the happy path of finalize_downloaded_bytes (no error branches)
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("finalize_happy");
        stdfs::create_dir_all(&storage_dir).unwrap();

        let agreement_id = "AGREEMENT-finalize-ok";
        let file_id = "FILE-finalize-ok";
        let file_path = storage_dir.join(file_id);
        let bytes = b"finalize happy path bytes";
        stdfs::write(&file_path, bytes).unwrap();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "finalize.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let agreement = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();

        finalize_downloaded_bytes(&database, &agreement, &file_path, bytes)
            .await
            .expect("finalize should succeed");

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.downloaded);
        assert!(stored.root.is_some());
        assert!(stored.padded_len.is_some());
    }

    #[tokio::test]
    async fn finalize_downloaded_bytes_handles_post_processing_error() {
        // Cover the post_processing error rollback branch (lines 547-552):
        // force prepare_file_metadata path failure by putting a directory at ledger.bin
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("finalize_postproc_err");
        stdfs::create_dir_all(&storage_dir).unwrap();
        // Pre-create the ledger.bin path as a directory so update_ledger fails.
        stdfs::create_dir_all(storage_dir.join("ledger.bin")).unwrap();

        let agreement_id = "AGREEMENT-finalize-pp-err";
        let file_id = "FILE-finalize-pp-err";
        let file_path = storage_dir.join(file_id);
        let bytes = b"finalize pp err bytes";
        stdfs::write(&file_path, bytes).unwrap();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "pp.bin".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let agreement = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();

        let err = finalize_downloaded_bytes(&database, &agreement, &file_path, bytes)
            .await
            .expect_err("finalize should fail on ledger update");

        assert!(
            err.to_string().contains("post-processing downloaded file"),
            "error should be wrapped with post-processing context: {err}"
        );
        assert!(
            !file_path.exists(),
            "local file should be cleaned up on post-processing error"
        );

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain undownloaded after rollback"
        );
    }

    #[tokio::test]
    async fn update_ledger_errors_when_parent_dir_cannot_be_created() {
        // Cover line 618 (creating ledger directory error) by passing a path
        // where parent creation fails. We use a regular file as the storage root.
        let storage_dir = unique_storage_dir("update_ledger_bad_parent");
        let parent_dir = storage_dir.parent().unwrap().to_path_buf();
        stdfs::create_dir_all(&parent_dir).unwrap();
        // Create a file where the storage_dir should be — fs::create_dir_all on
        // a path under a regular file should fail.
        stdfs::write(&storage_dir, b"not a directory").unwrap();

        let metadata = CryptoFileMetadata {
            root: Fq::one(),
            file_id: "FILE-bad-parent".into(),
            padded_len: 64,
            original_size: 32,
            filename: "bad_parent.bin".into(),
        };

        // storage_dir is now a file, so storage_dir.join("ledger.bin").parent()
        // is the file path — fs::create_dir_all will fail.
        let result = update_ledger(&storage_dir, &metadata).await;
        // Using a directory as a parent for ledger.bin fails — expect error.
        assert!(result.is_err(), "should fail to create ledger directory");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("creating ledger directory") || msg.contains("loading ledger"),
            "expected ledger error message, got: {msg}"
        );
    }
}
