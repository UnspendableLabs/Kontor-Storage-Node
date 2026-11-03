use crate::app::config::StorageMethod;
use crate::app::daemon::StorageLimits;
use crate::app::tasks::field_from_hex;
use crate::app::tasks::getnewagreements::ReadyListing;
use crate::app::tasks::stake::{JoinBudget, JoinDecision, StakeTracker};
use crate::clients::http_helpers::status_and_code;
use crate::clients::kor::Kor;
use crate::clients::portal::{AgreementNode, JoinAgreementResponse};
use crate::clients::{GcsClient, PortalClient};
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use kontor_crypto::{api, FileDescriptor, FileLedger, FileMetadata as CryptoFileMetadata};
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
use std::time::Instant;
use tokio::fs;
use tracing::{debug, info, warn};

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
}

impl fmt::Display for PostProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(err) => write!(f, "prepare_file failed: {err}"),
            Self::Metadata(err) => write!(f, "metadata persistence failed: {err}"),
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

/// Join an agreement whose file has just been downloaded.
///
/// Download first, join second, deliberately: a join that succeeded for a file
/// the node then failed to fetch is a membership it cannot prove, and since the
/// staking upgrade a missed proof is slashed. The cost of this order is a
/// download wasted when the join is refused, which the join budget keeps rare.
///
/// Idempotent — the Portal answers `created: false` for a membership it already
/// has. Returns `None` for an unauthenticated client (legacy tests), which has
/// nothing to sign with.
async fn join_downloaded_agreement(
    portal_client: &PortalClient,
    agreement: &agreements::Model,
) -> Result<Option<JoinAgreementResponse>> {
    if portal_client.node_id().is_none() {
        warn!(
            "Skipping join for agreement {} - client not authenticated",
            agreement.agreement_id
        );
        return Ok(None);
    }

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
    Ok(Some(join_response))
}

/// Whether this node already holds a membership in `agreement`, by the local
/// row or by this cycle's listing.
///
/// Both are looked at because each lags in its own way: the local `nodes` is
/// refreshed by reconciliation, which only lists agreements the node is in,
/// and the listing is current but only covers agreements still ready. Old rows
/// store bare node-id strings rather than `{node_id, status}` objects, so both
/// shapes count.
fn holds_membership(
    agreement: &agreements::Model,
    listed: Option<&crate::clients::portal::Agreement>,
    node_id: Option<&str>,
) -> bool {
    let Some(node_id) = node_id else {
        return false;
    };
    let in_local = agreement.nodes.as_array().is_some_and(|nodes| {
        nodes.iter().any(|node| {
            node.as_str() == Some(node_id)
                || node.get("node_id").and_then(|id| id.as_str()) == Some(node_id)
        })
    });
    let in_listing = listed.is_some_and(|listed| {
        listed
            .nodes
            .iter()
            .any(|node: &AgreementNode| node.node_id == node_id)
    });
    in_local || in_listing
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
    if let Err(err) = process_downloaded_file(&downloaded.bytes, agreement, &txn).await {
        cleanup_guard.cleanup().await;
        txn.rollback().await.ok();
        return Err(anyhow!(err));
    }

    // Only `downloaded` is `Set` here: every other column stays `NotSet` so the
    // UPDATE leaves it alone. In particular `object_id` / `ledger_index` are
    // mirrored from the Portal by the agreement sync and must survive a
    // download — writing `Set(None)` here would null them out.
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

/// [`download_agreements_gated`] with no stake gating: what the node did
/// before staking, and still does against a Portal that reports no stake.
#[cfg(test)]
pub async fn download_agreements(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
    storage_backend: &StorageBackend,
) -> Result<()> {
    download_agreements_gated(
        portal_client,
        database,
        storage_limits,
        storage_backend,
        &ReadyListing::new(),
        &mut JoinBudget::unmetered(),
        None,
    )
    .await
}

/// Download agreement files that are not yet stored locally.
///
/// This function orchestrates the download workflow:
/// 1. Queries for pending agreements respecting storage limits
/// 2. For each agreement, checks storage limits, then whether the stake can
///    cover joining it (`budget`, from this cycle's `listing`)
/// 3. Downloads the file and joins the agreement on Portal
/// 4. Stores the file to the configured backend (local or GCS)
/// 5. Updates the database to mark the agreement as downloaded
///
/// A join the Portal refuses with a `422` (no stake, not enough unreserved
/// collateral, cleanup pending, withdrawal requested) costs the downloaded
/// file and pauses joins for a while — `tracker` remembers that across cycles
/// — but does not fail the cycle: the proofs that run after it are what keep
/// the existing stake from being slashed.
pub async fn download_agreements_gated(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
    storage_backend: &StorageBackend,
    listing: &ReadyListing,
    budget: &mut JoinBudget,
    tracker: Option<&StakeTracker>,
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

        // Collateral last among the checks: it is the one that sets something
        // aside, and an agreement skipped for size must not hold any.
        let listed = listing.get(&agreement.agreement_id);
        let member = holds_membership(&agreement, listed, portal_client.node_id());
        let collateral = match budget.decide(
            member,
            listed.map(|listed| listed.required_collateral.as_deref()),
        ) {
            JoinDecision::Join { collateral } => collateral,
            JoinDecision::Skip(reason) => {
                debug!(
                    "Not joining {} this cycle: {reason}",
                    agreement.agreement_id
                );
                continue;
            }
        };

        let downloaded = portal_client
            .download_file(&agreement.agreement_id, &agreement.file_id)
            .await
            .with_context(|| {
                format!("downloading file for agreement {}", agreement.agreement_id)
            })?;

        match join_downloaded_agreement(portal_client, &agreement).await {
            Ok(Some(joined)) => {
                record_reservation(tracker, &agreement, collateral, &joined);
            }
            Ok(None) => {}
            Err(err) => {
                let Some((422, code)) = status_and_code(&err) else {
                    return Err(err);
                };
                let code = code.unwrap_or_else(|| "UNPROCESSABLE".to_string());
                warn!(
                    "The Portal refused to let this node join {} ({code}); joins are paused \
                     for a while and the downloaded file is discarded: {err:#}",
                    agreement.agreement_id
                );
                discard_download(&downloaded.path).await;
                budget.refund(collateral);
                budget.close(&code);
                if let Some(tracker) = tracker {
                    tracker.pause_joins(&code, Instant::now());
                }
                continue;
            }
        }

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
    if let Some(summary) = budget.summary() {
        info!("Agreements not joined this cycle: {summary}");
    }

    Ok(())
}

/// Hold a fresh membership's collateral until its join executes.
fn record_reservation(
    tracker: Option<&StakeTracker>,
    agreement: &agreements::Model,
    collateral: Option<Kor>,
    joined: &JoinAgreementResponse,
) {
    if !joined.created {
        return;
    }
    if let (Some(tracker), Some(collateral), Some(nonce)) = (tracker, collateral, joined.nonce) {
        tracker.record_join(&agreement.agreement_id, collateral, nonce, Instant::now());
    }
}

/// Remove a file downloaded for a join that was refused.
async fn discard_download(path: &Path) {
    if let Err(err) = fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(
                "failed to remove {} after a refused join: {err}",
                path.display()
            );
        }
    }
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

/// Derive the crypto metadata of a freshly downloaded file and persist it on the
/// agreement row.
///
/// Takes no storage path: the aggregated ledger is a derived artifact rebuilt
/// from the database by [`rebuild_ledger`], so post-processing only touches the
/// database.
pub(crate) async fn process_downloaded_file(
    file_bytes: &[u8],
    agreement: &agreements::Model,
    transaction: &DatabaseTransaction,
) -> Result<(), PostProcessError> {
    let metadata = prepare_file_metadata(file_bytes, &agreement.filename)
        .map_err(PostProcessError::Prepare)?;

    persist_file_metadata(transaction, agreement, &metadata)
        .await
        .map_err(PostProcessError::Metadata)?;

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

    if let Err(err) = process_downloaded_file(bytes, agreement, &txn).await {
        txn.rollback().await.ok();
        let _ = fs::remove_file(local_path).await;
        return Err(anyhow!(err).context(format!(
            "post-processing downloaded file for agreement {}",
            agreement.agreement_id
        )));
    }

    // See `store_agreement_file`: `object_id` / `ledger_index` stay `NotSet` so
    // the Portal-mirrored values survive the download.
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

/// The `nonce` every Portal-published file descriptor carries.
///
/// The Portal calls `prepare_file(.., &[])` for both `create-agreement` and
/// `nft::mint` (see `create_agreement_data::build_expr_for`, which renders
/// `nonce: []`), so `file_id = file_<SHA256(domain || len || data || 0)>` and
/// the on-chain descriptor's `nonce` is empty. The node must prepare files with
/// the same nonce or it derives a different `file_id` than the one the
/// agreement is keyed on.
pub(crate) const PORTAL_FILE_NONCE: &[u8] = &[];

fn prepare_file_metadata(bytes: &[u8], filename: &str) -> Result<CryptoFileMetadata> {
    let (_prepared, metadata) = api::prepare_file(bytes, filename, PORTAL_FILE_NONCE)
        .context("preparing file with kontor_crypto")?;
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

/// A [`FileDescriptor`] pinned to the ledger slot the filestorage contract
/// assigned the file.
///
/// `FileLedger::add_file` appends at the next free local index, which is only
/// correct for the registry that owns the counter — the contract. A storage
/// node holds an arbitrary subset of the network's files, so it must place each
/// one at its absolute on-chain slot and go through `add_files`, the
/// reconstruction path that takes explicit indices.
struct IndexedFile {
    file_id: String,
    root: kontor_crypto::FieldElement,
    depth: usize,
    ledger_index: usize,
}

impl FileDescriptor for IndexedFile {
    fn file_id(&self) -> &str {
        &self.file_id
    }

    fn root(&self) -> kontor_crypto::FieldElement {
        self.root
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn ledger_index(&self) -> Option<usize> {
        Some(self.ledger_index)
    }
}

/// Mirror of kontor-crypto's own `MAX_LEDGER_INDEX_SPARSITY_GAP` (private to
/// that crate, 1024 as of 0.3.0).
///
/// `FileLedger::add_files` rebuilds the aggregated Merkle tree and refuses a set
/// of slots whose highest index implies more leaves than the file count plus
/// this gap. A storage node holds an arbitrary subset of the network's files at
/// their absolute on-chain slots, so it eventually trips this — see the README.
///
/// Duplicated here only so the node can *say* it is about to trip it
/// ([`crate::server::admin::status`]) instead of only discovering it when the
/// rebuild fails. If upstream changes the value, this over- or under-predicts
/// the wall; it never changes what the ledger actually accepts.
pub(crate) const MAX_LEDGER_INDEX_SPARSITY_GAP: usize = 1024;

/// Outcome of a [`rebuild_ledger`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LedgerStats {
    /// Files placed in the rebuilt ledger.
    pub placed: usize,
    /// Downloaded agreements skipped because the Portal has not published
    /// their contract-assigned `ledger_index` yet.
    pub awaiting_ledger_index: usize,
}

/// Rebuild `<storage_dir>/ledger.bin` from the database.
///
/// The ledger is a derived artifact: a `file_id -> (ledger_index, root
/// commitment)` view over the agreements this node has downloaded. Proving a
/// single challenge uses it purely to resolve the challenged file's slot, which
/// the contract resolves independently from its own registry — the two must
/// agree or the SNARK's public inputs differ and verification fails.
///
/// Rebuilding wholesale (rather than appending per download) is what makes the
/// node self-healing: an agreement is normally stored before its creating
/// transaction confirms, so its `ledger_index` arrives on a later reconcile
/// pass and simply gets picked up by the next rebuild.
///
/// Agreements without a known `ledger_index` are left out and counted in
/// [`LedgerStats::awaiting_ledger_index`]; they are unprovable until the Portal
/// reconciles them, but the node still stores and serves their files.
pub(crate) async fn rebuild_ledger(
    database: &DatabaseConnection,
    storage_root: &Path,
) -> Result<LedgerStats> {
    let downloaded = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .all(database)
        .await
        .context("loading downloaded agreements for ledger rebuild")?;

    let mut entries: Vec<IndexedFile> = Vec::with_capacity(downloaded.len());
    let mut stats = LedgerStats::default();

    for agreement in &downloaded {
        let (Some(root_hex), Some(padded_len)) = (agreement.root.as_ref(), agreement.padded_len)
        else {
            // Downloaded but not post-processed (or processed by an older
            // version); the next download pass fills these in.
            continue;
        };
        let Some(ledger_index) = agreement.ledger_index else {
            stats.awaiting_ledger_index += 1;
            continue;
        };

        entries.push(IndexedFile {
            file_id: agreement.file_id.clone(),
            root: field_from_hex(root_hex, "root").with_context(|| {
                format!("decoding root of agreement {}", agreement.agreement_id)
            })?,
            depth: depth_from_padded_len(padded_len).with_context(|| {
                format!(
                    "invalid padded_len for agreement {}",
                    agreement.agreement_id
                )
            })?,
            ledger_index: ledger_index
                .try_into()
                .with_context(|| format!("ledger_index of {} is negative", agreement.file_id))?,
        });
    }

    stats.placed = entries.len();

    let mut ledger = FileLedger::new();
    if !entries.is_empty() {
        ledger.add_files(entries.iter()).map_err(|err| {
            let highest = entries
                .iter()
                .map(|entry| entry.ledger_index)
                .max()
                .unwrap_or(0);
            anyhow!(err).context(format!(
                "placing {} file(s) at their contract ledger slots (highest slot {highest}); \
                 note that kontor-crypto rejects a ledger whose highest slot exceeds the file \
                 count by more than MAX_LEDGER_INDEX_SPARSITY_GAP ({MAX_LEDGER_INDEX_SPARSITY_GAP}), \
                 which a node holding a small subset of the network's files will eventually hit",
                entries.len()
            ))
        })?;
    }

    let ledger_path = ledger_path(storage_root);
    if let Some(parent) = ledger_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating ledger directory {}", parent.display()))?;
    }

    ledger
        .save(&ledger_path)
        .with_context(|| format!("saving ledger to {}", ledger_path.display()))?;

    if stats.awaiting_ledger_index > 0 {
        warn!(
            "Ledger rebuilt with {} file(s); {} downloaded agreement(s) have no ledger_index yet \
             and cannot be proven until the Portal reconciles them on chain",
            stats.placed, stats.awaiting_ledger_index
        );
    }

    Ok(stats)
}

/// Merkle depth implied by a padded leaf count, mirroring
/// `FileMetadata::depth()`.
fn depth_from_padded_len(padded_len: i64) -> Result<usize> {
    let padded_len: usize = padded_len
        .try_into()
        .context("padded_len does not fit into usize")?;
    if padded_len == 0 || !padded_len.is_power_of_two() {
        return Err(anyhow!(
            "padded_len {padded_len} is not a positive power of two"
        ));
    }
    Ok(padded_len.trailing_zeros() as usize)
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
        // Mirrored from the Portal by the agreement sync, before the download.
        fx.object_id = Some("obj_download".into());
        fx.ledger_index = Some(3);
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
        assert_eq!(
            downloaded.object_id.as_deref(),
            Some("obj_download"),
            "the download must not clear the Portal-mirrored object_id"
        );
        assert_eq!(
            downloaded.ledger_index,
            Some(3),
            "the download must not clear the contract-assigned ledger_index"
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

    /// A post-processing failure must roll the whole download back: no local
    /// file left behind and the agreement still un-downloaded.
    #[tokio::test]
    async fn post_processing_failure_rolls_back_the_download() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-post-process-error";
        let file_id = "FILE-post-process-error";
        let filename = "contract.pdf";
        let download_path = "/files/bad-post-process.pdf";
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
            // Empty body: `prepare_file` rejects empty data, which is how this
            // test drives `process_downloaded_file` into its failure branch.
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("post_process_error");
        stdfs::remove_dir_all(&storage_dir).ok();
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = filename.into();
        fx.mime_type = "application/pdf".into();
        fx.into_active_model().insert(&database).await.unwrap();

        let result = download_agreements(
            &PortalClient::new(mock_server.uri(), storage_dir.clone()),
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
        )
        .await;

        assert!(result.is_err(), "post-processing failure should bubble up");
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

    /// `object_id` / `ledger_index` are mirrored from the Portal by the
    /// agreement sync, well before the file is downloaded. Marking an agreement
    /// as downloaded must not touch them: nulling them out would drop the file
    /// out of the rebuilt ledger and make `build_file_metadata` fail, so the
    /// node could not prove anything until the next reconcile pass refilled
    /// them.
    #[tokio::test]
    async fn finalize_downloaded_bytes_preserves_the_portal_descriptor_fields() {
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("finalize_keeps_descriptor");
        stdfs::create_dir_all(&storage_dir).unwrap();

        let agreement_id = "AGREEMENT-keeps-descriptor";
        let file_id = "FILE-keeps-descriptor";
        let file_path = storage_dir.join(file_id);
        let bytes = b"descriptor preservation bytes";
        stdfs::write(&file_path, bytes).unwrap();

        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.filename = "descriptor.bin".into();
        fx.object_id = Some("obj_descriptor".into());
        fx.ledger_index = Some(7);
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
        assert_eq!(stored.object_id.as_deref(), Some("obj_descriptor"));
        assert_eq!(stored.ledger_index, Some(7));
    }

    #[test]
    fn post_process_error_display_is_readable() {
        let prepare_err = PostProcessError::Prepare(anyhow!("prep"));
        let metadata_err = PostProcessError::Metadata(anyhow!("meta"));

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
    }

    #[tokio::test]
    async fn persist_file_metadata_rejects_overflow_sizes() {
        let database = setup_agreements_db().await;
        let metadata = CryptoFileMetadata {
            root: Fq::one(),
            object_id: "obj_overflow".into(),
            file_id: "FILE-overflow".into(),
            nonce: PORTAL_FILE_NONCE.to_vec(),
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
            object_id: None,
            ledger_index: None,
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
            // Empty body: `prepare_file` rejects empty data, which is how this
            // test drives `process_downloaded_file` into its failure branch.
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
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
            // Empty body: `prepare_file` rejects empty data, which is how this
            // test drives `process_downloaded_file` into its failure branch.
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
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

    /// `rebuild_ledger` writes `ledger.bin` under the storage directory, which
    /// the download pipeline may have created several levels deep.
    #[tokio::test]
    async fn rebuild_ledger_creates_the_storage_directory_when_missing() {
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

        rebuild_ledger(&database, &storage_dir).await.unwrap();

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
            // Empty body: `prepare_file` rejects empty data, which is how this
            // test drives `process_downloaded_file` into its failure branch.
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
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
            err.to_string().contains("prepare_file failed"),
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
        // Cover the post-processing rollback branch. `prepare_file` rejects
        // empty data, so empty bytes are the cheapest way in.
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("finalize_postproc_err");
        stdfs::create_dir_all(&storage_dir).unwrap();

        let agreement_id = "AGREEMENT-finalize-pp-err";
        let file_id = "FILE-finalize-pp-err";
        let file_path = storage_dir.join(file_id);
        let bytes = b"";
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
            .expect_err("finalize should fail when the file cannot be prepared");

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
    async fn rebuild_ledger_errors_when_parent_dir_cannot_be_created() {
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("rebuild_ledger_bad_parent");
        let parent_dir = storage_dir.parent().unwrap().to_path_buf();
        stdfs::create_dir_all(&parent_dir).unwrap();
        // Create a file where the storage_dir should be, so
        // `create_dir_all(ledger.bin's parent)` fails.
        stdfs::write(&storage_dir, b"not a directory").unwrap();

        let result = rebuild_ledger(&database, &storage_dir).await;
        assert!(result.is_err(), "should fail to create ledger directory");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("creating ledger directory") || msg.contains("saving ledger"),
            "expected ledger error message, got: {msg}"
        );
    }

    /// The rebuilt ledger must place each file at the slot the filestorage
    /// contract assigned it, not at the node's local insertion order: the
    /// contract resolves the same index when verifying, and a mismatch changes
    /// the SNARK's public inputs.
    #[tokio::test]
    async fn rebuild_ledger_places_files_at_their_contract_slots() {
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("rebuild_ledger_slots");
        stdfs::create_dir_all(&storage_dir).unwrap();

        let (_prepared, metadata) =
            api::prepare_file(b"ledger slot fixture", "slot.bin", PORTAL_FILE_NONCE).unwrap();
        let root_hex = hex::encode(metadata.root.to_repr());

        // Stored second locally, but slot 5 on chain.
        let mut fixture = AgreementFixture::new("AGREEMENT-slot", &metadata.file_id);
        fixture.downloaded = true;
        fixture.root = Some(root_hex);
        fixture.padded_len = Some(metadata.padded_len as i64);
        fixture.object_id = Some(metadata.object_id.clone());
        fixture.ledger_index = Some(5);
        fixture.into_active_model().insert(&database).await.unwrap();

        let stats = rebuild_ledger(&database, &storage_dir).await.unwrap();
        assert_eq!(stats.placed, 1);
        assert_eq!(stats.awaiting_ledger_index, 0);

        let ledger = FileLedger::load(&storage_dir.join("ledger.bin")).unwrap();
        let (index, _rc) = ledger
            .lookup(&metadata.file_id)
            .expect("file should be in the rebuilt ledger");
        assert_eq!(index, 5, "file must sit at its contract-assigned slot");
    }

    /// A downloaded agreement whose creating transaction the Portal has not
    /// reconciled yet has no `ledger_index`. It must be left out of the ledger
    /// (proving it is impossible) without failing the rebuild for the others.
    #[tokio::test]
    async fn rebuild_ledger_skips_agreements_without_a_ledger_index() {
        let database = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("rebuild_ledger_pending");
        stdfs::create_dir_all(&storage_dir).unwrap();

        let (_prepared, metadata) =
            api::prepare_file(b"pending slot fixture", "pending.bin", PORTAL_FILE_NONCE).unwrap();

        let mut fixture = AgreementFixture::new("AGREEMENT-pending", &metadata.file_id);
        fixture.downloaded = true;
        fixture.root = Some(hex::encode(metadata.root.to_repr()));
        fixture.padded_len = Some(metadata.padded_len as i64);
        fixture.object_id = Some(metadata.object_id.clone());
        fixture.ledger_index = None;
        fixture.into_active_model().insert(&database).await.unwrap();

        let stats = rebuild_ledger(&database, &storage_dir).await.unwrap();
        assert_eq!(stats.placed, 0);
        assert_eq!(stats.awaiting_ledger_index, 1);

        let ledger = FileLedger::load(&storage_dir.join("ledger.bin")).unwrap();
        assert!(ledger.lookup(&metadata.file_id).is_none());
    }

    #[test]
    fn depth_from_padded_len_requires_a_power_of_two() {
        assert_eq!(depth_from_padded_len(64).unwrap(), 6);
        assert!(depth_from_padded_len(0).is_err());
        assert!(depth_from_padded_len(48).is_err());
        assert!(depth_from_padded_len(-8).is_err());
    }

    // ── Stake gating ────────────────────────────────────────────────────────

    use crate::app::tasks::stake::StakePolicy;
    use crate::clients::portal::{Agreement, RegistryEntry};

    /// Serve the download of `agreement_id` from the mock server.
    async fn mount_download(mock_server: &MockServer, agreement_id: &str) {
        let file_path = format!("/files/{agreement_id}");
        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": format!("{}{file_path}", mock_server.uri())
            })))
            .mount(mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path(file_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(mock_server)
            .await;
    }

    /// A pending agreement this node has not joined.
    async fn insert_unjoined(database: &DatabaseConnection, agreement_id: &str, file_id: &str) {
        let mut fx = AgreementFixture::new(agreement_id, file_id);
        fx.nodes = json!([]);
        fx.into_active_model().insert(database).await.unwrap();
    }

    fn listed(agreement_id: &str, collateral: Option<&str>, nodes: &[&str]) -> Agreement {
        serde_json::from_value(json!({
            "agreement_id": agreement_id,
            "user_id": "user_1",
            "file_id": format!("FILE-{agreement_id}"),
            "filename": "test.bin",
            "mime_type": "application/octet-stream",
            "original_size": 123,
            "nodes": nodes.iter().map(|n| json!({"node_id": n, "status": "pending"})).collect::<Vec<_>>(),
            "transaction_id": null,
            "status": "ready",
            "created_at": "2024-01-01T00:00:00Z",
            "required_collateral": collateral,
        }))
        .unwrap()
    }

    fn listing(agreements: Vec<Agreement>) -> ReadyListing {
        agreements
            .into_iter()
            .map(|a| (a.agreement_id.clone(), a))
            .collect()
    }

    /// A tracker that has read a bond with `available` unreserved KOR.
    fn tracker_with_available(available: &str) -> StakeTracker {
        let tracker = StakeTracker::new(StakePolicy::default());
        let entry = RegistryEntry {
            signer_id: 42,
            x_only_pubkey: "ab".into(),
            bls_pubkey: None,
            next_nonce: 0,
            kor_balance: Some("5".into()),
            user_id: None,
            stake: Some("100".into()),
            stake_reserved: None,
            stake_available: Some(available.into()),
            stake_withdrawal_height: None,
            bond_cleanup_pending: Some(false),
            reward_balance: None,
        };
        tracker.observe(Some(&entry), Instant::now());
        tracker
    }

    fn requests_to(requests: &[Request], needle: &str) -> usize {
        requests
            .iter()
            .filter(|r| r.url.path().contains(needle))
            .count()
    }

    /// The point of the gate: nothing is downloaded — let alone joined — that
    /// the stake cannot cover. A known collateral is checked exactly; an
    /// unknown one (the usual case: the Portal joins in the batch that creates
    /// the agreement) is taken at the estimate. What was set aside for each is
    /// held for the next cycle.
    #[tokio::test]
    async fn only_agreements_the_stake_covers_are_downloaded() {
        let mock_server = MockServer::start().await;
        for id in ["AGR-fits", "AGR-too-big", "AGR-unknown", "AGR-unlisted"] {
            mount_download(&mock_server, id).await;
            mount_join_agreement_mock(&mock_server, id).await;
        }

        let database = setup_agreements_db().await;
        for id in ["AGR-fits", "AGR-too-big", "AGR-unknown", "AGR-unlisted"] {
            insert_unjoined(&database, id, &format!("FILE-{id}")).await;
        }
        let storage_dir = unique_storage_dir("gate_covers");
        let client = create_authenticated_client(&mock_server, storage_dir).await;

        let tracker = tracker_with_available("50");
        let listing = listing(vec![
            listed("AGR-fits", Some("30"), &[]),
            listed("AGR-too-big", Some("50.000000000000000001"), &[]),
            listed("AGR-unknown", None, &[]),
        ]);
        let mut budget = tracker.join_budget(Instant::now());

        download_agreements_gated(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &listing,
            &mut budget,
            Some(&tracker),
        )
        .await
        .unwrap();

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests_to(&requests, "AGR-fits/join"), 1);
        assert_eq!(requests_to(&requests, "AGR-unknown/join"), 1);
        for skipped in ["AGR-too-big", "AGR-unlisted"] {
            assert_eq!(
                requests_to(&requests, skipped),
                0,
                "{skipped} must be neither downloaded nor joined"
            );
        }

        let fits = Agreements::find_by_id("AGR-fits")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(fits.downloaded);
        let status = tracker.status();
        let mut held: Vec<(String, String)> = status["pending_joins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|join| {
                (
                    join["agreement_id"].as_str().unwrap().to_string(),
                    join["collateral"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        held.sort();
        assert_eq!(
            held,
            vec![
                ("AGR-fits".to_string(), "30".to_string()),
                ("AGR-unknown".to_string(), "10".to_string()),
            ],
            "the exact collateral, and the default estimate for the unknown one"
        );
    }

    /// A membership already held is an obligation: its file is downloaded
    /// whatever the stake says, cleanup included.
    #[tokio::test]
    async fn an_existing_membership_is_downloaded_even_with_joins_closed() {
        let mock_server = MockServer::start().await;
        mount_download(&mock_server, "AGR-mine").await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-mine/join"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-test",
                "created": false
            })))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        insert_unjoined(&database, "AGR-mine", "FILE-AGR-mine").await;
        let client =
            create_authenticated_client(&mock_server, unique_storage_dir("gate_mine")).await;

        let tracker = tracker_with_available("0");
        let listing = listing(vec![listed("AGR-mine", Some("30"), &["NODE-test"])]);
        let mut budget = tracker.join_budget(Instant::now());

        download_agreements_gated(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &listing,
            &mut budget,
            Some(&tracker),
        )
        .await
        .unwrap();

        let mine = Agreements::find_by_id("AGR-mine")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(mine.downloaded);
        assert_eq!(
            tracker.status()["pending_joins"],
            json!([]),
            "an idempotent re-join reserves nothing new"
        );
    }

    /// A §5 refusal is survived: the cycle goes on, the file it downloaded is
    /// thrown away, nothing else is joined this cycle, and joins stay paused
    /// rather than being retried every 30 seconds.
    #[tokio::test]
    async fn a_join_refused_for_collateral_does_not_fail_the_cycle() {
        let mock_server = MockServer::start().await;
        mount_download(&mock_server, "AGR-a").await;
        mount_download(&mock_server, "AGR-b").await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-a/join"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "error": {
                    "code": "INSUFFICIENT_COLLATERAL",
                    "message": "insufficient unreserved collateral",
                    "status": 422
                }
            })))
            .mount(&mock_server)
            .await;
        mount_join_agreement_mock(&mock_server, "AGR-b").await;

        let database = setup_agreements_db().await;
        insert_unjoined(&database, "AGR-a", "FILE-AGR-a").await;
        insert_unjoined(&database, "AGR-b", "FILE-AGR-b").await;
        let storage_dir = unique_storage_dir("gate_refused");
        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;

        let tracker = tracker_with_available("50");
        let listing = listing(vec![
            listed("AGR-a", Some("10"), &[]),
            listed("AGR-b", Some("10"), &[]),
        ]);
        let mut budget = tracker.join_budget(Instant::now());

        download_agreements_gated(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &listing,
            &mut budget,
            Some(&tracker),
        )
        .await
        .expect("a refused join must not fail the cycle");

        for id in ["AGR-a", "AGR-b"] {
            let row = Agreements::find_by_id(id)
                .one(&database)
                .await
                .unwrap()
                .unwrap();
            assert!(!row.downloaded, "{id} must not be marked downloaded");
        }
        assert!(
            !storage_dir.join("FILE-AGR-a").exists(),
            "the file downloaded for the refused join is discarded"
        );
        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(
            requests_to(&requests, "AGR-b"),
            0,
            "nothing more this cycle"
        );
        assert_eq!(
            client.current_nonce(),
            Some(0),
            "the refused join's nonce was given back"
        );

        assert_eq!(tracker.status()["joins_paused"], "INSUFFICIENT_COLLATERAL");
        let mut next_cycle = tracker.join_budget(Instant::now());
        assert!(matches!(
            next_cycle.decide(false, Some(Some("1"))),
            JoinDecision::Skip(_)
        ));
    }

    /// Any other join failure keeps the old behaviour: the cycle fails, and
    /// the daemon's backoff takes it from there.
    #[tokio::test]
    async fn other_join_failures_still_fail_the_cycle() {
        let mock_server = MockServer::start().await;
        mount_download(&mock_server, "AGR-x").await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-x/join"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let database = setup_agreements_db().await;
        insert_unjoined(&database, "AGR-x", "FILE-AGR-x").await;
        let client =
            create_authenticated_client(&mock_server, unique_storage_dir("gate_500")).await;

        let tracker = tracker_with_available("50");
        let listing = listing(vec![listed("AGR-x", Some("10"), &[])]);
        let mut budget = tracker.join_budget(Instant::now());

        let err = download_agreements_gated(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &listing,
            &mut budget,
            Some(&tracker),
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("status 500"), "{err:#}");
        assert_eq!(tracker.status()["joins_paused"], serde_json::Value::Null);
    }

    /// An old Portal reports no stake: everything pending is downloaded and
    /// joined as before, listed or not.
    #[tokio::test]
    async fn an_old_portal_downloads_everything_as_before() {
        let mock_server = MockServer::start().await;
        mount_download(&mock_server, "AGR-old").await;
        mount_join_agreement_mock(&mock_server, "AGR-old").await;

        let database = setup_agreements_db().await;
        insert_unjoined(&database, "AGR-old", "FILE-AGR-old").await;
        let client =
            create_authenticated_client(&mock_server, unique_storage_dir("gate_old")).await;

        let tracker = StakeTracker::new(StakePolicy::default());
        let mut legacy = RegistryEntry {
            signer_id: 42,
            x_only_pubkey: "ab".into(),
            bls_pubkey: None,
            next_nonce: 0,
            kor_balance: Some("10".into()),
            user_id: None,
            stake: None,
            stake_reserved: None,
            stake_available: None,
            stake_withdrawal_height: None,
            bond_cleanup_pending: None,
            reward_balance: None,
        };
        legacy.kor_balance = Some("10".into());
        tracker.observe(Some(&legacy), Instant::now());
        let mut budget = tracker.join_budget(Instant::now());

        download_agreements_gated(
            &client,
            &database,
            StorageLimits::default(),
            &StorageBackend::local(),
            &ReadyListing::new(),
            &mut budget,
            Some(&tracker),
        )
        .await
        .unwrap();

        let old = Agreements::find_by_id("AGR-old")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(old.downloaded);
    }

    #[test]
    fn membership_is_read_from_both_row_shapes_and_the_listing() {
        let mut fx = AgreementFixture::new("AGR-1", "F");
        fx.nodes = json!(["NODE-test"]);
        let bare = fx.into_active_model();
        let model = |active: agreements::ActiveModel| agreements::Model {
            agreement_id: active.agreement_id.unwrap(),
            user_id: active.user_id.unwrap(),
            file_id: active.file_id.unwrap(),
            filename: active.filename.unwrap(),
            mime_type: active.mime_type.unwrap(),
            original_size: active.original_size.unwrap(),
            nodes: active.nodes.unwrap(),
            root: None,
            padded_len: None,
            object_id: None,
            ledger_index: None,
            downloaded: false,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: active.created_at.unwrap(),
        };
        let bare = model(bare);
        assert!(holds_membership(&bare, None, Some("NODE-test")));
        assert!(!holds_membership(&bare, None, Some("NODE-other")));
        assert!(!holds_membership(&bare, None, None));

        let mut fx = AgreementFixture::new("AGR-2", "F");
        fx.nodes = json!([{"node_id": "NODE-test", "status": "valid"}]);
        assert!(holds_membership(
            &model(fx.into_active_model()),
            None,
            Some("NODE-test")
        ));

        let mut fx = AgreementFixture::new("AGR-3", "F");
        fx.nodes = json!([]);
        let none = model(fx.into_active_model());
        let listed = listed("AGR-3", Some("1"), &["NODE-test"]);
        assert!(holds_membership(&none, Some(&listed), Some("NODE-test")));
        assert!(!holds_membership(&none, None, Some("NODE-test")));
    }
}
