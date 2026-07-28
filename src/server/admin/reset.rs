//! `POST /api/admin/reset-database` — wipe this node's chain-derived state.
//!
//! Both of the node's tables are chain-derived: `agreements` mirrors what the
//! Portal published on Kontor, and `challenges` mirrors what the filestorage
//! contract asked this node to prove. When the signet is reset, every row
//! refers to a chain that no longer exists and the daemon keeps trying to
//! prove agreements nobody can verify.
//!
//! Nothing outside the database is touched unless `delete_files` is set: the
//! BLS key, the daemon lock and every other file in the storage directory
//! survive, because this endpoint deletes objects it can name from the rows it
//! just read — never the directory.

use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use futures_util::stream::{self, StreamExt};
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, TransactionTrait};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::app::config::StorageMethod;
use crate::clients::http_helpers::HttpStatusError;
use crate::entities::agreements;
use crate::entities::prelude::{Agreements, Challenges};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Literal an operator must type to arm the reset.
pub const CONFIRMATION_PHRASE: &str = "RESET";

/// Concurrent object deletions against GCS. Enough to keep a bucket-wide wipe
/// from taking minutes, low enough that the request is not a burst of hundreds
/// of parallel HTTP calls.
const GCS_DELETE_CONCURRENCY: usize = 8;

/// Request body for `POST /api/admin/reset-database`.
#[derive(Debug, Default, Deserialize)]
pub struct ResetDatabaseRequest {
    /// Must equal [`CONFIRMATION_PHRASE`].
    #[serde(default)]
    pub confirm: String,
    /// Also delete the stored file blobs of the agreements being wiped.
    ///
    /// Off by default. The rows go away either way; without this the blobs stay
    /// behind as orphans that no agreement references and nothing will ever
    /// clean up, which is the safer default but wastes the space a storage node
    /// is selling.
    #[serde(default)]
    pub delete_files: bool,
}

/// Outcome of the blob deletion pass.
#[derive(Debug, Default)]
struct BlobReport {
    /// Blobs the wiped rows claimed to have stored.
    requested: usize,
    deleted: usize,
    /// Already gone: a local file that no longer exists, or a bucket object
    /// GCS answers `404` for. Nothing for the operator to act on.
    missing: usize,
    failed: usize,
    /// File ids that could not be turned into a safe object name.
    skipped: usize,
}

impl BlobReport {
    fn to_json(&self) -> Value {
        json!({
            "requested": self.requested,
            "deleted": self.deleted,
            "missing": self.missing,
            "failed": self.failed,
            "skipped": self.skipped,
        })
    }
}

/// Rejects anything that is not a plain object name.
///
/// File ids come from the Portal, and the local backend turns them straight
/// into `storage_dir/<file_id>`. On the download path a traversing id merely
/// fails to open; here it would delete an arbitrary file, so it is refused
/// rather than sanitized.
fn is_safe_object_name(file_id: &str) -> bool {
    !file_id.is_empty() && !file_id.contains(['/', '\\', '\0']) && file_id != "." && file_id != ".."
}

/// Deletes every row of both tables, children first.
///
/// `challenges` carries an `agreement_id`; no foreign key is declared today,
/// but a single correct order costs nothing and survives one being added.
async fn delete_all_rows(
    txn: &DatabaseTransaction,
) -> Result<Vec<(&'static str, u64)>, sea_orm::DbErr> {
    let challenges = Challenges::delete_many().exec(txn).await?;
    let agreements = Agreements::delete_many().exec(txn).await?;

    Ok(vec![
        ("challenges", challenges.rows_affected),
        ("agreements", agreements.rows_affected),
    ])
}

/// Wipes the node's database, and optionally the file blobs it referenced.
///
/// # Errors
/// - `400 CONFIRMATION_REQUIRED` when `confirm` is not [`CONFIRMATION_PHRASE`].
/// - `500 DATABASE_ERROR` when the transaction cannot be opened or committed.
///
/// Blob deletion never fails the request: the rows are already gone by then, so
/// reporting an orphan is more useful than pretending the reset did not happen.
pub async fn reset_database(
    request: &ResetDatabaseRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    if request.confirm != CONFIRMATION_PHRASE {
        return Err(ApiError::bad_request(
            error_codes::CONFIRMATION_REQUIRED,
            format!(
                "Destructive action: send {{\"confirm\": \"{CONFIRMATION_PHRASE}\"}} to proceed"
            ),
        ));
    }

    warn!(
        delete_files = request.delete_files,
        "Admin requested a full database reset"
    );

    // Read the blob names before the rows that carry them are deleted.
    let stored_file_ids = if request.delete_files {
        stored_file_ids(state).await?
    } else {
        Vec::new()
    };

    let txn = state.db.begin().await.map_err(|err| {
        error!("Database error opening reset transaction: {err}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::DATABASE_ERROR,
            "failed to open database transaction",
        )
    })?;

    let deleted = match delete_all_rows(&txn).await {
        Ok(deleted) => deleted,
        Err(err) => {
            error!("Database reset failed, rolling back: {err}");
            txn.rollback().await.ok();
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error_codes::DATABASE_ERROR,
                format!("failed to reset database: {err}"),
            ));
        }
    };

    txn.commit().await.map_err(|err| {
        error!("Failed to commit database reset: {err}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::DATABASE_ERROR,
            "failed to commit database transaction",
        )
    })?;

    let total: u64 = deleted.iter().map(|(_, count)| *count).sum();
    info!(total, "Database reset committed");

    let blobs = if request.delete_files {
        Some(delete_blobs(state, stored_file_ids).await)
    } else {
        None
    };

    let deleted_map: serde_json::Map<String, Value> = deleted
        .into_iter()
        .map(|(table, count)| (table.to_string(), json!(count)))
        .collect();

    Ok(json!({
        "deleted": deleted_map,
        "total_rows_deleted": total,
        "storage_method": state.storage_backend.method.to_string(),
        "files": blobs.as_ref().map(BlobReport::to_json),
    }))
}

/// File ids of the agreements whose blobs this node actually stored.
async fn stored_file_ids(state: &DownloadServerState) -> Result<Vec<String>, ApiError> {
    let agreements = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .all(&state.db)
        .await
        .map_err(|err| {
            error!("Database error listing stored files: {err}");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error_codes::DATABASE_ERROR,
                "failed to list stored files",
            )
        })?;

    Ok(agreements
        .into_iter()
        .map(|agreement| agreement.file_id)
        .collect())
}

/// Deletes the blobs behind `file_ids` from whichever backend holds them.
async fn delete_blobs(state: &DownloadServerState, file_ids: Vec<String>) -> BlobReport {
    let mut report = BlobReport {
        requested: file_ids.len(),
        ..BlobReport::default()
    };

    let safe: Vec<String> = file_ids
        .into_iter()
        .filter(|file_id| {
            let safe = is_safe_object_name(file_id);
            if !safe {
                warn!(%file_id, "Refusing to delete a file id that is not a plain object name");
            }
            safe
        })
        .collect();
    report.skipped = report.requested - safe.len();

    match state.storage_backend.method {
        StorageMethod::Local => delete_local_blobs(&state.storage_dir, &safe, &mut report).await,
        StorageMethod::Gcs => delete_gcs_blobs(state, safe, &mut report).await,
    }

    info!(
        requested = report.requested,
        deleted = report.deleted,
        missing = report.missing,
        failed = report.failed,
        skipped = report.skipped,
        "Stored file deletion finished"
    );
    report
}

async fn delete_local_blobs(storage_dir: &Path, file_ids: &[String], report: &mut BlobReport) {
    for file_id in file_ids {
        let path: PathBuf = storage_dir.join(file_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => report.deleted += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => report.missing += 1,
            Err(err) => {
                warn!("Failed to delete {}: {err}", path.display());
                report.failed += 1;
            }
        }
    }
}

async fn delete_gcs_blobs(
    state: &DownloadServerState,
    file_ids: Vec<String>,
    report: &mut BlobReport,
) {
    let Some(client) = state.storage_backend.gcs_client() else {
        // Configured for GCS but holding no client: the objects are
        // unreachable, so say so rather than report them as deleted.
        warn!("GCS backend has no client; leaving stored objects in place");
        report.failed += file_ids.len();
        return;
    };

    let outcomes = stream::iter(file_ids)
        .map(|file_id| {
            let client = client.clone();
            async move {
                client
                    .delete_object(&file_id)
                    .await
                    .map_err(|err| (file_id, err))
            }
        })
        .buffer_unordered(GCS_DELETE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    for outcome in outcomes {
        match outcome {
            Ok(()) => report.deleted += 1,
            // An object the bucket no longer holds is the same non-event as a
            // local file that is already gone, so it is counted the same way.
            Err((_, err)) if is_not_found(&err) => report.missing += 1,
            Err((file_id, err)) => {
                warn!(%file_id, "Failed to delete stored object: {err}");
                report.failed += 1;
            }
        }
    }
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HttpStatusError>()
        .is_some_and(|status| status.status == reqwest::StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::clients::GcsClient;
    use crate::entities::challenges;
    use crate::server::admin::AdminState;
    use crate::testutils::{
        setup_agreements_db, setup_challenges_db, setup_in_memory_db, tempdir, AgreementFixture,
        TEST_PRIVATE_KEY,
    };
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, PaginatorTrait};
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn confirmed(delete_files: bool) -> ResetDatabaseRequest {
        ResetDatabaseRequest {
            confirm: CONFIRMATION_PHRASE.to_string(),
            delete_files,
        }
    }

    async fn insert_agreement(db: &DatabaseConnection, file_id: &str, downloaded: bool) {
        AgreementFixture {
            downloaded,
            ..AgreementFixture::new(format!("AGR-{file_id}"), file_id)
        }
        .into_active_model()
        .insert(db)
        .await
        .unwrap();
    }

    async fn insert_challenge(db: &DatabaseConnection, challenge_id: &str) {
        let now = chrono::Utc::now().fixed_offset();
        challenges::ActiveModel {
            challenge_id: Set(challenge_id.to_string()),
            agreement_id: Set("AGR-FILE-1".to_string()),
            block_height: Set(100),
            challenge_count: Set(1),
            seed: Set("00".to_string()),
            prover_id: Set("42".to_string()),
            deadline_height: Set(200),
            status: Set("pending".to_string()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// State over a seeded database and a storage directory holding one blob
    /// per downloaded agreement, plus a file the reset must never touch.
    async fn seeded_state() -> (DownloadServerState, tempfile::TempDir) {
        let db = setup_in_memory_db().await;
        insert_agreement(&db, "FILE-1", true).await;
        insert_agreement(&db, "FILE-2", true).await;
        insert_agreement(&db, "FILE-3", false).await;
        insert_challenge(&db, "CHAL-1").await;
        insert_challenge(&db, "CHAL-2").await;

        let dir = tempdir();
        std::fs::write(dir.path().join("FILE-1"), b"one").unwrap();
        std::fs::write(dir.path().join("FILE-2"), b"two").unwrap();
        std::fs::write(dir.path().join("bls_key.enc"), b"identity").unwrap();

        let state = DownloadServerState {
            db,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            node_id: "NODE-TEST".to_string(),
            admin: AdminState::disabled(),
        };
        (state, dir)
    }

    async fn count_rows(state: &DownloadServerState) -> (u64, u64) {
        (
            Agreements::find().count(&state.db).await.unwrap(),
            Challenges::find().count(&state.db).await.unwrap(),
        )
    }

    #[tokio::test]
    async fn reset_requires_the_confirmation_phrase() {
        let (state, _dir) = seeded_state().await;

        for bad in ["", "reset", "yes", "RESET "] {
            let err = reset_database(
                &ResetDatabaseRequest {
                    confirm: bad.to_string(),
                    delete_files: true,
                },
                &state,
            )
            .await
            .unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert_eq!(err.code, error_codes::CONFIRMATION_REQUIRED);
        }

        assert_eq!(count_rows(&state).await, (3, 2), "nothing was touched");
        assert!(state.storage_dir.join("FILE-1").exists());
    }

    #[tokio::test]
    async fn reset_empties_both_tables_and_reports_counts() {
        let (state, _dir) = seeded_state().await;

        let value = reset_database(&confirmed(false), &state).await.unwrap();

        assert_eq!(count_rows(&state).await, (0, 0));
        assert_eq!(value["deleted"]["agreements"], 3);
        assert_eq!(value["deleted"]["challenges"], 2);
        assert_eq!(value["total_rows_deleted"], 5);
        assert_eq!(value["storage_method"], "local");
    }

    /// The default keeps the blobs: deleting stored data is irreversible, so it
    /// only happens when the operator ticks the box.
    #[tokio::test]
    async fn reset_leaves_stored_files_alone_by_default() {
        let (state, _dir) = seeded_state().await;

        let value = reset_database(&confirmed(false), &state).await.unwrap();

        assert!(value["files"].is_null());
        assert!(state.storage_dir.join("FILE-1").exists());
        assert!(state.storage_dir.join("FILE-2").exists());
    }

    #[tokio::test]
    async fn reset_deletes_stored_blobs_when_asked() {
        let (state, _dir) = seeded_state().await;

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["requested"], 2, "only downloaded agreements");
        assert_eq!(value["files"]["deleted"], 2);
        assert_eq!(value["files"]["missing"], 0);
        assert_eq!(value["files"]["failed"], 0);
        assert!(!state.storage_dir.join("FILE-1").exists());
        assert!(!state.storage_dir.join("FILE-2").exists());
    }

    /// The storage directory is also where the node's identity lives. Deleting
    /// blobs must be a list of names read from the database, never a sweep.
    #[tokio::test]
    async fn reset_never_touches_files_it_did_not_store() {
        let (state, _dir) = seeded_state().await;

        reset_database(&confirmed(true), &state).await.unwrap();

        assert!(
            state.storage_dir.join("bls_key.enc").exists(),
            "the BLS key must survive a database reset"
        );
    }

    /// A file id that would escape the storage directory is skipped, not
    /// joined onto the path and deleted.
    #[tokio::test]
    async fn reset_skips_file_ids_that_are_not_plain_names() {
        let (state, dir) = seeded_state().await;
        insert_agreement(&state.db, "../escape", true).await;
        std::fs::write(dir.path().parent().unwrap().join("escape"), b"outside").unwrap();

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["skipped"], 1);
        assert_eq!(value["files"]["deleted"], 2);
        assert!(dir.path().parent().unwrap().join("escape").exists());
        std::fs::remove_file(dir.path().parent().unwrap().join("escape")).ok();
    }

    /// A row marked downloaded whose blob is already gone is a missing file,
    /// not a failure — the operator has nothing to fix.
    #[tokio::test]
    async fn reset_counts_already_absent_blobs_as_missing() {
        let (state, _dir) = seeded_state().await;
        std::fs::remove_file(state.storage_dir.join("FILE-2")).unwrap();

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["deleted"], 1);
        assert_eq!(value["files"]["missing"], 1);
    }

    /// Resetting an already-empty node is a no-op, not an error — the operator
    /// may well click twice.
    #[tokio::test]
    async fn reset_is_idempotent() {
        let (state, _dir) = seeded_state().await;

        reset_database(&confirmed(true), &state).await.unwrap();
        let second = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(second["total_rows_deleted"], 0);
        assert_eq!(second["files"]["requested"], 0);
    }

    #[test]
    fn object_name_guard_accepts_ids_and_rejects_paths() {
        assert!(is_safe_object_name("FILE-123"));
        assert!(is_safe_object_name("obj_9f86d081884c7d65"));
        assert!(!is_safe_object_name(""));
        assert!(!is_safe_object_name("."));
        assert!(!is_safe_object_name(".."));
        assert!(!is_safe_object_name("../bls_key.enc"));
        assert!(!is_safe_object_name("nested/file"));
        assert!(!is_safe_object_name("windows\\file"));
    }

    /// A GCS-configured backend with no client cannot reach the objects; they
    /// are reported as failures rather than silently counted as deleted.
    #[tokio::test]
    async fn gcs_backend_without_a_client_reports_failures() {
        let (mut state, _dir) = seeded_state().await;
        state.storage_backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: None,
        };

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["storage_method"], "gcs");
        assert_eq!(value["files"]["failed"], 2);
        assert_eq!(value["files"]["deleted"], 0);
        // The local copies are irrelevant to a GCS node, and untouched.
        assert!(state.storage_dir.join("FILE-1").exists());
    }

    /// A blob the node cannot remove is reported, not swallowed: the row is
    /// gone, so the operator is the only one who can still deal with the file.
    ///
    /// Mirrors the read-only-directory pattern used in `database::sqlite`
    /// tests; it relies on the test process not being root, as those do.
    #[cfg(unix)]
    #[tokio::test]
    async fn reset_reports_blobs_it_cannot_delete() {
        use std::os::unix::fs::PermissionsExt;

        let (state, _dir) = seeded_state().await;
        let dir = &state.storage_dir;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        // Restore before the assertions so a failure still cleans up.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(value["files"]["failed"], 2);
        assert_eq!(value["files"]["deleted"], 0);
        assert_eq!(
            value["total_rows_deleted"], 5,
            "the wipe itself still succeeded"
        );
        assert!(dir.join("FILE-1").exists());
    }

    const BUCKET: &str = "bucket-reset";

    /// A seeded node whose GCS client talks to `mock` instead of Google.
    async fn gcs_state(mock: &MockServer) -> (DownloadServerState, tempfile::TempDir) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token-gcs"
            })))
            .mount(mock)
            .await;

        let (mut state, dir) = seeded_state().await;
        state.storage_backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(GcsClient::with_test_endpoints(
                BUCKET,
                "svc@example.com",
                TEST_PRIVATE_KEY,
                format!("{}/token", mock.uri()),
                mock.uri(),
            ))),
        };
        (state, dir)
    }

    async fn mount_delete(mock: &MockServer, file_id: &str, response: ResponseTemplate) {
        Mock::given(method("DELETE"))
            .and(path(format!("/storage/v1/b/{BUCKET}/o/{file_id}")))
            .respond_with(response)
            .expect(1)
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn gcs_reset_deletes_the_objects_it_stored() {
        let mock = MockServer::start().await;
        mount_delete(&mock, "FILE-1", ResponseTemplate::new(204)).await;
        mount_delete(&mock, "FILE-2", ResponseTemplate::new(204)).await;
        let (state, _dir) = gcs_state(&mock).await;

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["requested"], 2);
        assert_eq!(value["files"]["deleted"], 2);
        assert_eq!(value["files"]["failed"], 0);
        assert_eq!(count_rows(&state).await, (0, 0));
    }

    /// An object the bucket has already lost is a non-event, exactly as it is
    /// for a local file that is no longer there.
    #[tokio::test]
    async fn gcs_reset_counts_a_404_as_missing() {
        let mock = MockServer::start().await;
        mount_delete(&mock, "FILE-1", ResponseTemplate::new(204)).await;
        mount_delete(
            &mock,
            "FILE-2",
            ResponseTemplate::new(404).set_body_string("not found"),
        )
        .await;
        let (state, _dir) = gcs_state(&mock).await;

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["deleted"], 1);
        assert_eq!(value["files"]["missing"], 1);
        assert_eq!(value["files"]["failed"], 0);
    }

    /// A bucket that refuses the delete leaves an orphan. The rows are already
    /// gone, so the reset still succeeds and the count carries the news.
    #[tokio::test]
    async fn gcs_reset_reports_failed_deletions_without_failing() {
        let mock = MockServer::start().await;
        mount_delete(&mock, "FILE-1", ResponseTemplate::new(204)).await;
        mount_delete(
            &mock,
            "FILE-2",
            ResponseTemplate::new(500).set_body_string("boom"),
        )
        .await;
        let (state, _dir) = gcs_state(&mock).await;

        let value = reset_database(&confirmed(true), &state).await.unwrap();

        assert_eq!(value["files"]["deleted"], 1);
        assert_eq!(value["files"]["failed"], 1);
        assert_eq!(value["total_rows_deleted"], 5);
    }

    /// The blob names are read before the wipe, so a database that cannot
    /// answer that read fails the request before anything is deleted.
    #[tokio::test]
    async fn reset_fails_before_wiping_when_the_file_list_cannot_be_read() {
        let dir = tempdir();
        let state = DownloadServerState {
            // No `agreements` table at all.
            db: setup_challenges_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            node_id: "NODE-TEST".to_string(),
            admin: AdminState::disabled(),
        };
        insert_challenge(&state.db, "CHAL-1").await;

        let err = reset_database(&confirmed(true), &state).await.unwrap_err();

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, error_codes::DATABASE_ERROR);
        assert_eq!(
            Challenges::find().count(&state.db).await.unwrap(),
            1,
            "the wipe must not have started"
        );
    }

    /// Half a reset is worse than none: a delete that fails mid-transaction
    /// rolls back and reports, rather than leaving one table emptied.
    #[tokio::test]
    async fn a_failed_delete_rolls_the_whole_reset_back() {
        let dir = tempdir();
        let state = DownloadServerState {
            // No `challenges` table, so the first delete of the transaction
            // fails and the `agreements` delete never runs.
            db: setup_agreements_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            node_id: "NODE-TEST".to_string(),
            admin: AdminState::disabled(),
        };
        insert_agreement(&state.db, "FILE-1", true).await;

        let err = reset_database(&confirmed(false), &state).await.unwrap_err();

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, error_codes::DATABASE_ERROR);
        assert_eq!(
            Agreements::find().count(&state.db).await.unwrap(),
            1,
            "the agreements must survive a rolled-back reset"
        );
    }
}
