//! `GET /api/admin/status` — what a reset would erase.
//!
//! Deliberately small: the public dashboard at `/` already lists the files, so
//! this only answers the question the danger zone raises — how much state is
//! there, and where does it live.

use axum::http::StatusCode;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, PaginatorTrait, QueryFilter, QuerySelect};
use serde_json::{json, Value};
use tracing::error;

use crate::app::config::StorageMethod;
use crate::entities::agreements;
use crate::entities::prelude::{Agreements, Challenges};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Counts of everything the reset would delete.
///
/// `session_expires_at` is echoed back so the page can show when the operator
/// will be signed out instead of finding out mid-reset.
///
/// # Errors
/// `500 DATABASE_ERROR` if any of the counts cannot be read.
pub async fn node_status(
    state: &DownloadServerState,
    session_expires_at: i64,
) -> Result<Value, ApiError> {
    let agreements_total = Agreements::find()
        .count(&state.db)
        .await
        .map_err(|err| database_error("count agreements", &err))?;

    let agreements_downloaded = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(&state.db)
        .await
        .map_err(|err| database_error("count downloaded agreements", &err))?;

    let challenges_total = Challenges::find()
        .count(&state.db)
        .await
        .map_err(|err| database_error("count challenges", &err))?;

    let stored_bytes = stored_bytes(state).await?;

    // The directory is meaningless for a GCS node, and the bucket name is
    // configuration the admin session has no business echoing back.
    let directory = match state.storage_backend.method {
        StorageMethod::Local => json!(state.storage_dir.display().to_string()),
        StorageMethod::Gcs => Value::Null,
    };

    Ok(json!({
        "node_id": state.node_id,
        "storage": {
            "method": state.storage_backend.method.to_string(),
            "directory": directory,
        },
        "agreements": {
            "total": agreements_total,
            "downloaded": agreements_downloaded,
            "stored_bytes": stored_bytes,
        },
        "challenges": {
            "total": challenges_total,
        },
        "session_expires_at": session_expires_at,
    }))
}

/// Sum of `original_size` over downloaded agreements — the node's own view of
/// how much it is storing, the same figure the capacity limit is checked
/// against.
async fn stored_bytes(state: &DownloadServerState) -> Result<u64, ApiError> {
    // `SUM(...)` always returns one row, but its value is NULL when nothing
    // matches, which arrives as `Some(None)`.
    let total: Option<i64> = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .select_only()
        .column_as(Expr::col(agreements::Column::OriginalSize).sum(), "total")
        .into_tuple::<Option<i64>>()
        .one(&state.db)
        .await
        .map_err(|err| database_error("sum stored bytes", &err))?
        .flatten();

    Ok(total.unwrap_or(0).try_into().unwrap_or(0))
}

fn database_error(what: &str, err: &sea_orm::DbErr) -> ApiError {
    error!("Database error trying to {what}: {err}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        error_codes::DATABASE_ERROR,
        format!("failed to {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::server::admin::AdminState;
    use crate::testutils::{setup_in_memory_db, tempdir, AgreementFixture};
    use sea_orm::ActiveModelTrait;

    async fn state_with(sizes: &[(i64, bool)]) -> (DownloadServerState, tempfile::TempDir) {
        let db = setup_in_memory_db().await;
        for (index, (size, downloaded)) in sizes.iter().enumerate() {
            AgreementFixture {
                original_size: *size,
                downloaded: *downloaded,
                ..AgreementFixture::new(format!("AGR-{index}"), format!("FILE-{index}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }

        let dir = tempdir();
        let state = DownloadServerState {
            db,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            node_id: "NODE-status".to_string(),
            admin: AdminState::disabled(),
        };
        (state, dir)
    }

    /// Any timestamp will do: the endpoint echoes it rather than deriving it.
    const SESSION_EXPIRY: i64 = 1_800_000_000;

    #[tokio::test]
    async fn status_counts_only_downloaded_agreements_as_stored() {
        let (state, _dir) = state_with(&[(100, true), (250, true), (999, false)]).await;

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["node_id"], "NODE-status");
        assert_eq!(value["session_expires_at"], SESSION_EXPIRY);
        assert_eq!(value["agreements"]["total"], 3);
        assert_eq!(value["agreements"]["downloaded"], 2);
        assert_eq!(value["agreements"]["stored_bytes"], 350);
        assert_eq!(value["challenges"]["total"], 0);
        assert_eq!(value["storage"]["method"], "local");
        assert_eq!(
            value["storage"]["directory"],
            state.storage_dir.display().to_string()
        );
    }

    /// An empty node answers zeros rather than erroring on `SUM(NULL)`.
    #[tokio::test]
    async fn status_of_an_empty_node_is_all_zeros() {
        let (state, _dir) = state_with(&[]).await;

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["agreements"]["total"], 0);
        assert_eq!(value["agreements"]["stored_bytes"], 0);
    }

    #[tokio::test]
    async fn gcs_status_reports_no_local_directory() {
        let (mut state, _dir) = state_with(&[(10, true)]).await;
        state.storage_backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: None,
        };

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["storage"]["method"], "gcs");
        assert_eq!(value["session_expires_at"], SESSION_EXPIRY);
        // Spelled as an equality rather than `is_null()`: `ExprTrait` is in
        // scope from the query above and its own `is_null` wins method
        // resolution on a `serde_json::Value`.
        assert_eq!(value["storage"]["directory"], Value::Null);
    }

    /// A database the node cannot read is a 500, not a status page full of
    /// zeros that would talk an operator into a reset. Each count is its own
    /// query, so a table missing on either side has to surface the same way.
    #[tokio::test]
    async fn status_surfaces_database_errors() {
        for db in [
            crate::testutils::setup_challenges_db().await,
            crate::testutils::setup_agreements_db().await,
        ] {
            let (mut state, _dir) = state_with(&[]).await;
            state.db = db;

            let err = node_status(&state, SESSION_EXPIRY).await.unwrap_err();

            assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(err.code, error_codes::DATABASE_ERROR);
        }
    }
}
