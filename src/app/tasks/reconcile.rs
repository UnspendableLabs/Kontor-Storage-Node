use super::downloadagreements::StorageBackend;
use super::getnewagreements::agreement_to_active_model;
use super::{load_existing_ids, sync_new_items, ITEM_TYPE_AGREEMENTS, STATUS_FAILED};
use crate::app::config::StorageMethod;
use crate::clients::portal::Agreement;
use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{Context, Result};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

/// Reconcile local DB with Portal:
/// - inserts agreements that are remote but missing locally,
/// - updates `status` and `nodes` of existing agreements when they diverge,
/// - optionally re-downloads undownloaded files from GCS (startup only).
pub(crate) async fn reconcile_from_portal(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    node_id: &str,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    redownload_from_gcs: bool,
) -> Result<()> {
    let remote_agreements = portal_client
        .get_node_agreements(node_id)
        .await
        .context("fetching all node agreements for reconciliation")?;

    if remote_agreements.is_empty() {
        info!("Reconciliation: no agreements found on Portal for node {node_id}");
        return Ok(());
    }

    let requested_ids: Vec<String> = remote_agreements
        .iter()
        .map(|a| a.agreement_id.clone())
        .collect();

    let existing_ids = load_existing_ids::<Agreements, _>(
        database,
        agreements::Column::AgreementId,
        &requested_ids,
        |m| m.agreement_id,
    )
    .await?;

    let already_in_db = existing_ids.len();
    let total_remote = remote_agreements.len();

    let to_update: Vec<Agreement> = remote_agreements
        .iter()
        .filter(|a| existing_ids.contains(&a.agreement_id))
        .cloned()
        .collect();

    sync_new_items(
        remote_agreements,
        existing_ids,
        ITEM_TYPE_AGREEMENTS,
        |a| a.agreement_id.clone(),
        agreement_to_active_model,
        database,
    )
    .await
    .context("inserting reconciled agreements")?;

    let newly_inserted = total_remote - already_in_db;

    let updated = update_existing_agreement_metadata(&to_update, database)
        .await
        .context("updating existing agreement statuses")?;

    let mut redownloaded = 0usize;
    if redownload_from_gcs && storage_backend.method == StorageMethod::Gcs {
        if let Some(gcs_client) = &storage_backend.gcs_client {
            let undownloaded = Agreements::find()
                .filter(agreements::Column::Downloaded.eq(false))
                .all(database)
                .await
                .context("querying undownloaded agreements for reconciliation")?;

            for agreement in undownloaded {
                match redownload_one_from_gcs(&agreement, gcs_client, database, storage_dir).await {
                    Ok(()) => redownloaded += 1,
                    Err(err) => {
                        warn!(
                            "Reconciliation: failed to re-download {} from GCS: {err:#}",
                            agreement.agreement_id
                        );
                    }
                }
            }
        }
    }

    info!(
        "Reconciled {total_remote} agreements ({already_in_db} already in DB, \
         {newly_inserted} inserted, {updated} updated, {redownloaded} re-downloaded from GCS)"
    );

    Ok(())
}

/// Update `status` and `nodes` of agreements already present in DB whose
/// remote representation has changed. Only those two columns are touched.
async fn update_existing_agreement_metadata(
    remote_agreements: &[Agreement],
    database: &DatabaseConnection,
) -> Result<usize> {
    if remote_agreements.is_empty() {
        return Ok(0);
    }

    let ids: Vec<String> = remote_agreements
        .iter()
        .map(|a| a.agreement_id.clone())
        .collect();
    let local_models = Agreements::find()
        .filter(agreements::Column::AgreementId.is_in(ids))
        .all(database)
        .await
        .context("loading existing agreements for status reconciliation")?;

    let mut updated = 0usize;
    for local in local_models {
        let Some(remote) = remote_agreements
            .iter()
            .find(|a| a.agreement_id == local.agreement_id)
        else {
            continue;
        };

        let remote_nodes =
            serde_json::to_value(&remote.nodes).context("serializing remote agreement nodes")?;

        let status_changed = remote.status != local.status;
        let nodes_changed = remote_nodes != local.nodes;

        if !status_changed && !nodes_changed {
            continue;
        }

        if status_changed {
            if remote.status == STATUS_FAILED {
                warn!(
                    "agreement {} status: {} -> {}",
                    local.agreement_id, local.status, remote.status
                );
            } else {
                info!(
                    "agreement {} status: {} -> {}",
                    local.agreement_id, local.status, remote.status
                );
            }
        }

        let mut active = agreements::ActiveModel {
            agreement_id: Set(local.agreement_id.clone()),
            ..Default::default()
        };
        if status_changed {
            active.status = Set(remote.status.clone());
        }
        if nodes_changed {
            active.nodes = Set(remote_nodes);
        }

        // Mark the primary key as Unchanged so SeaORM issues an UPDATE on it
        // rather than treating the row as new.
        active.agreement_id = ActiveValue::Unchanged(local.agreement_id);

        Agreements::update(active)
            .exec(database)
            .await
            .context("updating agreement metadata")?;
        updated += 1;
    }

    Ok(updated)
}

async fn redownload_one_from_gcs(
    agreement: &agreements::Model,
    gcs_client: &Arc<crate::clients::GcsClient>,
    database: &DatabaseConnection,
    storage_dir: &Path,
) -> Result<()> {
    let bytes = gcs_client
        .download_to_bytes(&agreement.file_id)
        .await
        .with_context(|| {
            format!(
                "downloading {} from GCS for reconciliation",
                agreement.file_id
            )
        })?;

    fs::create_dir_all(storage_dir)
        .await
        .with_context(|| format!("creating storage directory {}", storage_dir.display()))?;

    let temp_path = storage_dir.join(&agreement.file_id);
    fs::write(&temp_path, &bytes)
        .await
        .with_context(|| format!("writing temp file {}", temp_path.display()))?;

    super::downloadagreements::finalize_downloaded_bytes(database, agreement, &temp_path, &bytes)
        .await?;

    if let Err(err) = fs::remove_file(&temp_path).await {
        warn!(
            "failed to remove temp file {} after reconciliation: {err}",
            temp_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::clients::portal::{Agreement, AgreementNode};
    use crate::clients::{GcsClient, PortalClient};
    use crate::testutils::{
        setup_agreements_db, unique_storage_dir, AgreementFixture, TEST_PRIVATE_KEY,
    };
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait};
    use serde_json::json;
    use std::fs as stdfs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_agreement(id: &str, status: &str) -> Agreement {
        Agreement {
            agreement_id: id.to_string(),
            user_id: "user_1".to_string(),
            file_id: format!("FILE-{id}"),
            filename: "contract.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            original_size: 1_024,
            nodes: vec![AgreementNode {
                node_id: "NODE-test".to_string(),
                status: "valid".to_string(),
            }],
            transaction_id: None,
            curation: json!({}),
            status: status.to_string(),
            created_at: "2024-01-15T10:30:00Z".to_string(),
            merkle_root: None,
            data_symbols: None,
            parity_symbols: None,
            padded_len: None,
            blob_size: None,
            file_hash: None,
        }
    }

    fn agreement_json(a: &Agreement) -> serde_json::Value {
        json!({
            "agreement_id": a.agreement_id,
            "user_id": a.user_id,
            "file_id": a.file_id,
            "filename": a.filename,
            "mime_type": a.mime_type,
            "original_size": a.original_size,
            "nodes": a.nodes,
            "transaction_id": a.transaction_id,
            "curation": a.curation,
            "status": a.status,
            "created_at": a.created_at,
        })
    }

    fn mock_portal_client(server_uri: &str, storage_dir: PathBuf) -> PortalClient {
        let keypair = Arc::new(crate::crypto::BlsKeyPair::generate().unwrap());
        PortalClient::with_auth(
            server_uri,
            storage_dir,
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        )
    }

    async fn mount_node_agreements(mock_server: &MockServer, agreements: &[Agreement]) {
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("nodes", "NODE-test"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": agreements.len(),
                "agreements": agreements.iter().map(agreement_json).collect::<Vec<_>>()
            })))
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn inserts_agreements_from_portal_when_db_is_empty() {
        let mock_server = MockServer::start().await;
        let agreements = vec![
            sample_agreement("AGR-1", "confirmed"),
            sample_agreement("AGR-2", "completed"),
        ];
        mount_node_agreements(&mock_server, &agreements).await;

        let db = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("reconcile_insert");
        stdfs::create_dir_all(&storage_dir).ok();

        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let stored = Agreements::find().all(&db).await.unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].agreement_id, "AGR-1");
        assert_eq!(stored[0].status, "confirmed");
        assert_eq!(stored[1].agreement_id, "AGR-2");
        assert_eq!(stored[1].status, "completed");
    }

    #[tokio::test]
    async fn does_not_duplicate_existing_agreements() {
        let mock_server = MockServer::start().await;
        let agreements = vec![
            sample_agreement("AGR-existing", "confirmed"),
            sample_agreement("AGR-new", "ready"),
        ];
        mount_node_agreements(&mock_server, &agreements).await;

        let db = setup_agreements_db().await;
        let mut seeded = AgreementFixture::new("AGR-existing", "FILE-AGR-existing");
        seeded.filename = "existing.pdf".into();
        seeded.mime_type = "application/pdf".into();
        seeded.original_size = 555;
        seeded.downloaded = true;
        seeded.status = "confirmed".into();
        seeded.created_at = DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap();
        seeded.into_active_model().insert(&db).await.unwrap();

        let storage_dir = unique_storage_dir("reconcile_dedup");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let stored = Agreements::find().all(&db).await.unwrap();
        assert_eq!(stored.len(), 2, "should have original + 1 new");

        let existing = stored
            .iter()
            .find(|m| m.agreement_id == "AGR-existing")
            .unwrap();
        assert!(
            existing.downloaded,
            "existing agreement should retain its downloaded flag"
        );
        assert_eq!(
            existing.original_size, 555,
            "existing data should not be overwritten"
        );
    }

    #[tokio::test]
    async fn redownloads_undownloaded_files_from_gcs() {
        let mock_server = MockServer::start().await;
        let agreements = vec![sample_agreement("AGR-gcs", "confirmed")];
        mount_node_agreements(&mock_server, &agreements).await;

        let bucket = "reconcile-bucket";

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-reconcile"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/storage/v1/b/{bucket}/o/FILE-AGR-gcs")))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer token-reconcile"))
            .respond_with(ResponseTemplate::new(200).set_body_string("file-body"))
            .mount(&mock_server)
            .await;

        let db = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("reconcile_gcs");
        stdfs::remove_dir_all(&storage_dir).ok();

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

        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq("AGR-gcs"))
            .one(&db)
            .await
            .unwrap()
            .expect("agreement should exist");

        assert!(
            stored.downloaded,
            "agreement should be marked downloaded after GCS re-download"
        );
        assert!(stored.root.is_some(), "metadata root should be computed");
        assert!(stored.padded_len.is_some(), "padded_len should be computed");
    }

    #[tokio::test]
    async fn noop_when_all_agreements_already_exist() {
        let mock_server = MockServer::start().await;
        let agreements = vec![sample_agreement("AGR-noop", "confirmed")];
        mount_node_agreements(&mock_server, &agreements).await;

        let db = setup_agreements_db().await;
        let mut seeded = AgreementFixture::new("AGR-noop", "FILE-AGR-noop");
        seeded.filename = "noop.pdf".into();
        seeded.mime_type = "application/pdf".into();
        seeded.original_size = 1024;
        seeded.root = Some("abc123".into());
        seeded.padded_len = Some(2048);
        seeded.downloaded = true;
        seeded.status = "confirmed".into();
        seeded.created_at = DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap();
        seeded.into_active_model().insert(&db).await.unwrap();

        let storage_dir = unique_storage_dir("reconcile_noop");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let count = Agreements::find().count(&db).await.unwrap();
        assert_eq!(count, 1, "no additional agreements should be inserted");

        let stored = Agreements::find().one(&db).await.unwrap().unwrap();
        assert!(stored.downloaded, "downloaded flag should not change");
        assert_eq!(stored.root.as_deref(), Some("abc123"));
    }

    #[tokio::test]
    async fn noop_when_portal_returns_empty() {
        let mock_server = MockServer::start().await;
        mount_node_agreements(&mock_server, &[]).await;

        let db = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("reconcile_empty");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let count = Agreements::find().count(&db).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn skips_gcs_redownload_for_local_storage() {
        let mock_server = MockServer::start().await;
        let agreements = vec![sample_agreement("AGR-local", "confirmed")];
        mount_node_agreements(&mock_server, &agreements).await;

        let db = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("reconcile_local_skip");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true)
            .await
            .unwrap();

        let stored = Agreements::find().one(&db).await.unwrap().unwrap();
        assert!(
            !stored.downloaded,
            "local-storage agreements should remain undownloaded for normal flow to handle"
        );
    }

    #[tokio::test]
    async fn gcs_redownload_failure_is_warned_not_fatal() {
        let mock_server = MockServer::start().await;
        let agreements = vec![sample_agreement("AGR-gcs-fail", "confirmed")];
        mount_node_agreements(&mock_server, &agreements).await;

        let bucket = "reconcile-fail-bucket";

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-fail"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/storage/v1/b/{bucket}/o/FILE-AGR-gcs-fail")))
            .and(query_param("alt", "media"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock_server)
            .await;

        let db = setup_agreements_db().await;
        let storage_dir = unique_storage_dir("reconcile_gcs_fail");
        stdfs::remove_dir_all(&storage_dir).ok();

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

        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let result =
            reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, true).await;

        assert!(
            result.is_ok(),
            "GCS re-download failure should not be fatal"
        );

        let stored = Agreements::find().one(&db).await.unwrap().unwrap();
        assert!(
            !stored.downloaded,
            "agreement should remain undownloaded after GCS failure"
        );
    }

    #[tokio::test]
    async fn updates_status_of_existing_agreement_when_portal_marks_failed() {
        let mock_server = MockServer::start().await;
        let agreements = vec![sample_agreement("AGR-fail", "failed")];
        mount_node_agreements(&mock_server, &agreements).await;

        let db = setup_agreements_db().await;

        let mut seeded = AgreementFixture::new("AGR-fail", "FILE-AGR-fail");
        seeded.status = "ready".into();
        seeded.downloaded = true;
        seeded.root = Some("seeded-root".into());
        seeded.padded_len = Some(4096);
        seeded.original_size = 2048;
        seeded.created_at = DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap();
        seeded.into_active_model().insert(&db).await.unwrap();

        let storage_dir = unique_storage_dir("reconcile_status_failed");
        stdfs::create_dir_all(&storage_dir).ok();

        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir, false)
            .await
            .unwrap();

        let stored = Agreements::find()
            .filter(agreements::Column::AgreementId.eq("AGR-fail"))
            .one(&db)
            .await
            .unwrap()
            .expect("agreement should still exist");
        assert_eq!(stored.status, "failed");
        assert!(
            stored.downloaded,
            "downloaded flag should be preserved on status update"
        );
        assert_eq!(
            stored.root.as_deref(),
            Some("seeded-root"),
            "root must be preserved on status reconcile"
        );
        assert_eq!(
            stored.padded_len,
            Some(4096),
            "padded_len must be preserved on status reconcile"
        );
        assert_eq!(
            stored.original_size, 2048,
            "original_size must be preserved on status reconcile"
        );
        assert_eq!(
            stored.created_at,
            DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap(),
            "created_at must be preserved on status reconcile"
        );
        assert_eq!(
            stored.nodes,
            json!([{"node_id": "NODE-test", "status": "valid"}]),
            "nodes should reflect the latest portal payload"
        );
    }
}
