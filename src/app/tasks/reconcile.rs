use super::downloadagreements::StorageBackend;
use super::getnewagreements::agreement_to_active_model;
use super::{sync_new_items, ITEM_TYPE_AGREEMENTS};
use crate::app::config::StorageMethod;
use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

pub(crate) async fn reconcile_from_portal(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    node_id: &str,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
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

    let existing_ids: HashSet<String> = Agreements::find()
        .filter(agreements::Column::AgreementId.is_in(requested_ids.clone()))
        .all(database)
        .await?
        .into_iter()
        .map(|m| m.agreement_id)
        .collect();

    let already_in_db = existing_ids.len();
    let total_remote = remote_agreements.len();

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

    let mut redownloaded = 0usize;
    if storage_backend.method == StorageMethod::Gcs {
        if let Some(gcs_client) = &storage_backend.gcs_client {
            let undownloaded = Agreements::find()
                .filter(agreements::Column::Downloaded.eq(false))
                .all(database)
                .await
                .context("querying undownloaded agreements for reconciliation")?;

            for agreement in undownloaded {
                match redownload_from_gcs(&agreement, gcs_client, database, storage_dir).await {
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
         {newly_inserted} inserted, {redownloaded} re-downloaded from GCS)"
    );

    Ok(())
}

async fn redownload_from_gcs(
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

    let txn = database.begin().await?;

    if let Err(err) = super::downloadagreements::process_downloaded_file(
        temp_path.as_path(),
        &bytes,
        agreement,
        &txn,
    )
    .await
    {
        txn.rollback().await.ok();
        let _ = fs::remove_file(&temp_path).await;
        return Err(anyhow!(err).context(format!(
            "processing re-downloaded file for agreement {}",
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
        let _ = fs::remove_file(&temp_path).await;
        return Err(anyhow!(err).context("marking reconciled agreement as downloaded"));
    }

    if let Err(err) = txn.commit().await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(err.into());
    }

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
    use super::*;
    use crate::clients::portal::Agreement;
    use crate::clients::{GcsClient, PortalClient};
    use crate::testutils::{setup_agreements_db, unique_storage_dir};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
    use serde_json::json;
    use std::fs as stdfs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnumunEUnoZIs5\nDhEXTNTyJPFxsZMxgRhLs7m6aiVu7GrDgoWFMoLy/B6Ccl2c9ml/RzuK5uKbJKM9\ntcwA90gpp536aLWB0BbQuWtfceU3BmQWFtQRXqCww/o462cujXhcMe5bVPvE9b/5\nyV+oWmKa42tw4x5//Cj8LGAw8aQwlC+OQ19iA+vmKx7xjs0uBFtQHnjGxekT71vp\nLgv53SVi5yUscz9Scy/VuBkNfOCaEz5zV+EUplYuvRMVEJ0Pvk1wOYjby4Gz+OVI\nrp1+1RFBEeTu2zo06E4o23pfz5DbZaBMZ8qK3WkNx6eQOuYK6Zrq+zM5/Uoq6fqQ\nAIuYpCNxAgMBAAECggEAB1pTx9IpNEfcFpc4RpY2q5rU/s/zDPOE1iS92p82nuM8\nVu/M3Kb3OKG20K8kzXG79DlyMcenXXfAtD7Y/53XiwPvGAApHNS7e1D1lQyQKNZd\n4t4DU/ObBcTBnmcrcc3/3cLOmTBjjSHc1Z1vVRkJQ5L+rcc3GhM61Ls5SEv/j6WN\nFw/fnYGtxUUXBz1gVvok0o89qTgW0Pt7SWrUkbAhrsGeTFpzNbicgRsBUXJJdRcl\nvK5rwKSPUhiIVhpQ78usSLdO30X3Bfvf/GQpR56/UgDqkn20ZMpJhKrAxSbmLSu9\nhgkIbLAlABxdYUbGFp5aTALAJ8EyZn8MU9RRuL9DcQKBgQDp263xaTlx8BgbKnq1\nwY+SxuDlGz/LoGYjF6v6FNHM1hQ5v2FpxaxF5EDUm3fdh+Z9yegL/g8GQdQQnelG\nA43VACvGAESw1ilsBDl6TZ+LZY4MTQrWSGUqQxt3APu3lHDAXkipHu2X3cv/3VrO\nDGs2WYWPiMxg1ZkIBojyZQ0SnQKBgQC3m910nvJIJ+WLXeXiG2qN147/5GU7Yma2\n0pEhQ4XVN/f7joGzUXLeB0BXNNbdKuRqEQ1r2VkH3qqY6HAL6/fK01qEhWBLv1hu\ndkEhEruK9WxzA/vLgmqFBsi04IFlnK70RCXckWZEHFjnnoutqAWpl7FTRiTeT8Bv\nHgmX2+lh5QKBgDAuADIiWaFts6m1IL7dd/TnYGITMRuEmkZUlCvbqjWnTVdwZGNk\nRE/J7Mlglltfqk70EAiYeQPy//vEbNDt3oSpmlsapww/sxz76dOWtm4DqDZEkR0A\noUcJuFjWLQXvYSNgyVt+cbi+C09VjWWyDUyPOQMPTfwNRY/vuLsnsn/JAoGBAKrW\n0Ri46DBxRukFJmfbIKr3/etlZTf7GB1WEYnE3RsGZ6vd7hqeV2X1k01RMfc5+Kwk\nT7ug0XE8IroB1HeTSM2lGJ0jyPTSBoNJbtJKLsxeDVl7RGcYYuqB5HBAUMXuIu/P\nFPeFJoWLZsGkyMx9AT/KkEkuhBGCXUhGx6BQE3htAoGAbEGbhHV8oU7NYKEmVyWM\nwfEQXGH2QQpHsj7xkTywOKEneaMkVUzA5GwF7CQEvk/2xXEgze+haaRGxFQJTO5m\nGK2ECeQhTwXvNi+3/MEMCdoPYuckF4hCVzsGwfkVBPf1zcOw0k0+EEsqbWwtXi2l\njIyC7b2m2fgAI0Ltt1btCfo=\n-----END PRIVATE KEY-----";

    fn sample_agreement(id: &str, status: &str) -> Agreement {
        Agreement {
            agreement_id: id.to_string(),
            user_id: "user_1".to_string(),
            file_id: format!("FILE-{id}"),
            filename: "contract.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            original_size: 1_024,
            nodes: vec!["NODE-test".to_string()],
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

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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
        let seeded = agreements::ActiveModel {
            agreement_id: Set("AGR-existing".into()),
            user_id: Set("user_1".into()),
            file_id: Set("FILE-AGR-existing".into()),
            filename: Set("existing.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(555),
            nodes: Set(json!(["NODE-test"])),
            root: Set(None),
            padded_len: Set(None),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("confirmed".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        let storage_dir = unique_storage_dir("reconcile_dedup");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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
        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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
        let seeded = agreements::ActiveModel {
            agreement_id: Set("AGR-noop".into()),
            user_id: Set("user_1".into()),
            file_id: Set("FILE-AGR-noop".into()),
            filename: Set("noop.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(1024),
            nodes: Set(json!(["NODE-test"])),
            root: Set(Some("abc123".into())),
            padded_len: Set(Some(2048)),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("confirmed".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        let storage_dir = unique_storage_dir("reconcile_noop");
        stdfs::create_dir_all(&storage_dir).ok();
        let client = mock_portal_client(&mock_server.uri(), storage_dir.clone());
        let backend = StorageBackend::local();

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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

        reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir)
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
        let result = reconcile_from_portal(&client, &db, "NODE-test", &backend, &storage_dir).await;

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
}
