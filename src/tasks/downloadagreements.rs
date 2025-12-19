use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

/// Download agreement files that are not yet stored locally.
pub async fn download_agreements(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
) -> Result<()> {
    let pending = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(false))
        .all(database)
        .await
        .context("failed to load agreements to download")?;

    let total = pending.len();

    for agreement in pending {
        portal_client
            .download_file(&agreement.agreement_id, &agreement.file_id)
            .await
            .with_context(|| {
                format!("downloading file for agreement {}", agreement.agreement_id)
            })?;

        let mut model: agreements::ActiveModel = agreement.into();
        model.downloaded = Set(true);
        model
            .update(database)
            .await
            .context("marking agreement as downloaded failed")?;
    }

    println!("Downloaded {} agreements", total);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::prelude::Agreements;
    use sea_orm::{
        ConnectionTrait, Database, DatabaseBackend, EntityTrait, PaginatorTrait, Schema,
    };
    use serde_json::json;
    use std::fs as stdfs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::fs;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_storage_dir(prefix: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_download_agreements_{prefix}_{id}"))
    }

    async fn setup_in_memory_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DatabaseBackend::Sqlite);
        let stmt = schema.create_table_from_entity(Agreements);
        db.execute(&stmt).await.unwrap();
        db
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
            .and(header("authorization", "Bearer secret"))
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

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("download");
        stdfs::remove_dir_all(&storage_dir).ok();
        let agreement = agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set(filename.into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(123),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        };
        agreement.insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
        )
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
    }

    #[tokio::test]
    async fn skips_when_nothing_to_download() {
        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("empty");

        download_agreements(
            &PortalClient::new("http://localhost:1", "secret", storage_dir),
            &database,
        )
        .await
        .unwrap();

        let count = Agreements::find().count(&database).await.unwrap();
        assert_eq!(count, 0);
    }
}
