use crate::clients::PortalClient;
use crate::daemon::StorageLimits;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{anyhow, Context, Result};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set,
};

/// Download agreement files that are not yet stored locally.
pub async fn download_agreements(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_limits: StorageLimits,
) -> Result<()> {
    let mut used_bytes = match storage_limits.capacity {
        Some(_) => current_used_capacity(database).await?,
        None => 0,
    };
    let mut downloaded_files = match storage_limits.max_files {
        Some(_) => current_downloaded_count(database).await?,
        None => 0,
    };

    let pending = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(false))
        .all(database)
        .await
        .context("failed to load agreements to download")?;

    let mut downloaded_count = 0usize;

    for agreement in pending {
        let original_size: u64 = agreement
            .original_size
            .try_into()
            .context("original_size does not fit into u64")?;

        if let Some(max_files) = storage_limits.max_files {
            if downloaded_files >= max_files {
                println!(
                    "Skipping download for {} - max stored files {} reached",
                    agreement.agreement_id, max_files
                );
                continue;
            }
        }

        if let Some(capacity) = storage_limits.capacity {
            match used_bytes.checked_add(original_size) {
                Some(next) if next <= capacity => {}
                _ => {
                    println!(
                        "Skipping download for {} ({} bytes) - capacity {} bytes would be exceeded",
                        agreement.agreement_id, original_size, capacity
                    );
                    continue;
                }
            }
        }

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

        used_bytes = used_bytes.saturating_add(original_size);
        downloaded_files = downloaded_files.saturating_add(1);
        downloaded_count += 1;
    }

    println!("Downloaded {} agreements", downloaded_count);

    Ok(())
}

async fn current_used_capacity(database: &DatabaseConnection) -> Result<u64> {
    let downloaded = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .all(database)
        .await
        .context("failed to load downloaded agreements for capacity tracking")?;

    let mut total: u64 = 0;
    for agreement in downloaded {
        let size: u64 = agreement
            .original_size
            .try_into()
            .context("original_size does not fit into u64")?;
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("stored agreements exceed trackable capacity"))?;
    }
    Ok(total)
}

async fn current_downloaded_count(database: &DatabaseConnection) -> Result<u64> {
    let count = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(database)
        .await?;
    Ok(count)
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
            StorageLimits::default(),
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
            StorageLimits::default(),
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
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("capacity_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let already_downloaded = agreements::ActiveModel {
            agreement_id: Set("AGREEMENT-downloaded".into()),
            user_id: Set("user_1".into()),
            file_id: Set("FILE-downloaded".into()),
            filename: Set("downloaded.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(900),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z").unwrap()),
        };
        already_downloaded.insert(&database).await.unwrap();

        let pending = agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("pending.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(200),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-03T00:00:00Z").unwrap()),
        };
        pending.insert(&database).await.unwrap();

        // Capacity is below the sum of downloaded (900) + pending (200).
        download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: Some(1000),
                max_files: None,
            },
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
                .and(header("authorization", "Bearer secret"))
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

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("capacity_mid_batch");
        stdfs::remove_dir_all(&storage_dir).ok();

        let first = agreements::ActiveModel {
            agreement_id: Set(agreements[0].0.into()),
            user_id: Set("user_1".into()),
            file_id: Set(agreements[0].1.into()),
            filename: Set("one.txt".into()),
            mime_type: Set("text/plain".into()),
            original_size: Set(600),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-04T00:00:00Z").unwrap()),
        };
        first.insert(&database).await.unwrap();

        let second = agreements::ActiveModel {
            agreement_id: Set(agreements[1].0.into()),
            user_id: Set("user_1".into()),
            file_id: Set(agreements[1].1.into()),
            filename: Set("two.txt".into()),
            mime_type: Set("text/plain".into()),
            original_size: Set(500),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-05T00:00:00Z").unwrap()),
        };
        second.insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: Some(1000),
                max_files: None,
            },
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
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": format!("{}{}", mock_server.uri(), download_path)
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("max_files_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let already_downloaded = agreements::ActiveModel {
            agreement_id: Set("AGREEMENT-downloaded".into()),
            user_id: Set("user_1".into()),
            file_id: Set("FILE-downloaded".into()),
            filename: Set("downloaded.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(100),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-02T00:00:00Z").unwrap()),
        };
        already_downloaded.insert(&database).await.unwrap();

        let pending = agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("pending.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(200),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-03T00:00:00Z").unwrap()),
        };
        pending.insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: None,
                max_files: Some(1),
            },
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
                .and(header("authorization", "Bearer secret"))
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

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("max_files_mid_batch");
        stdfs::remove_dir_all(&storage_dir).ok();

        let first = agreements::ActiveModel {
            agreement_id: Set(agreements[0].0.into()),
            user_id: Set("user_1".into()),
            file_id: Set(agreements[0].1.into()),
            filename: Set("one.txt".into()),
            mime_type: Set("text/plain".into()),
            original_size: Set(10),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-04T00:00:00Z").unwrap()),
        };
        first.insert(&database).await.unwrap();

        let second = agreements::ActiveModel {
            agreement_id: Set(agreements[1].0.into()),
            user_id: Set("user_1".into()),
            file_id: Set(agreements[1].1.into()),
            filename: Set("two.txt".into()),
            mime_type: Set("text/plain".into()),
            original_size: Set(10),
            nodes: Set(json!(["NODE-1"])),
            downloaded: Set(false),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::DateTime::parse_from_rfc3339("2024-01-05T00:00:00Z").unwrap()),
        };
        second.insert(&database).await.unwrap();

        download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
            StorageLimits {
                capacity: None,
                max_files: Some(1),
            },
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
}
