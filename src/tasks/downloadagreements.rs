use crate::clients::PortalClient;
use crate::daemon::StorageLimits;
use crate::entities::{
    agreements, file_metadata,
    prelude::{Agreements, FileMetadata},
};
use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use kontor_crypto::{api, FileLedger, FileMetadata as CryptoFileMetadata};
use sea_orm::{sea_query::OnConflict, ActiveValue::NotSet};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use std::fmt;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug)]
enum PostProcessError {
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

        let downloaded = portal_client
            .download_file(&agreement.agreement_id, &agreement.file_id)
            .await
            .with_context(|| {
                format!("downloading file for agreement {}", agreement.agreement_id)
            })?;

        let txn = database.begin().await?;

        // If post-processing fails, delete the downloaded file so capacity tracking
        // stays accurate and the next retry can start cleanly.
        if let Err(err) = process_downloaded_file(
            downloaded.path.as_path(),
            &downloaded.bytes,
            &agreement,
            &txn,
        )
        .await
        {
            if downloaded.path.exists() {
                if let Err(remove_err) = fs::remove_file(&downloaded.path).await {
                    eprintln!(
                        "failed to remove downloaded file {} after error: {remove_err}",
                        downloaded.path.display()
                    );
                }
            }
            txn.rollback().await.ok();
            return Err(anyhow!(err));
        }

        let mut model: agreements::ActiveModel = agreement.into();
        model.downloaded = Set(true);
        model
            .update(&txn)
            .await
            .context("marking agreement as downloaded failed")?;

        txn.commit().await?;

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

async fn process_downloaded_file(
    saved_path: &Path,
    file_bytes: &[u8],
    agreement: &agreements::Model,
    transaction: &DatabaseTransaction,
) -> Result<(), PostProcessError> {
    let metadata = prepare_file_metadata(file_bytes, &agreement.filename)
        .map_err(PostProcessError::Prepare)?;
    let storage_root = saved_path
        .parent()
        .ok_or_else(|| {
            anyhow!(
                "downloaded file path {} does not have a parent directory",
                saved_path.display()
            )
        })
        .map_err(PostProcessError::Prepare)?;
    // Persist metadata first within the transaction so DB writes roll back if ledger fails.
    persist_file_metadata(transaction, &agreement.agreement_id, &metadata)
        .await
        .map_err(PostProcessError::Metadata)?;

    update_ledger(storage_root, &metadata)
        .await
        .map_err(PostProcessError::Ledger)?;

    Ok(())
}

fn prepare_file_metadata(bytes: &[u8], filename: &str) -> Result<CryptoFileMetadata> {
    let (_prepared, metadata) =
        api::prepare_file(bytes, filename).context("preparing file with kontor_crypto")?;
    Ok(metadata)
}

async fn persist_file_metadata(
    database: &impl ConnectionTrait,
    agreement_id: &str,
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

    let active_model = file_metadata::ActiveModel {
        id: Set(metadata.file_id.clone()),
        agreement_id: Set(agreement_id.to_string()),
        filename: Set(metadata.filename.clone()),
        root: Set(root_hex),
        file_id: Set(metadata.file_id.clone()),
        original_size: Set(original_size),
        padded_len: Set(padded_len),
        created_at: NotSet,
    };

    FileMetadata::insert(active_model)
        .on_conflict(
            OnConflict::column(file_metadata::Column::Id)
                .update_columns([
                    file_metadata::Column::Id,
                    file_metadata::Column::Filename,
                    file_metadata::Column::Root,
                    file_metadata::Column::FileId,
                    file_metadata::Column::OriginalSize,
                    file_metadata::Column::PaddedLen,
                ])
                .to_owned(),
        )
        .exec(database)
        .await
        .context("persisting file metadata")?;

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
    use super::*;
    use crate::entities::prelude::{Agreements, FileMetadata};
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
        let agreements_stmt = schema.create_table_from_entity(Agreements);
        db.execute(&agreements_stmt).await.unwrap();

        let metadata_stmt = schema.create_table_from_entity(FileMetadata);
        db.execute(&metadata_stmt).await.unwrap();
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

        let metadata = FileMetadata::find()
            .one(&database)
            .await
            .unwrap()
            .expect("file metadata should be persisted");
        assert_eq!(metadata.agreement_id, agreement_id);
        assert!(!metadata.file_id.is_empty(), "file_id should be populated");
        assert_eq!(metadata.id, metadata.file_id, "id mirrors file_id");
        assert_eq!(metadata.filename, filename);
        assert_eq!(
            metadata.original_size,
            "file-body".len() as i64,
            "original_size should reflect prepared file bytes"
        );

        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger file should be created alongside downloads"
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
        let storage_dir = unique_storage_dir("idempotent");
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

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir.clone());

        download_agreements(&client, &database, StorageLimits::default())
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

        download_agreements(&client, &database, StorageLimits::default())
            .await
            .unwrap();

        let metadata_count = FileMetadata::find()
            .count(&database)
            .await
            .expect("should count metadata rows");
        assert_eq!(metadata_count, 1, "metadata should not duplicate on retry");

        let latest = FileMetadata::find()
            .one(&database)
            .await
            .unwrap()
            .expect("metadata should still exist");
        assert_eq!(latest.agreement_id, agreement_id);
        assert!(!latest.file_id.is_empty(), "file_id should remain set");
        assert_eq!(latest.id, latest.file_id, "id mirrors file_id");
        assert_eq!(
            latest.original_size,
            "file-body".len() as i64,
            "original_size reflects prepared file bytes"
        );

        assert!(
            storage_dir.join("ledger.bin").exists(),
            "ledger should remain persisted after retry"
        );

        let agreement_after_retry = Agreements::find()
            .filter(agreements::Column::AgreementId.eq(agreement_id))
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(agreement_after_retry.downloaded);
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
                max_file_size: None,
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
    async fn skips_downloads_over_max_file_size() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-too-large";
        let file_id = "FILE-too-large";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let database = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("max_file_size_skip");
        stdfs::remove_dir_all(&storage_dir).ok();

        let pending = agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("pending.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(2_000),
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
                max_file_size: Some(1_000),
                max_files: None,
            },
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
                max_file_size: None,
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
                max_file_size: None,
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
                max_file_size: None,
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
        let storage_dir = unique_storage_dir("ledger_error");
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

        // Create a directory where the ledger file should be written to force a failure.
        let ledger_dir = storage_dir.join("ledger.bin");
        stdfs::create_dir_all(&ledger_dir).unwrap();

        let result = download_agreements(
            &PortalClient::new(mock_server.uri(), "secret", storage_dir.clone()),
            &database,
            StorageLimits::default(),
        )
        .await;

        assert!(result.is_err(), "ledger write failure should bubble up");
        assert!(
            !storage_dir.join(file_id).exists(),
            "downloaded file should be removed when post-processing fails"
        );

        let metadata_count = FileMetadata::find().count(&database).await.unwrap();
        assert_eq!(
            metadata_count, 0,
            "metadata should not be persisted when ledger fails"
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
    }
}
