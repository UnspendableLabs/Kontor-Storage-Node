//! Compute and submit Proof-of-Retrievability proofs for active challenges.
//!
//! This module handles the core POR workflow:
//! 1. Query active challenges from the local database
//! 2. Load the associated file data from local storage or GCS
//! 3. Generate cryptographic proofs using `kontor_crypto`
//! 4. Submit proofs to the Portal and update challenge status

use crate::clients::PortalClient;
use crate::config::StorageMethod;
use crate::entities::{agreements, challenges, prelude::Agreements, prelude::Challenges};
use crate::tasks::downloadagreements::StorageBackend;
use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use kontor_crypto::{api, Challenge as CryptoChallenge, FileLedger, FileMetadata, PorSystem};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::path::Path;
use tokio::fs;
use tracing::{info, warn, Instrument};

/// Compute and submit proofs for all active challenges.
///
/// This function:
/// 1. Queries challenges with status = "active" from the database
/// 2. For each challenge, loads the associated agreement and file data
/// 3. Generates a cryptographic proof using the POR system
/// 4. Submits the proof to Portal and updates the challenge status
pub async fn compute_and_submit_proofs(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
) -> Result<()> {
    // Query all active challenges
    let active_challenges = Challenges::find()
        .filter(challenges::Column::Status.eq("active"))
        .all(database)
        .await
        .context("failed to query active challenges")?;

    if active_challenges.is_empty() {
        info!("No active challenges to process");
        return Ok(());
    }

    info!("Processing {} active challenge(s)", active_challenges.len());

    // Load the file ledger once for all challenges
    let ledger_path = storage_dir.join("ledger.bin");
    let ledger = if ledger_path.exists() {
        FileLedger::load(&ledger_path)
            .with_context(|| format!("loading ledger from {}", ledger_path.display()))?
    } else {
        warn!(
            "Ledger file not found at {}; skipping proof computation",
            ledger_path.display()
        );
        return Ok(());
    };

    let mut submitted_count = 0usize;

    for challenge in active_challenges {
        let span = tracing::info_span!("process_challenge",
            challenge_id = %challenge.challenge_id,
            agreement_id = %challenge.agreement_id
        );

        match process_single_challenge(
            portal_client,
            database,
            storage_backend,
            storage_dir,
            &ledger,
            &challenge,
        )
        .instrument(span)
        .await
        {
            Ok(()) => {
                submitted_count += 1;
            }
            Err(err) => {
                warn!(
                    "Failed to process challenge {}: {err}",
                    challenge.challenge_id
                );
                // Continue processing other challenges
            }
        }
    }

    if submitted_count > 0 {
        info!("Submitted {} proof(s)", submitted_count);
    }

    Ok(())
}

/// Process a single challenge: load file, generate proof, submit to Portal.
async fn process_single_challenge(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    ledger: &FileLedger,
    challenge: &challenges::Model,
) -> Result<()> {
    // Get the associated agreement
    let agreement = Agreements::find()
        .filter(agreements::Column::AgreementId.eq(&challenge.agreement_id))
        .one(database)
        .await
        .context("failed to query agreement")?
        .ok_or_else(|| anyhow!("agreement {} not found", challenge.agreement_id))?;

    // Skip if agreement not downloaded or missing required metadata
    if !agreement.downloaded {
        return Err(anyhow!(
            "agreement {} not yet downloaded",
            agreement.agreement_id
        ));
    }

    if agreement.root.is_none() || agreement.padded_len.is_none() {
        return Err(anyhow!(
            "agreement {} missing root or padded_len metadata",
            agreement.agreement_id
        ));
    }

    // Load file bytes
    let file_bytes = load_file_bytes(storage_backend, storage_dir, &agreement.file_id).await?;

    // Prepare the file for proving.
    // We intentionally discard the metadata returned by prepare_file and use the DB metadata
    // instead. The DB metadata (root, padded_len) was computed at download time and registered
    // with Portal - we must use the same values to generate a valid proof.
    let (prepared, _metadata) =
        api::prepare_file(&file_bytes, &agreement.filename).context("preparing file for proof")?;

    // Build file metadata from agreement
    let file_metadata = build_file_metadata(&agreement)?;

    // Convert seed hex to FieldElement
    let seed_field = seed_to_field_element(&challenge.seed)?;

    // Create the crypto challenge
    let block_height: u64 = challenge.block_height.try_into().with_context(|| {
        format!(
            "block_height {} does not fit into u64",
            challenge.block_height
        )
    })?;
    let challenge_count: usize = challenge.challenge_count.try_into().with_context(|| {
        format!(
            "challenge_count {} does not fit into usize",
            challenge.challenge_count
        )
    })?;

    let crypto_challenge = CryptoChallenge::new(
        file_metadata,
        block_height,
        challenge_count,
        seed_field,
        challenge.prover_id.clone(),
    );

    // Create POR system and generate proof
    let system = PorSystem::new(ledger);
    let proof = system
        .prove(vec![&prepared], &[crypto_challenge])
        .map_err(|err| anyhow!("proof generation failed: {err}"))?;

    // Serialize proof to hex
    let proof_bytes = postcard::to_allocvec(&proof).context("serializing proof")?;
    let proof_hex = hex::encode(&proof_bytes);

    // Submit to Portal (BLS signature is computed internally by submit_proof)
    let response = portal_client
        .submit_proof(&challenge.challenge_id, &proof_hex)
        .await
        .with_context(|| format!("submitting proof for challenge {}", challenge.challenge_id))?;

    // Check response status - Portal may reject proof
    if response.status != "proved" {
        return Err(anyhow!(
            "proof rejected by Portal with status: {}",
            response.status
        ));
    }

    // Update challenge status in DB.
    // NOTE: If a crash occurs between the Portal submission above and this DB update,
    // the proof will be re-submitted on the next cycle. Portal should handle duplicate
    // submissions idempotently based on the challenge_id.
    let now = chrono::Utc::now().fixed_offset();
    let active_model = challenges::ActiveModel {
        challenge_id: Set(challenge.challenge_id.clone()),
        status: Set("proved".to_string()),
        // Store the proof returned by Portal if available, otherwise use our computed proof.
        // Portal may canonicalize or transform the proof representation.
        proof: Set(Some(response.proof.unwrap_or_else(|| proof_hex.clone()))),
        bls_signature: Set(response.bls_signature),
        updated_at: Set(now),
        ..Default::default()
    };

    active_model
        .update(database)
        .await
        .context("updating challenge status")?;

    info!(
        "Submitted proof for challenge {} (agreement {})",
        challenge.challenge_id, challenge.agreement_id
    );

    Ok(())
}

/// Load file bytes from local storage or GCS.
async fn load_file_bytes(
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    file_id: &str,
) -> Result<Vec<u8>> {
    match storage_backend.method {
        StorageMethod::Local => {
            let file_path = storage_dir.join(file_id);
            fs::read(&file_path)
                .await
                .with_context(|| format!("reading file from {}", file_path.display()))
        }
        StorageMethod::Gcs => {
            let gcs_client = storage_backend
                .gcs_client()
                .ok_or_else(|| anyhow!("GCS client not initialized"))?;
            let bytes = gcs_client
                .download_to_bytes(file_id)
                .await
                .with_context(|| format!("downloading file {file_id} from GCS"))?;
            Ok(bytes.to_vec())
        }
    }
}

/// Convert a hex-encoded seed to a FieldElement.
///
/// The seed must be exactly 32 bytes (64 hex characters). Seeds of other lengths
/// are rejected to prevent cryptographic mismatches.
fn seed_to_field_element(seed_hex: &str) -> Result<kontor_crypto::FieldElement> {
    let seed_bytes = hex::decode(seed_hex).context("decoding seed hex")?;

    // Require exactly 32 bytes for field conversion
    let seed_array: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("seed must be exactly 32 bytes, got {} bytes", v.len()))?;

    kontor_crypto::FieldElement::from_repr(seed_array.into())
        .into_option()
        .ok_or_else(|| anyhow!("seed bytes do not represent a valid field element"))
}

/// Build FileMetadata from an agreement model.
fn build_file_metadata(agreement: &agreements::Model) -> Result<FileMetadata> {
    let root_hex = agreement
        .root
        .as_ref()
        .ok_or_else(|| anyhow!("agreement missing root"))?;
    let padded_len = agreement
        .padded_len
        .ok_or_else(|| anyhow!("agreement missing padded_len"))?;

    let root_bytes = hex::decode(root_hex).context("decoding root hex")?;
    let root_array: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| anyhow!("root hex is not 32 bytes"))?;

    let root = kontor_crypto::FieldElement::from_repr(root_array.into())
        .into_option()
        .ok_or_else(|| anyhow!("invalid root field element"))?;

    let original_size: usize = agreement
        .original_size
        .try_into()
        .context("original_size does not fit into usize")?;
    let padded_len: usize = padded_len
        .try_into()
        .context("padded_len does not fit into usize")?;

    Ok(FileMetadata {
        root,
        file_id: agreement.file_id.clone(),
        padded_len,
        original_size,
        filename: agreement.filename.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::BlsKeyPair;
    use crate::entities::prelude::{Agreements, Challenges};
    use chrono::DateTime;
    use sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, DatabaseBackend, EntityTrait, Schema, Set,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::MockServer;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_storage_dir(prefix: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_compute_proofs_{prefix}_{id}"))
    }

    async fn setup_in_memory_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DatabaseBackend::Sqlite);

        let agreements_stmt = schema.create_table_from_entity(Agreements);
        db.execute(&agreements_stmt).await.unwrap();

        let challenges_stmt = schema.create_table_from_entity(Challenges);
        db.execute(&challenges_stmt).await.unwrap();

        db
    }

    fn sample_agreement(
        agreement_id: &str,
        file_id: &str,
        downloaded: bool,
    ) -> agreements::ActiveModel {
        agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("test.bin".into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(100),
            nodes: Set(json!(["NODE-1"])),
            root: Set(if downloaded {
                Some("0".repeat(64)) // 32 bytes as hex
            } else {
                None
            }),
            padded_len: Set(if downloaded { Some(128) } else { None }),
            downloaded: Set(downloaded),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        }
    }

    fn sample_challenge(challenge_id: &str, agreement_id: &str) -> challenges::ActiveModel {
        challenges::ActiveModel {
            challenge_id: Set(challenge_id.into()),
            agreement_id: Set(agreement_id.into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set("0102030405060708091011121314151617181920212223242526272829303132".into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
    }

    #[tokio::test]
    async fn returns_ok_when_no_active_challenges() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("no_challenges");
        std::fs::create_dir_all(&storage_dir).ok();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(result.is_ok(), "should succeed with no challenges");
    }

    #[tokio::test]
    async fn returns_ok_when_ledger_missing() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("no_ledger");
        std::fs::create_dir_all(&storage_dir).ok();

        // Insert an active challenge
        sample_challenge("chal_1", "agr_1")
            .insert(&db)
            .await
            .unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(
            result.is_ok(),
            "should succeed but skip when ledger missing"
        );

        // Challenge should still be active (not updated)
        let challenge = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_1"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.status, "active");
    }

    #[test]
    fn seed_to_field_element_rejects_short_seeds() {
        let short_seed = "0102030405";
        let result = seed_to_field_element(short_seed);
        assert!(result.is_err(), "should reject short seeds");
        assert!(
            result.unwrap_err().to_string().contains("exactly 32 bytes"),
            "error message should mention expected size"
        );
    }

    #[test]
    fn seed_to_field_element_rejects_long_seeds() {
        // 33 bytes = 66 hex chars
        let long_seed = "010203040506070809101112131415161718192021222324252627282930313233";
        let result = seed_to_field_element(long_seed);
        assert!(result.is_err(), "should reject long seeds");
        assert!(
            result.unwrap_err().to_string().contains("exactly 32 bytes"),
            "error message should mention expected size"
        );
    }

    #[test]
    fn seed_to_field_element_handles_valid_32_byte_seeds() {
        let full_seed = "0102030405060708091011121314151617181920212223242526272829303132";
        let result = seed_to_field_element(full_seed);
        assert!(result.is_ok(), "should handle exactly 32-byte seeds");
    }

    #[test]
    fn seed_to_field_element_rejects_invalid_hex() {
        let invalid_seed = "not_valid_hex";
        let result = seed_to_field_element(invalid_seed);
        assert!(result.is_err(), "should reject invalid hex");
    }

    #[test]
    fn build_file_metadata_requires_root() {
        let agreement = agreements::Model {
            agreement_id: "agr_1".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 100,
            nodes: json!(["NODE-1"]),
            root: None, // Missing
            padded_len: Some(128),
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let result = build_file_metadata(&agreement);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing root"));
    }

    #[test]
    fn build_file_metadata_requires_padded_len() {
        let agreement = agreements::Model {
            agreement_id: "agr_1".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 100,
            nodes: json!(["NODE-1"]),
            root: Some("0".repeat(64)),
            padded_len: None, // Missing
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let result = build_file_metadata(&agreement);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing padded_len"));
    }

    #[tokio::test]
    async fn skips_challenge_when_agreement_not_downloaded() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("not_downloaded");
        std::fs::create_dir_all(&storage_dir).ok();

        // Create an empty ledger
        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Insert agreement that's not downloaded
        sample_agreement("agr_1", "file_1", false)
            .insert(&db)
            .await
            .unwrap();
        sample_challenge("chal_1", "agr_1")
            .insert(&db)
            .await
            .unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(
            result.is_ok(),
            "should succeed but skip undownloaded agreements"
        );

        // Challenge should still be active
        let challenge = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_1"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.status, "active");
    }

    #[tokio::test]
    async fn skips_challenge_when_agreement_not_found() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("no_agreement");
        std::fs::create_dir_all(&storage_dir).ok();

        // Create an empty ledger
        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Insert challenge without corresponding agreement
        sample_challenge("chal_1", "agr_missing")
            .insert(&db)
            .await
            .unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(result.is_ok(), "should succeed but skip missing agreements");

        // Challenge should still be active
        let challenge = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_1"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(challenge.status, "active");
    }
}
