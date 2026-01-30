//! Compute and submit Proof-of-Retrievability proofs for active challenges.
//!
//! This module handles the core POR workflow:
//! 1. Query active challenges from the local database
//! 2. Load the associated file data from local storage or GCS
//! 3. Generate cryptographic proofs using `kontor_crypto`
//! 4. Submit proofs to the Portal and update challenge status

use crate::app::config::StorageMethod;
use crate::app::tasks::downloadagreements::StorageBackend;
use crate::app::tasks::{STATUS_ACTIVE, STATUS_PROVED};
use crate::clients::PortalClient;
use crate::entities::{agreements, challenges, prelude::Agreements, prelude::Challenges};
use anyhow::{anyhow, Context, Result};
use ff::PrimeField;
use kontor_crypto::{api, Challenge as CryptoChallenge, FileLedger, FileMetadata, PorSystem};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::path::Path;
use tokio::fs;
use tracing::{info, warn, Instrument};

/// Trait for generating cryptographic proofs.
///
/// This abstraction allows swapping the real crypto implementation with a mock
/// for faster testing.
pub trait ProofGenerator: Send + Sync {
    /// Generate a proof for the given file and challenge.
    ///
    /// Returns the serialized proof as bytes.
    fn generate_proof(
        &self,
        file_bytes: &[u8],
        filename: &str,
        ledger: &FileLedger,
        file_metadata: FileMetadata,
        crypto_challenge: CryptoChallenge,
    ) -> Result<Vec<u8>>;
}

/// Real implementation using kontor_crypto.
pub struct RealProofGenerator;

impl ProofGenerator for RealProofGenerator {
    fn generate_proof(
        &self,
        file_bytes: &[u8],
        filename: &str,
        ledger: &FileLedger,
        _file_metadata: FileMetadata,
        crypto_challenge: CryptoChallenge,
    ) -> Result<Vec<u8>> {
        // Prepare the file for proving
        let (prepared, _metadata) =
            api::prepare_file(file_bytes, filename).context("preparing file for proof")?;

        // Create POR system and generate proof
        let system = PorSystem::new(ledger);
        let proof = system
            .prove(vec![&prepared], &[crypto_challenge])
            .map_err(|err| anyhow!("proof generation failed: {err}"))?;

        // Serialize proof to bytes
        postcard::to_allocvec(&proof).context("serializing proof")
    }
}

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
    compute_and_submit_proofs_with_generator(
        portal_client,
        database,
        storage_backend,
        storage_dir,
        &RealProofGenerator,
    )
    .await
}

/// Internal implementation that accepts a proof generator for testability.
pub async fn compute_and_submit_proofs_with_generator<G: ProofGenerator>(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    proof_generator: &G,
) -> Result<()> {
    // Query all active challenges
    let active_challenges = Challenges::find()
        .filter(challenges::Column::Status.eq(STATUS_ACTIVE))
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
            proof_generator,
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
async fn process_single_challenge<G: ProofGenerator>(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    ledger: &FileLedger,
    challenge: &challenges::Model,
    proof_generator: &G,
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
        file_metadata.clone(),
        block_height,
        challenge_count,
        seed_field,
        challenge.prover_id.clone(),
    );

    // Generate proof using the provided generator
    let proof_bytes = proof_generator.generate_proof(
        &file_bytes,
        &agreement.filename,
        ledger,
        file_metadata,
        crypto_challenge,
    )?;
    let proof_hex = hex::encode(&proof_bytes);

    // Submit to Portal (BLS signature is computed internally by submit_proof)
    let response = portal_client
        .submit_proof(&challenge.challenge_id, &proof_hex)
        .await
        .with_context(|| format!("submitting proof for challenge {}", challenge.challenge_id))?;

    // Check response status - Portal may reject proof
    if response.status != STATUS_PROVED {
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
        status: Set(STATUS_PROVED.to_string()),
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
    use crate::clients::GcsClient;
    use crate::crypto::BlsKeyPair;
    use crate::entities::prelude::Challenges;
    use crate::testutils::{setup_in_memory_db, unique_storage_dir};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use serde_json::json;
    use std::fs as stdfs;
    use std::sync::Arc;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnumunEUnoZIs5\nDhEXTNTyJPFxsZMxgRhLs7m6aiVu7GrDgoWFMoLy/B6Ccl2c9ml/RzuK5uKbJKM9\ntcwA90gpp536aLWB0BbQuWtfceU3BmQWFtQRXqCww/o462cujXhcMe5bVPvE9b/5\nyV+oWmKa42tw4x5//Cj8LGAw8aQwlC+OQ19iA+vmKx7xjs0uBFtQHnjGxekT71vp\nLgv53SVi5yUscz9Scy/VuBkNfOCaEz5zV+EUplYuvRMVEJ0Pvk1wOYjby4Gz+OVI\nrp1+1RFBEeTu2zo06E4o23pfz5DbZaBMZ8qK3WkNx6eQOuYK6Zrq+zM5/Uoq6fqQ\nAIuYpCNxAgMBAAECggEAB1pTx9IpNEfcFpc4RpY2q5rU/s/zDPOE1iS92p82nuM8\nVu/M3Kb3OKG20K8kzXG79DlyMcenXXfAtD7Y/53XiwPvGAApHNS7e1D1lQyQKNZd\n4t4DU/ObBcTBnmcrcc3/3cLOmTBjjSHc1Z1vVRkJQ5L+rcc3GhM61Ls5SEv/j6WN\nFw/fnYGtxUUXBz1gVvok0o89qTgW0Pt7SWrUkbAhrsGeTFpzNbicgRsBUXJJdRcl\nvK5rwKSPUhiIVhpQ78usSLdO30X3Bfvf/GQpR56/UgDqkn20ZMpJhKrAxSbmLSu9\nhgkIbLAlABxdYUbGFp5aTALAJ8EyZn8MU9RRuL9DcQKBgQDp263xaTlx8BgbKnq1\nwY+SxuDlGz/LoGYjF6v6FNHM1hQ5v2FpxaxF5EDUm3fdh+Z9yegL/g8GQdQQnelG\nA43VACvGAESw1ilsBDl6TZ+LZY4MTQrWSGUqQxt3APu3lHDAXkipHu2X3cv/3VrO\nDGs2WYWPiMxg1ZkIBojyZQ0SnQKBgQC3m910nvJIJ+WLXeXiG2qN147/5GU7Yma2\n0pEhQ4XVN/f7joGzUXLeB0BXNNbdKuRqEQ1r2VkH3qqY6HAL6/fK01qEhWBLv1hu\ndkEhEruK9WxzA/vLgmqFBsi04IFlnK70RCXckWZEHFjnnoutqAWpl7FTRiTeT8Bv\nHgmX2+lh5QKBgDAuADIiWaFts6m1IL7dd/TnYGITMRuEmkZUlCvbqjWnTVdwZGNk\nRE/J7Mlglltfqk70EAiYeQPy//vEbNDt3oSpmlsapww/sxz76dOWtm4DqDZEkR0A\noUcJuFjWLQXvYSNgyVt+cbi+C09VjWWyDUyPOQMPTfwNRY/vuLsnsn/JAoGBAKrW\n0Ri46DBxRukFJmfbIKr3/etlZTf7GB1WEYnE3RsGZ6vd7hqeV2X1k01RMfc5+Kwk\nT7ug0XE8IroB1HeTSM2lGJ0jyPTSBoNJbtJKLsxeDVl7RGcYYuqB5HBAUMXuIu/P\nFPeFJoWLZsGkyMx9AT/KkEkuhBGCXUhGx6BQE3htAoGAbEGbhHV8oU7NYKEmVyWM\nwfEQXGH2QQpHsj7xkTywOKEneaMkVUzA5GwF7CQEvk/2xXEgze+haaRGxFQJTO5m\nGK2ECeQhTwXvNi+3/MEMCdoPYuckF4hCVzsGwfkVBPf1zcOw0k0+EEsqbWwtXi2l\njIyC7b2m2fgAI0Ltt1btCfo=\n-----END PRIVATE KEY-----";

    /// Mock proof generator that returns a fake proof instantly.
    struct MockProofGenerator;

    impl ProofGenerator for MockProofGenerator {
        fn generate_proof(
            &self,
            _file_bytes: &[u8],
            _filename: &str,
            _ledger: &FileLedger,
            _file_metadata: FileMetadata,
            _crypto_challenge: CryptoChallenge,
        ) -> Result<Vec<u8>> {
            // Return a fake proof - just some bytes that can be hex-encoded
            Ok(b"mock_proof_bytes_for_testing".to_vec())
        }
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

    /// Helper to create authenticated PortalClient and mount required mocks.
    async fn create_authenticated_client(
        mock_server: &MockServer,
        storage_dir: std::path::PathBuf,
    ) -> PortalClient {
        // Mock the portal xpub endpoint
        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        PortalClient::with_auth(mock_server.uri(), storage_dir, keypair, "NODE-test")
    }

    /// Helper to create a mock agreement with fake metadata for testing.
    /// Since we use MockProofGenerator, we don't need real crypto values.
    fn mock_agreement(agreement_id: &str, file_id: &str) -> agreements::ActiveModel {
        // Use a valid field element representation (all zeros is valid)
        let root_hex = "0".repeat(64); // 32 zero bytes

        agreements::ActiveModel {
            agreement_id: Set(agreement_id.into()),
            user_id: Set("user_1".into()),
            file_id: Set(file_id.into()),
            filename: Set("test.bin".into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(100),
            nodes: Set(json!(["NODE-test"])),
            root: Set(Some(root_hex)),
            padded_len: Set(Some(128)),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        }
    }

    #[tokio::test]
    async fn submits_proof_successfully_for_local_storage() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_local");
        stdfs::create_dir_all(&storage_dir).ok();

        let agreement_id = "agr_local_proof";
        let file_id = "file_local_proof";
        let file_bytes = b"test file content";

        // Create mock agreement (no real crypto needed with MockProofGenerator)
        mock_agreement(agreement_id, file_id)
            .insert(&db)
            .await
            .unwrap();

        // Write file to storage
        stdfs::write(storage_dir.join(file_id), file_bytes).unwrap();

        // Create empty ledger (MockProofGenerator ignores it)
        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Create challenge with valid 32-byte seed
        let seed = "0000000000000000000000000000000000000000000000000000000000000001";
        challenges::ActiveModel {
            challenge_id: Set("chal_local".into()),
            agreement_id: Set(agreement_id.into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Mock submit_proof endpoint
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_local"))
            .and(header_exists("Signature-Input"))
            .and(header_exists("Signature"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": "abc123",
                "bls_signature": "sig123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let backend = StorageBackend::local();

        // Use mock proof generator for fast tests
        let result = compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await;
        assert!(result.is_ok(), "should succeed: {:?}", result);

        // Verify challenge was updated
        let updated_challenge = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_local"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_challenge.status, "proved");
        assert!(updated_challenge.proof.is_some());
        assert!(updated_challenge.bls_signature.is_some());
    }

    #[tokio::test]
    async fn submits_proof_successfully_for_gcs_storage() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_gcs");
        stdfs::create_dir_all(&storage_dir).ok();

        let agreement_id = "agr_gcs_proof";
        let file_id = "file_gcs_proof";
        let file_bytes = b"test file content for GCS proof";
        let bucket = "bucket-proof";

        // Create mock agreement
        mock_agreement(agreement_id, file_id)
            .insert(&db)
            .await
            .unwrap();

        // Create empty ledger
        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Create challenge with valid 32-byte seed
        let seed = "0000000000000000000000000000000000000000000000000000000000000001";
        challenges::ActiveModel {
            challenge_id: Set("chal_gcs".into()),
            agreement_id: Set(agreement_id.into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Mock GCS token endpoint
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-gcs-proof"
            })))
            .mount(&mock_server)
            .await;

        // Mock GCS download endpoint
        Mock::given(method("GET"))
            .and(path(format!("/storage/v1/b/{bucket}/o/{file_id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(file_bytes.to_vec())
                    .append_header("Content-Type", "application/octet-stream"),
            )
            .mount(&mock_server)
            .await;

        // Mock submit_proof endpoint
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_gcs"))
            .and(header_exists("Signature-Input"))
            .and(header_exists("Signature"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": "gcs_proof",
                "bls_signature": "gcs_sig"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
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

        let result = compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await;
        assert!(result.is_ok(), "GCS proof should succeed: {:?}", result);

        // Verify challenge was updated
        let updated_challenge = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_gcs"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_challenge.status, "proved");
    }

    #[tokio::test]
    async fn continues_processing_when_one_challenge_fails() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_multi");
        stdfs::create_dir_all(&storage_dir).ok();

        // Setup two agreements - one will succeed, one will fail (missing file)
        let file_id_1 = "file_1";
        let file_id_2 = "file_2";
        mock_agreement("agr_1", file_id_1)
            .insert(&db)
            .await
            .unwrap();
        mock_agreement("agr_2", file_id_2)
            .insert(&db)
            .await
            .unwrap();

        // Only write file_1 to storage (file_2 will be missing)
        stdfs::write(storage_dir.join(file_id_1), b"content for success").unwrap();

        // Create empty ledger
        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        let seed = "0000000000000000000000000000000000000000000000000000000000000001";

        // Challenge 1 - will succeed
        challenges::ActiveModel {
            challenge_id: Set("chal_multi_1".into()),
            agreement_id: Set("agr_1".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Challenge 2 - will fail (file missing on disk)
        challenges::ActiveModel {
            challenge_id: Set("chal_multi_2".into()),
            agreement_id: Set("agr_2".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_multi_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": "proof1",
                "bls_signature": "sig1"
            })))
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await;
        assert!(result.is_ok(), "should succeed overall even when one fails");

        // Challenge 1 should be proved
        let chal1 = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_multi_1"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chal1.status, "proved");

        // Challenge 2 should still be active (failed)
        let chal2 = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_multi_2"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chal2.status, "active");
    }

    #[tokio::test]
    async fn handles_portal_rejection_status() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_rejected");
        stdfs::create_dir_all(&storage_dir).ok();

        let file_id = "file_rejected";
        mock_agreement("agr_rejected", file_id)
            .insert(&db)
            .await
            .unwrap();

        stdfs::write(storage_dir.join(file_id), b"content for rejected test").unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        let seed = "0000000000000000000000000000000000000000000000000000000000000001";
        challenges::ActiveModel {
            challenge_id: Set("chal_rejected".into()),
            agreement_id: Set("agr_rejected".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Portal returns a rejection status
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_rejected"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "rejected",
                "proof": null,
                "bls_signature": null
            })))
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await;
        // Should succeed overall but challenge should remain active
        assert!(result.is_ok());

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_rejected"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            chal.status, "active",
            "challenge should remain active when rejected"
        );
    }

    #[tokio::test]
    async fn skips_challenge_when_agreement_missing_root() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("missing_root");
        stdfs::create_dir_all(&storage_dir).ok();

        // Agreement with downloaded=true but root=None
        let agreement = agreements::ActiveModel {
            agreement_id: Set("agr_no_root".into()),
            user_id: Set("user_1".into()),
            file_id: Set("file_no_root".into()),
            filename: Set("test.bin".into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(100),
            nodes: Set(json!(["NODE-test"])),
            root: Set(None), // Missing!
            padded_len: Set(Some(128)),
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        };
        agreement.insert(&db).await.unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        sample_challenge("chal_no_root", "agr_no_root")
            .insert(&db)
            .await
            .unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(result.is_ok());

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_no_root"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chal.status, "active", "challenge should remain active");
    }

    #[tokio::test]
    async fn skips_challenge_when_agreement_missing_padded_len() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("missing_padded_len");
        stdfs::create_dir_all(&storage_dir).ok();

        let agreement = agreements::ActiveModel {
            agreement_id: Set("agr_no_padded".into()),
            user_id: Set("user_1".into()),
            file_id: Set("file_no_padded".into()),
            filename: Set("test.bin".into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(100),
            nodes: Set(json!(["NODE-test"])),
            root: Set(Some("0".repeat(64))),
            padded_len: Set(None), // Missing!
            downloaded: Set(true),
            transaction_id: Set(None),
            curation: Set(json!({})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap()),
        };
        agreement.insert(&db).await.unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        sample_challenge("chal_no_padded", "agr_no_padded")
            .insert(&db)
            .await
            .unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client =
            PortalClient::with_auth(mock_server.uri(), storage_dir.clone(), keypair, "NODE-test");
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(&client, &db, &backend, &storage_dir).await;
        assert!(result.is_ok());

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_no_padded"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chal.status, "active");
    }

    #[tokio::test]
    async fn load_file_bytes_errors_when_gcs_client_not_initialized() {
        let backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: None,
        };
        let storage_dir = unique_storage_dir("gcs_not_init");

        let result = load_file_bytes(&backend, &storage_dir, "some_file").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("GCS client not initialized"));
    }

    #[test]
    fn build_file_metadata_rejects_invalid_root_hex() {
        let agreement = agreements::Model {
            agreement_id: "agr_bad_root".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 100,
            nodes: json!(["NODE-1"]),
            root: Some("invalid_hex".into()), // Not valid hex
            padded_len: Some(128),
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
            .contains("decoding root hex"));
    }

    #[test]
    fn build_file_metadata_rejects_wrong_length_root() {
        let agreement = agreements::Model {
            agreement_id: "agr_short_root".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 100,
            nodes: json!(["NODE-1"]),
            root: Some("0102030405".into()), // Too short (5 bytes instead of 32)
            padded_len: Some(128),
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let result = build_file_metadata(&agreement);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not 32 bytes"));
    }

    #[test]
    fn build_file_metadata_succeeds_with_valid_data() {
        // Use a real field element from prepare_file
        let file_bytes = b"test content";
        let (_prepared, real_metadata) = api::prepare_file(file_bytes, "test.bin").unwrap();
        let root_hex = hex::encode(real_metadata.root.to_repr());

        let agreement = agreements::Model {
            agreement_id: "agr_valid".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: real_metadata.original_size as i64,
            nodes: json!(["NODE-1"]),
            root: Some(root_hex),
            padded_len: Some(real_metadata.padded_len as i64),
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let result = build_file_metadata(&agreement);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.file_id, "file_1");
        assert_eq!(metadata.filename, "test.bin");
    }

    #[test]
    fn seed_to_field_element_rejects_non_representable_value() {
        // A value that is >= the field modulus will fail from_repr
        // The BLS12-381 scalar field modulus is slightly less than 2^255
        // Use all 0xff bytes which is definitely larger than the modulus
        let invalid_seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = seed_to_field_element(invalid_seed);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("valid field element"));
    }

    #[tokio::test]
    async fn portal_submission_uses_returned_proof_when_available() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_returned");
        stdfs::create_dir_all(&storage_dir).ok();

        let file_id = "file_ret";
        mock_agreement("agr_ret", file_id)
            .insert(&db)
            .await
            .unwrap();

        stdfs::write(
            storage_dir.join(file_id),
            b"content for returned proof test",
        )
        .unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        let seed = "0000000000000000000000000000000000000000000000000000000000000001";
        challenges::ActiveModel {
            challenge_id: Set("chal_ret".into()),
            agreement_id: Set("agr_ret".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Portal returns its own proof representation
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_ret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": "portal_canonical_proof",
                "bls_signature": "portal_sig"
            })))
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let backend = StorageBackend::local();

        compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await
        .unwrap();

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_ret"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(chal.status, "proved");
        assert_eq!(
            chal.proof,
            Some("portal_canonical_proof".to_string()),
            "should use Portal's returned proof"
        );
        assert_eq!(
            chal.bls_signature,
            Some("portal_sig".to_string()),
            "should store Portal's signature"
        );
    }

    #[tokio::test]
    async fn uses_computed_proof_when_portal_returns_none() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("proof_fallback");
        stdfs::create_dir_all(&storage_dir).ok();

        let file_id = "file_fb";
        mock_agreement("agr_fb", file_id).insert(&db).await.unwrap();

        stdfs::write(
            storage_dir.join(file_id),
            b"content for fallback proof test",
        )
        .unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        let seed = "0000000000000000000000000000000000000000000000000000000000000001";
        challenges::ActiveModel {
            challenge_id: Set("chal_fb".into()),
            agreement_id: Set("agr_fb".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set(seed.into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        }
        .insert(&db)
        .await
        .unwrap();

        // Portal returns no proof in response
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_fb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": null,
                "bls_signature": null
            })))
            .mount(&mock_server)
            .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let backend = StorageBackend::local();

        compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &backend,
            &storage_dir,
            &MockProofGenerator,
        )
        .await
        .unwrap();

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_fb"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(chal.status, "proved");
        assert!(
            chal.proof.is_some(),
            "should use computed proof when portal returns none"
        );
        assert!(
            chal.proof.as_ref().unwrap().len() > 10,
            "computed proof should be non-trivial"
        );
    }
}
