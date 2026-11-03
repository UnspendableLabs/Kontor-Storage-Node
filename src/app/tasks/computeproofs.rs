//! Compute and submit Proof-of-Retrievability proofs for active challenges.
//!
//! This module handles the core POR workflow:
//! 1. Query active challenges from the local database
//! 2. Load the associated file data from local storage or GCS
//! 3. Generate cryptographic proofs using `kontor_crypto`
//! 4. Submit proofs to the Portal and update challenge status
//!
//! # Retrying a rejected proof
//!
//! Kontor no longer fails a challenge on a bad proof: `verify-proof` returns an
//! error, the challenge stays `active` until its deadline, and the Portal hands
//! it back to the node as `active` again. The node mirrors that status, so the
//! challenge is simply proved again on a later cycle — which is right for a
//! rejection caused by something that has since changed (a ledger slot the
//! Portal had not reconciled, a nonce lost to a collision).
//!
//! It is wrong for a proof that is rejected *deterministically*: that one would
//! be recomputed and resubmitted every cycle, paying gas and a SNARK each time,
//! until the deadline. [`ProofRetries`] spaces resubmissions out and stops after
//! [`MAX_PROOF_SUBMISSIONS`]. Stopping does not save the collateral — the
//! challenge will expire and be slashed either way — it only stops the node
//! burning its gas reserve on the way there, and says so in the log.
//!
//! Challenges are worked through nearest deadline first: one cycle can run out
//! of time or gas, and the one that expires soonest is the one a delay costs.

use crate::app::config::StorageMethod;
use crate::app::tasks::downloadagreements::{StorageBackend, PORTAL_FILE_NONCE};
use crate::app::tasks::{field_from_hex, STATUS_ACTIVE, STATUS_PROVED};
use crate::clients::PortalClient;
use crate::entities::{agreements, challenges, prelude::Agreements, prelude::Challenges};
use anyhow::{anyhow, Context, Result};
use kontor_crypto::{api, Challenge as CryptoChallenge, FileLedger, FileMetadata, PorSystem};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::fs;
use tracing::{debug, error, info, warn, Instrument};

/// Submissions one challenge gets before the node stops proving it.
pub const MAX_PROOF_SUBMISSIONS: u32 = 5;

/// Wait before the first resubmission; doubles with each one after.
const RESUBMIT_BASE_DELAY: Duration = Duration::from_secs(60);

/// Ceiling on that wait, so a challenge with a long window is still retried a
/// few times well before its deadline.
const RESUBMIT_MAX_DELAY: Duration = Duration::from_secs(16 * 60);

/// Bookkeeping for challenges that have been proved at least once.
///
/// In memory: a restart starts every count again, which costs at most another
/// [`MAX_PROOF_SUBMISSIONS`] attempts on a challenge that was already hopeless
/// and never costs a proof that could have landed.
#[derive(Debug, Default)]
pub struct ProofRetries {
    attempts: Mutex<HashMap<String, Attempts>>,
}

#[derive(Debug, Clone, Copy)]
struct Attempts {
    submissions: u32,
    last: Instant,
    gave_up_logged: bool,
}

/// What [`ProofRetries::check`] says about one active challenge.
#[derive(Debug, PartialEq, Eq)]
enum RetryCheck {
    Prove,
    /// Proved recently; not again until the backoff has passed.
    Wait,
    /// Out of submissions. `announce` is true the first time only.
    GiveUp {
        announce: bool,
    },
}

impl ProofRetries {
    fn check(&self, challenge_id: &str, now: Instant) -> RetryCheck {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = attempts.get_mut(challenge_id) else {
            return RetryCheck::Prove;
        };
        if entry.submissions >= MAX_PROOF_SUBMISSIONS {
            let announce = !entry.gave_up_logged;
            entry.gave_up_logged = true;
            return RetryCheck::GiveUp { announce };
        }
        if now.duration_since(entry.last) < resubmit_delay(entry.submissions) {
            RetryCheck::Wait
        } else {
            RetryCheck::Prove
        }
    }

    /// A proof for `challenge_id` reached the Portal — accepted or refused.
    fn record_submission(&self, challenge_id: &str, now: Instant) -> u32 {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = attempts
            .entry(challenge_id.to_string())
            .or_insert(Attempts {
                submissions: 0,
                last: now,
                gave_up_logged: false,
            });
        entry.submissions += 1;
        entry.last = now;
        entry.submissions
    }

    /// Drop the counts of challenges no longer active, once they are old
    /// enough that a return to `active` is not coming.
    fn prune(&self, active: &[String], now: Instant) {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        attempts.retain(|id, entry| {
            active.contains(id) || now.duration_since(entry.last) < Duration::from_secs(24 * 3600)
        });
    }
}

/// Backoff after the `submissions`-th proof: 1, 2, 4, 8, 16, 16… minutes.
fn resubmit_delay(submissions: u32) -> Duration {
    let doublings = submissions.saturating_sub(1).min(16);
    RESUBMIT_BASE_DELAY
        .saturating_mul(1 << doublings)
        .min(RESUBMIT_MAX_DELAY)
}

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
        // Prepare the file for proving. The nonce must be the one the Portal
        // published in the on-chain descriptor, otherwise the derived `file_id`
        // differs from the one the challenge is bound to.
        let (prepared, _metadata) = api::prepare_file(file_bytes, filename, PORTAL_FILE_NONCE)
            .context("preparing file for proof")?;

        // Create POR system and generate proof
        let system = PorSystem::new(ledger);
        let proof = system
            .prove(vec![&prepared], &[crypto_challenge])
            .map_err(|err| anyhow!("proof generation failed: {err}"))?;

        // Serialize with kontor-crypto's own versioned wire format (`NPOR` magic
        // + format version + pinned bincode). This is exactly what the
        // filestorage contract feeds to `proof::from-bytes`, so any other
        // encoding is rejected before verification even starts.
        proof
            .to_bytes()
            .map_err(|err| anyhow!("serializing proof: {err}"))
    }
}

/// Compute and submit proofs for all active challenges.
///
/// This function:
/// 1. Queries challenges with status = "active" from the database, nearest
///    deadline first
/// 2. For each challenge, loads the associated agreement and file data
/// 3. Generates a cryptographic proof using the POR system
/// 4. Submits the proof to Portal and updates the challenge status
///
/// `retries` carries the per-challenge submission count across cycles.
pub async fn compute_and_submit_proofs(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    retries: &ProofRetries,
) -> Result<()> {
    prove_active_challenges(
        portal_client,
        database,
        storage_backend,
        storage_dir,
        &RealProofGenerator,
        retries,
    )
    .await
}

/// [`prove_active_challenges`] with a fresh retry memory, for tests that run
/// one pass.
#[cfg(test)]
pub async fn compute_and_submit_proofs_with_generator<G: ProofGenerator>(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    proof_generator: &G,
) -> Result<()> {
    prove_active_challenges(
        portal_client,
        database,
        storage_backend,
        storage_dir,
        proof_generator,
        &ProofRetries::default(),
    )
    .await
}

/// Internal implementation that accepts a proof generator for testability.
async fn prove_active_challenges<G: ProofGenerator>(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    proof_generator: &G,
    retries: &ProofRetries,
) -> Result<()> {
    // Only `active` is worked on. Every other status — `proved`, `failed`,
    // and any the Portal adds later, such as a `settled` leaking through — is
    // simply not this function's business, and is never an error.
    let active_challenges = Challenges::find()
        .filter(challenges::Column::Status.eq(STATUS_ACTIVE))
        .order_by_asc(challenges::Column::DeadlineHeight)
        .order_by_asc(challenges::Column::ChallengeId)
        .all(database)
        .await
        .context("failed to query active challenges")?;

    let now = Instant::now();
    let active_ids: Vec<String> = active_challenges
        .iter()
        .map(|challenge| challenge.challenge_id.clone())
        .collect();
    retries.prune(&active_ids, now);

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
        match retries.check(&challenge.challenge_id, now) {
            RetryCheck::Prove => {}
            RetryCheck::Wait => {
                debug!(
                    "Challenge {} was proved recently; waiting before resubmitting",
                    challenge.challenge_id
                );
                continue;
            }
            RetryCheck::GiveUp { announce } => {
                if announce {
                    error!(
                        "Giving up on challenge {} (agreement {}, deadline height {}) after \
                         {MAX_PROOF_SUBMISSIONS} proofs Kontor did not accept. It will expire, \
                         and expiry is slashed at 30× the agreement's collateral — check the \
                         stored file and its ledger slot.",
                        challenge.challenge_id, challenge.agreement_id, challenge.deadline_height
                    );
                }
                continue;
            }
        }

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
                let submissions = retries.record_submission(&challenge.challenge_id, now);
                if submissions > 1 {
                    warn!(
                        "Resubmitted a proof for challenge {} (submission {submissions} of at \
                         most {MAX_PROOF_SUBMISSIONS}): the previous one was not accepted",
                        challenge.challenge_id
                    );
                }
                submitted_count += 1;
            }
            Err(ProcessError::Submitted(err)) => {
                // The Portal saw this proof and turned it down: that counts.
                retries.record_submission(&challenge.challenge_id, now);
                warn!(
                    "Failed to process challenge {}: {err}",
                    challenge.challenge_id
                );
            }
            Err(ProcessError::NotSubmitted(err)) => {
                // Nothing reached the Portal (missing file, slot not yet
                // reconciled…): free to try again next cycle.
                warn!(
                    "Failed to process challenge {}: {err}",
                    challenge.challenge_id
                );
            }
        }
    }

    if submitted_count > 0 {
        info!("Submitted {} proof(s)", submitted_count);
    }

    Ok(())
}

/// Why a challenge was not proved, split by whether the Portal saw a proof.
#[derive(Debug)]
enum ProcessError {
    /// Failed before anything was submitted.
    NotSubmitted(anyhow::Error),
    /// A proof was submitted and refused, or accepted and then not recorded.
    Submitted(anyhow::Error),
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
) -> Result<(), ProcessError> {
    let proof_hex = build_proof(
        portal_client,
        database,
        storage_backend,
        storage_dir,
        ledger,
        challenge,
        proof_generator,
    )
    .await
    .map_err(ProcessError::NotSubmitted)?;

    submit_and_record(portal_client, database, challenge, proof_hex)
        .await
        .map_err(ProcessError::Submitted)
}

/// Load the file and generate the proof for one challenge.
async fn build_proof<G: ProofGenerator>(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    storage_backend: &StorageBackend,
    storage_dir: &Path,
    ledger: &FileLedger,
    challenge: &challenges::Model,
    proof_generator: &G,
) -> Result<String> {
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

    // Without a contract-assigned slot the file was left out of the rebuilt
    // ledger, so `prove` would fail deep inside kontor-crypto on a lookup miss.
    // Say why here instead: the Portal has not reconciled the creating
    // transaction yet, and the next sync cycle may well fix it.
    if agreement.ledger_index.is_none() {
        return Err(anyhow!(
            "agreement {} has no ledger_index yet: the Portal has not reconciled its \
             creating transaction against Kontor, so no verifiable proof can be built",
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

    // The prover identity bound into the challenge hash is the Kontor
    // `signer_id` rendered as a decimal string — the contract stores
    // `challenge-data.prover-id` as a `u64` and the host derives the crypto
    // `Challenge.prover_id` from it via `prover_challenge_key`. The Portal's
    // `challenges.prover_id` is a Portal-side node name and must NOT be used
    // here: it would produce a different `Challenge::id()`, hence a different
    // SNARK statement than the one the contract verifies.
    let signer_id = portal_client
        .signer_id()
        .ok_or_else(|| anyhow!("authentication required to compute proofs: no signer_id"))?;

    let crypto_challenge = CryptoChallenge::new(
        file_metadata.clone(),
        block_height,
        challenge_count,
        seed_field,
        prover_challenge_key(signer_id),
    );

    // Generate proof using the provided generator
    let proof_bytes = proof_generator.generate_proof(
        &file_bytes,
        &agreement.filename,
        ledger,
        file_metadata,
        crypto_challenge,
    )?;
    Ok(hex::encode(&proof_bytes))
}

/// Submit one proof and mirror the Portal's answer locally.
async fn submit_and_record(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
    challenge: &challenges::Model,
    proof_hex: String,
) -> Result<()> {
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

/// Render a Kontor `signer_id` the way the filestorage host binds it into a
/// challenge hash: as its decimal string.
///
/// Mirrors `prover_challenge_key` in Kontor's `core/indexer/src/runtime/wit`.
/// The value feeds `Challenge::id()`, which the SNARK's initial state commits
/// to, so it must match the host byte for byte.
fn prover_challenge_key(signer_id: u64) -> String {
    signer_id.to_string()
}

/// Convert a hex-encoded challenge seed to a FieldElement.
///
/// The filestorage contract derives the seed with HKDF-SHA256 and stores the
/// full 64-byte output (`derive_challenge_seed_for_file`), which the host maps
/// into the field with `field_from_uniform_bytes` — an unbiased wide reduction,
/// not a canonical 32-byte decoding. Reproducing that exactly is what makes the
/// node's `Challenge.seed` equal the contract's; anything else yields a
/// different challenge and a proof that cannot verify.
fn seed_to_field_element(seed_hex: &str) -> Result<kontor_crypto::FieldElement> {
    let seed_bytes = hex::decode(seed_hex).context("decoding seed hex")?;

    let seed_array: [u8; 64] = seed_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("seed must be exactly 64 bytes, got {} bytes", v.len()))?;

    Ok(kontor_crypto::field_from_uniform_bytes(&seed_array))
}

/// Build FileMetadata from an agreement model.
///
/// Every field has to reproduce the on-chain `raw-file-descriptor` exactly: the
/// contract builds its own `FileMetadata` from `agreement-data`, and
/// `Challenge::id()` hashes `file_id`, `nonce`, `padded_len`, `original_size`
/// and `root` on both sides. `nonce` is therefore mirrored from the Portal
/// rather than invented — see
/// [`crate::app::tasks::downloadagreements::PORTAL_FILE_NONCE`] for why it is
/// empty. `object_id` does not enter the challenge hash but is still required
/// (`FileMetadata::validate` rejects an empty one), so it too comes from the
/// Portal.
fn build_file_metadata(agreement: &agreements::Model) -> Result<FileMetadata> {
    let root_hex = agreement
        .root
        .as_ref()
        .ok_or_else(|| anyhow!("agreement missing root"))?;
    let padded_len = agreement
        .padded_len
        .ok_or_else(|| anyhow!("agreement missing padded_len"))?;
    let object_id = agreement
        .object_id
        .as_ref()
        .ok_or_else(|| anyhow!("agreement missing object_id"))?
        .clone();

    let root = field_from_hex(root_hex, "root")?;

    let original_size: usize = agreement
        .original_size
        .try_into()
        .context("original_size does not fit into usize")?;
    let padded_len: usize = padded_len
        .try_into()
        .context("padded_len does not fit into usize")?;

    Ok(FileMetadata {
        root,
        object_id,
        file_id: agreement.file_id.clone(),
        nonce: PORTAL_FILE_NONCE.to_vec(),
        padded_len,
        original_size,
        filename: agreement.filename.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::app::tasks::downloadagreements::rebuild_ledger;
    use crate::clients::GcsClient;
    use crate::crypto::BlsKeyPair;
    use crate::entities::prelude::Challenges;
    use crate::testutils::{setup_in_memory_db, unique_storage_dir, AgreementFixture};
    use chrono::DateTime;
    use ff::PrimeField;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use serde_json::json;
    use std::fs as stdfs;
    use std::sync::Arc;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A challenge seed as the filestorage contract publishes it: the full
    /// 64-byte HKDF-SHA256 output, hex-encoded (128 characters).
    const TEST_SEED_HEX: &str = "0102030405060708091011121314151617181920212223242526272829303132\
                                 3334353637383940414243444546474849505152535455565758596061626364";

    /// `object-id` mirrored from the Portal for fixtures that need a complete
    /// on-chain descriptor.
    const TEST_OBJECT_ID: &str = "obj_test";

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
            object_id: Set(downloaded.then(|| TEST_OBJECT_ID.to_string())),
            ledger_index: Set(downloaded.then_some(0)),
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
            seed: Set(TEST_SEED_HEX.into()),
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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
        // The old 32-byte form is now too short: the contract publishes the
        // full 64-byte HKDF output.
        let short_seed = "0102030405060708091011121314151617181920212223242526272829303132";
        let result = seed_to_field_element(short_seed);
        assert!(result.is_err(), "should reject short seeds");
        assert!(
            result.unwrap_err().to_string().contains("exactly 64 bytes"),
            "error message should mention expected size"
        );
    }

    #[test]
    fn seed_to_field_element_rejects_long_seeds() {
        let long_seed = format!("{TEST_SEED_HEX}ff");
        let result = seed_to_field_element(&long_seed);
        assert!(result.is_err(), "should reject long seeds");
        assert!(
            result.unwrap_err().to_string().contains("exactly 64 bytes"),
            "error message should mention expected size"
        );
    }

    #[test]
    fn seed_to_field_element_handles_valid_64_byte_seeds() {
        assert_eq!(TEST_SEED_HEX.len(), 128, "64 bytes is 128 hex characters");
        assert!(seed_to_field_element(TEST_SEED_HEX).is_ok());
    }

    /// `field_from_uniform_bytes` is a wide reduction, so an all-`0xff` seed —
    /// far above the field modulus — must still map to a valid element rather
    /// than being rejected the way a canonical 32-byte decoding would.
    #[test]
    fn seed_to_field_element_reduces_values_above_the_modulus() {
        let seed = "ff".repeat(64);
        assert!(seed_to_field_element(&seed).is_ok());
    }

    #[test]
    fn seed_to_field_element_rejects_invalid_hex() {
        let invalid_seed = "not_valid_hex";
        let result = seed_to_field_element(invalid_seed);
        assert!(result.is_err(), "should reject invalid hex");
    }

    /// The prover identity bound into the challenge hash is the Kontor
    /// `signer_id` as a decimal string, mirroring Kontor's
    /// `prover_challenge_key`.
    #[test]
    fn prover_challenge_key_renders_the_signer_id_as_decimal() {
        assert_eq!(prover_challenge_key(0), "0");
        assert_eq!(prover_challenge_key(42), "42");
        assert_eq!(prover_challenge_key(u64::MAX), "18446744073709551615");
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
            object_id: None,
            ledger_index: None,
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
            object_id: None,
            ledger_index: None,
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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

    async fn create_authenticated_client(
        mock_server: &MockServer,
        storage_dir: std::path::PathBuf,
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
            object_id: Set(Some(TEST_OBJECT_ID.to_string())),
            ledger_index: Set(Some(0)),
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
        let seed = TEST_SEED_HEX;
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
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
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
        let seed = TEST_SEED_HEX;
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
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
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

        let seed = TEST_SEED_HEX;

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

        let seed = TEST_SEED_HEX;
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
            object_id: Set(None),
            ledger_index: Set(None),
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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
            object_id: Set(None),
            ledger_index: Set(None),
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
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir.clone(),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let backend = StorageBackend::local();

        let result = compute_and_submit_proofs(
            &client,
            &db,
            &backend,
            &storage_dir,
            &ProofRetries::default(),
        )
        .await;
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
            object_id: Some(TEST_OBJECT_ID.to_string()),
            ledger_index: None,
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
            object_id: Some(TEST_OBJECT_ID.to_string()),
            ledger_index: None,
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

    /// The rebuilt metadata must equal the descriptor the contract holds,
    /// field for field — `Challenge::id()` hashes over all of it.
    #[test]
    fn build_file_metadata_reproduces_the_on_chain_descriptor() {
        let file_bytes = b"test content";
        let (_prepared, real_metadata) =
            api::prepare_file(file_bytes, "test.bin", PORTAL_FILE_NONCE).unwrap();
        let root_hex = hex::encode(real_metadata.root.to_repr());

        let agreement = agreements::Model {
            agreement_id: real_metadata.file_id.clone(),
            user_id: "user_1".into(),
            file_id: real_metadata.file_id.clone(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: real_metadata.original_size as i64,
            nodes: json!(["NODE-1"]),
            root: Some(root_hex),
            padded_len: Some(real_metadata.padded_len as i64),
            object_id: Some(real_metadata.object_id.clone()),
            ledger_index: Some(3),
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let metadata = build_file_metadata(&agreement).expect("descriptor should rebuild");
        assert_eq!(metadata.file_id, real_metadata.file_id);
        assert_eq!(metadata.object_id, real_metadata.object_id);
        assert_eq!(metadata.nonce, real_metadata.nonce);
        assert_eq!(metadata.root, real_metadata.root);
        assert_eq!(metadata.padded_len, real_metadata.padded_len);
        assert_eq!(metadata.original_size, real_metadata.original_size);
        assert_eq!(metadata.filename, real_metadata.filename);
    }

    /// Without `object_id` the descriptor is incomplete, so the derived
    /// challenge id would differ from the contract's. Refuse rather than prove
    /// something unverifiable.
    #[test]
    fn build_file_metadata_requires_object_id() {
        let agreement = agreements::Model {
            agreement_id: "agr_no_object".into(),
            user_id: "user_1".into(),
            file_id: "file_1".into(),
            filename: "test.bin".into(),
            mime_type: "application/octet-stream".into(),
            original_size: 100,
            nodes: json!(["NODE-1"]),
            root: Some("0".repeat(64)),
            padded_len: Some(128),
            object_id: None,
            ledger_index: Some(0),
            downloaded: true,
            transaction_id: None,
            curation: json!({}),
            status: "ready".into(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        };

        let err = build_file_metadata(&agreement).unwrap_err();
        assert!(err.to_string().contains("missing object_id"));
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

        let seed = TEST_SEED_HEX;
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

    /// End-to-end run of the production proof path, at a contract slot that is
    /// not the one a local append would have picked.
    ///
    /// Every input comes from where it comes from in production: the ledger
    /// from [`rebuild_ledger`] (`add_files` at the absolute on-chain slot, not
    /// `add_file` at the next free local index), the descriptor from
    /// [`build_file_metadata`]. Two things are asserted:
    ///
    /// - the wire format is kontor-crypto's own `NPOR` container, which
    ///   `proof::from-bytes` parses — a postcard-encoded proof (what this node
    ///   used to emit) is rejected before verification even starts;
    /// - the proof actually *verifies* against the statement the verifier
    ///   rebuilds. Deserializing only proves the bytes are well-formed; since
    ///   `ledger_indices` are public inputs even for a single-file proof, a
    ///   file placed at the wrong slot would round-trip through `from_bytes`
    ///   just fine and still fail on chain.
    #[tokio::test]
    async fn a_real_proof_verifies_against_the_file_at_its_contract_slot() {
        /// Deliberately not 0: a ledger built by local insertion order would
        /// put this lone file at index 0 and the test would pass without ever
        /// exercising the absolute-slot path.
        const LEDGER_INDEX: i64 = 5;

        let file_bytes = b"real proof generator coverage";
        let filename = "real.bin";
        let (_prepared, prepared) =
            api::prepare_file(file_bytes, filename, PORTAL_FILE_NONCE).unwrap();

        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("real_proof_slot");
        stdfs::create_dir_all(&storage_dir).ok();

        AgreementFixture {
            filename: filename.to_string(),
            original_size: prepared.original_size as i64,
            root: Some(hex::encode(prepared.root.to_repr())),
            padded_len: Some(prepared.padded_len as i64),
            object_id: Some(prepared.object_id.clone()),
            ledger_index: Some(LEDGER_INDEX),
            downloaded: true,
            ..AgreementFixture::new("agr_real", &prepared.file_id)
        }
        .into_active_model()
        .insert(&db)
        .await
        .unwrap();

        let stats = rebuild_ledger(&db, &storage_dir).await.unwrap();
        assert_eq!(stats.placed, 1);
        let ledger = FileLedger::load(&storage_dir.join("ledger.bin")).unwrap();

        let agreement = Agreements::find().one(&db).await.unwrap().unwrap();
        let metadata = build_file_metadata(&agreement).unwrap();
        let challenge = CryptoChallenge::new(
            metadata.clone(),
            850_000,
            5,
            seed_to_field_element(TEST_SEED_HEX).unwrap(),
            prover_challenge_key(42),
        );

        let proof_bytes = RealProofGenerator
            .generate_proof(file_bytes, filename, &ledger, metadata, challenge.clone())
            .expect("real proof generator should succeed");

        assert_eq!(
            &proof_bytes[..4],
            b"NPOR",
            "proof must carry kontor-crypto's magic bytes"
        );
        let proof = kontor_crypto::Proof::from_bytes(&proof_bytes)
            .expect("the contract must be able to deserialize what we emit");

        assert!(
            PorSystem::new(&ledger)
                .verify(&proof, &[challenge])
                .expect("verification should not error"),
            "a proof built from the rebuilt ledger must satisfy the statement a \
             verifier reconstructs from the same slot"
        );

        stdfs::remove_dir_all(&storage_dir).ok();
    }

    #[tokio::test]
    async fn rejects_block_height_overflow() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("block_height_overflow");
        stdfs::create_dir_all(&storage_dir).ok();

        let file_id = "file_overflow";
        mock_agreement("agr_overflow", file_id)
            .insert(&db)
            .await
            .unwrap();
        stdfs::write(storage_dir.join(file_id), b"content").unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Negative block_height (i64) cannot be converted to u64.
        challenges::ActiveModel {
            challenge_id: Set("chal_overflow".into()),
            agreement_id: Set("agr_overflow".into()),
            block_height: Set(-1),
            challenge_count: Set(5),
            seed: Set(TEST_SEED_HEX.into()),
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
        assert!(
            result.is_ok(),
            "overall function should succeed even with one bad challenge"
        );

        // Challenge should still be active because block_height conversion failed
        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_overflow"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chal.status, "active");
    }

    #[tokio::test]
    async fn rejects_challenge_count_overflow() {
        let mock_server = MockServer::start().await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("challenge_count_overflow");
        stdfs::create_dir_all(&storage_dir).ok();

        let file_id = "file_count_overflow";
        mock_agreement("agr_count_overflow", file_id)
            .insert(&db)
            .await
            .unwrap();
        stdfs::write(storage_dir.join(file_id), b"content").unwrap();

        let ledger = FileLedger::new();
        ledger.save(&storage_dir.join("ledger.bin")).unwrap();

        // Negative challenge_count (i64) cannot be converted to usize.
        challenges::ActiveModel {
            challenge_id: Set("chal_count_overflow".into()),
            agreement_id: Set("agr_count_overflow".into()),
            block_height: Set(850000),
            challenge_count: Set(-5),
            seed: Set(TEST_SEED_HEX.into()),
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
        assert!(result.is_ok());

        let chal = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_count_overflow"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            chal.status, "active",
            "challenge should remain active when conversion fails"
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

        let seed = TEST_SEED_HEX;
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

    // ── Resubmission and ordering ───────────────────────────────────────────

    /// One downloaded agreement with its file and an empty ledger on disk, and
    /// a challenge on it per `(id, deadline, status)`.
    async fn setup_challenges(
        db: &DatabaseConnection,
        storage_dir: &Path,
        challenges_to_insert: &[(&str, i64, &str)],
    ) {
        mock_agreement("agr_retry", "file_retry")
            .insert(db)
            .await
            .unwrap();
        stdfs::write(storage_dir.join("file_retry"), b"bytes").unwrap();
        FileLedger::new()
            .save(&storage_dir.join("ledger.bin"))
            .unwrap();
        for (id, deadline, status) in challenges_to_insert {
            let mut challenge = sample_challenge(id, "agr_retry");
            challenge.deadline_height = Set(*deadline);
            challenge.status = Set((*status).to_string());
            challenge.insert(db).await.unwrap();
        }
    }

    async fn mount_accepting_proofs(mock_server: &MockServer) {
        Mock::given(method("POST"))
            .and(wiremock::matchers::path_regex("^/api/challenges/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "proved",
                "proof": null,
                "bls_signature": "sig"
            })))
            .mount(mock_server)
            .await;
    }

    async fn proved_paths(mock_server: &MockServer) -> Vec<String> {
        mock_server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    /// A cycle can run out of time or gas part way; the challenge that expires
    /// soonest is the one to have proved first.
    #[tokio::test]
    async fn challenges_are_proved_nearest_deadline_first() {
        let mock_server = MockServer::start().await;
        mount_accepting_proofs(&mock_server).await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("deadline_order");
        stdfs::create_dir_all(&storage_dir).ok();
        setup_challenges(
            &db,
            &storage_dir,
            &[
                ("chal_late", 900, "active"),
                ("chal_soon", 800, "active"),
                ("chal_mid", 850, "active"),
            ],
        )
        .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &StorageBackend::local(),
            &storage_dir,
            &MockProofGenerator,
        )
        .await
        .unwrap();

        assert_eq!(
            proved_paths(&mock_server).await,
            vec![
                "/api/challenges/chal_soon",
                "/api/challenges/chal_mid",
                "/api/challenges/chal_late"
            ]
        );
    }

    /// Statuses other than `active` — including ones this node has never
    /// heard of, such as `settled` — are left alone without an error.
    #[tokio::test]
    async fn non_active_and_unknown_statuses_are_not_proved() {
        let mock_server = MockServer::start().await;
        mount_accepting_proofs(&mock_server).await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("unknown_status");
        stdfs::create_dir_all(&storage_dir).ok();
        setup_challenges(
            &db,
            &storage_dir,
            &[
                ("chal_settled", 800, "settled"),
                ("chal_failed", 800, "failed"),
                ("chal_proved", 800, "proved"),
                ("chal_brand_new_status", 800, "something-else"),
            ],
        )
        .await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        compute_and_submit_proofs_with_generator(
            &client,
            &db,
            &StorageBackend::local(),
            &storage_dir,
            &MockProofGenerator,
        )
        .await
        .unwrap();
        assert!(proved_paths(&mock_server).await.is_empty());
    }

    /// The Portal hands a rejected challenge back as `active`. The node proves
    /// it again — but not in the same breath: a resubmission waits out the
    /// backoff, and the memory of the first submission is what makes it wait.
    #[tokio::test]
    async fn a_challenge_back_to_active_is_resubmitted_only_after_the_backoff() {
        let mock_server = MockServer::start().await;
        mount_accepting_proofs(&mock_server).await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("resubmit");
        stdfs::create_dir_all(&storage_dir).ok();
        setup_challenges(&db, &storage_dir, &[("chal_back", 800, "active")]).await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let retries = ProofRetries::default();
        let backend = StorageBackend::local();
        let run = || {
            prove_active_challenges(
                &client,
                &db,
                &backend,
                &storage_dir,
                &MockProofGenerator,
                &retries,
            )
        };
        run().await.unwrap();
        assert_eq!(proved_paths(&mock_server).await.len(), 1);

        // What the challenge sync does when the Portal reports it active again.
        challenges::ActiveModel {
            challenge_id: sea_orm::ActiveValue::Unchanged("chal_back".into()),
            status: Set(STATUS_ACTIVE.into()),
            ..Default::default()
        }
        .update(&db)
        .await
        .unwrap();

        run().await.unwrap();
        assert_eq!(
            proved_paths(&mock_server).await.len(),
            1,
            "still inside the backoff: not resubmitted yet"
        );

        // Once the backoff has passed, it goes out again.
        assert_eq!(
            retries.check("chal_back", Instant::now() + resubmit_delay(1)),
            RetryCheck::Prove
        );
    }

    #[tokio::test]
    async fn a_challenge_out_of_submissions_is_not_proved_again() {
        let mock_server = MockServer::start().await;
        mount_accepting_proofs(&mock_server).await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("give_up");
        stdfs::create_dir_all(&storage_dir).ok();
        setup_challenges(&db, &storage_dir, &[("chal_hopeless", 800, "active")]).await;

        let retries = ProofRetries::default();
        let long_ago = Instant::now();
        for _ in 0..MAX_PROOF_SUBMISSIONS {
            retries.record_submission("chal_hopeless", long_ago);
        }

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        prove_active_challenges(
            &client,
            &db,
            &StorageBackend::local(),
            &storage_dir,
            &MockProofGenerator,
            &retries,
        )
        .await
        .unwrap();
        assert!(proved_paths(&mock_server).await.is_empty());
    }

    /// A proof the Portal turned down counts as a submission; a failure before
    /// anything was sent (here, no file on disk) does not, so the challenge is
    /// free to be tried the next cycle once the cause is fixed.
    #[tokio::test]
    async fn only_proofs_that_reached_the_portal_count() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/challenges/chal_refused"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad proof"))
            .mount(&mock_server)
            .await;
        let db = setup_in_memory_db().await;
        let storage_dir = unique_storage_dir("counts");
        stdfs::create_dir_all(&storage_dir).ok();
        setup_challenges(&db, &storage_dir, &[("chal_refused", 800, "active")]).await;

        let client = create_authenticated_client(&mock_server, storage_dir.clone()).await;
        let retries = ProofRetries::default();
        prove_active_challenges(
            &client,
            &db,
            &StorageBackend::local(),
            &storage_dir,
            &MockProofGenerator,
            &retries,
        )
        .await
        .unwrap();
        assert_eq!(
            retries.check("chal_refused", Instant::now()),
            RetryCheck::Wait
        );

        stdfs::remove_file(storage_dir.join("file_retry")).unwrap();
        let fresh = ProofRetries::default();
        prove_active_challenges(
            &client,
            &db,
            &StorageBackend::local(),
            &storage_dir,
            &MockProofGenerator,
            &fresh,
        )
        .await
        .unwrap();
        assert_eq!(
            fresh.check("chal_refused", Instant::now()),
            RetryCheck::Prove
        );
    }

    #[test]
    fn resubmissions_back_off_and_stop_at_the_cap() {
        assert_eq!(resubmit_delay(1), Duration::from_secs(60));
        assert_eq!(resubmit_delay(2), Duration::from_secs(120));
        assert_eq!(resubmit_delay(4), Duration::from_secs(480));
        assert_eq!(resubmit_delay(5), Duration::from_secs(960));
        assert_eq!(resubmit_delay(40), RESUBMIT_MAX_DELAY);

        let retries = ProofRetries::default();
        let t0 = Instant::now();
        assert_eq!(retries.check("c", t0), RetryCheck::Prove);
        retries.record_submission("c", t0);
        assert_eq!(
            retries.check("c", t0 + Duration::from_secs(59)),
            RetryCheck::Wait
        );
        assert_eq!(
            retries.check("c", t0 + Duration::from_secs(60)),
            RetryCheck::Prove
        );

        for _ in 1..MAX_PROOF_SUBMISSIONS {
            retries.record_submission("c", t0);
        }
        let much_later = t0 + Duration::from_secs(3600);
        assert_eq!(
            retries.check("c", much_later),
            RetryCheck::GiveUp { announce: true }
        );
        assert_eq!(
            retries.check("c", much_later),
            RetryCheck::GiveUp { announce: false },
            "said once, not every cycle"
        );

        // Forgotten a day after it stops being active.
        retries.prune(&[], t0 + Duration::from_secs(24 * 3600));
        assert_eq!(retries.check("c", much_later), RetryCheck::Prove);
    }
}
