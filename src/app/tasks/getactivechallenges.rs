use super::{load_existing_ids, sync_new_items, ITEM_TYPE_CHALLENGES, STATUS_FAILED};
use crate::clients::portal::Challenge;
use crate::clients::PortalClient;
use crate::entities::{challenges, prelude::Challenges};
use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset};
use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tracing::{info, warn};

/// Aggregate counters returned by `update_existing_challenge_metadata`.
#[derive(Debug, Default, Clone, Copy)]
struct ReconcileCounts {
    updated: usize,
    transitioned_to_failed: usize,
}

/// Reconcile local challenge state with Portal.
///
/// Returns the number of challenges that transitioned to the `failed` status
/// during this pass. Callers can use this to trigger a nonce resync.
pub async fn sync_active_challenges(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
) -> Result<usize> {
    let challenges = portal_client
        .get_all_node_challenges()
        .await
        .context("fetching node challenges failed")?;

    let requested_ids: Vec<String> = challenges
        .iter()
        .map(|challenge| challenge.challenge_id.clone())
        .collect();

    let existing_ids = load_existing_ids::<Challenges, _>(
        database,
        challenges::Column::ChallengeId,
        &requested_ids,
        |model| model.challenge_id,
    )
    .await?;

    let to_update: Vec<Challenge> = challenges
        .iter()
        .filter(|c| existing_ids.contains(&c.challenge_id))
        .cloned()
        .collect();

    sync_new_items(
        challenges,
        existing_ids,
        ITEM_TYPE_CHALLENGES,
        |c| c.challenge_id.clone(),
        challenge_to_active_model,
        database,
    )
    .await?;

    let counts = update_existing_challenge_metadata(&to_update, database)
        .await
        .context("updating existing challenge statuses")?;

    Ok(counts.transitioned_to_failed)
}

/// Update mutable fields (`status`, `proof`, `bls_signature`, `updated_at`) of
/// challenges already present locally whose remote representation has changed.
///
/// Returns the number of challenges that were updated together with the
/// number of challenges that transitioned to the `failed` status.
async fn update_existing_challenge_metadata(
    remote_challenges: &[Challenge],
    database: &DatabaseConnection,
) -> Result<ReconcileCounts> {
    let mut counts = ReconcileCounts::default();
    if remote_challenges.is_empty() {
        return Ok(counts);
    }

    let ids: Vec<String> = remote_challenges
        .iter()
        .map(|c| c.challenge_id.clone())
        .collect();
    let local_models = Challenges::find()
        .filter(challenges::Column::ChallengeId.is_in(ids))
        .all(database)
        .await
        .context("loading existing challenges for status reconciliation")?;

    for local in local_models {
        let Some(remote) = remote_challenges
            .iter()
            .find(|c| c.challenge_id == local.challenge_id)
        else {
            continue;
        };

        let remote_updated_at: DateTimeWithTimeZone =
            DateTime::<FixedOffset>::parse_from_rfc3339(&remote.updated_at)
                .with_context(|| format!("invalid updated_at timestamp {}", remote.updated_at))?;

        let status_changed = remote.status != local.status;
        let proof_changed = remote.proof != local.proof;
        let signature_changed = remote.bls_signature != local.bls_signature;
        let updated_at_changed = remote_updated_at != local.updated_at;

        if !status_changed && !proof_changed && !signature_changed && !updated_at_changed {
            continue;
        }

        if status_changed {
            if remote.status == STATUS_FAILED {
                warn!(
                    "challenge {} status: {} -> {}",
                    local.challenge_id, local.status, remote.status
                );
                if local.status != STATUS_FAILED {
                    counts.transitioned_to_failed += 1;
                }
            } else {
                info!(
                    "challenge {} status: {} -> {}",
                    local.challenge_id, local.status, remote.status
                );
            }
        }

        let mut active = challenges::ActiveModel {
            challenge_id: ActiveValue::Unchanged(local.challenge_id.clone()),
            ..Default::default()
        };
        if status_changed {
            active.status = Set(remote.status.clone());
        }
        if proof_changed {
            active.proof = Set(remote.proof.clone());
        }
        if signature_changed {
            active.bls_signature = Set(remote.bls_signature.clone());
        }
        if updated_at_changed {
            active.updated_at = Set(remote_updated_at);
        }

        Challenges::update(active)
            .exec(database)
            .await
            .context("updating challenge metadata")?;
        counts.updated += 1;
    }

    Ok(counts)
}

fn challenge_to_active_model(
    challenge: &crate::clients::portal::Challenge,
) -> Result<challenges::ActiveModel> {
    let created_at: DateTimeWithTimeZone =
        DateTime::<FixedOffset>::parse_from_rfc3339(&challenge.created_at)
            .with_context(|| format!("invalid created_at timestamp {}", challenge.created_at))?;

    let updated_at: DateTimeWithTimeZone =
        DateTime::<FixedOffset>::parse_from_rfc3339(&challenge.updated_at)
            .with_context(|| format!("invalid updated_at timestamp {}", challenge.updated_at))?;

    let block_height: i64 = challenge
        .block_height
        .try_into()
        .context("block_height does not fit into i64")?;

    let challenge_count: i64 = challenge
        .challenge_count
        .try_into()
        .context("challenge_count does not fit into i64")?;

    let deadline_height: i64 = challenge
        .deadline_height
        .try_into()
        .context("deadline_height does not fit into i64")?;

    Ok(challenges::ActiveModel {
        challenge_id: Set(challenge.challenge_id.clone()),
        agreement_id: Set(challenge.agreement_id.clone()),
        block_height: Set(block_height),
        challenge_count: Set(challenge_count),
        seed: Set(challenge.seed.clone()),
        prover_id: Set(challenge.prover_id.clone()),
        deadline_height: Set(deadline_height),
        status: Set(challenge.status.clone()),
        proof: Set(challenge.proof.clone()),
        bls_signature: Set(challenge.bls_signature.clone()),
        created_at: Set(created_at),
        updated_at: Set(updated_at),
    })
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::clients::portal::Challenge;
    use crate::crypto::BlsKeyPair;
    use crate::entities::prelude::Challenges;
    use crate::testutils::{setup_challenges_db, unique_storage_dir};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_challenge(id: &str) -> Challenge {
        Challenge {
            challenge_id: id.to_string(),
            agreement_id: "AGREEMENT-123".to_string(),
            block_height: 850000,
            challenge_count: 5,
            seed: "0102030405060708".to_string(),
            prover_id: "NODE-test".to_string(),
            deadline_height: 850100,
            status: "active".to_string(),
            proof: None,
            bls_signature: None,
            created_at: "2025-01-15T10:30:00Z".to_string(),
            updated_at: "2025-01-15T10:30:00Z".to_string(),
            transaction_id: None,
            txid: None,
            tx_block_height: None,
            tx_block_time: None,
            tx_status: None,
        }
    }

    fn challenge_json(challenge: &Challenge) -> serde_json::Value {
        json!({
            "challenge_id": challenge.challenge_id.clone(),
            "agreement_id": challenge.agreement_id.clone(),
            "block_height": challenge.block_height,
            "challenge_count": challenge.challenge_count,
            "seed": challenge.seed.clone(),
            "prover_id": challenge.prover_id.clone(),
            "deadline_height": challenge.deadline_height,
            "status": challenge.status.clone(),
            "proof": challenge.proof.clone(),
            "bls_signature": challenge.bls_signature.clone(),
            "created_at": challenge.created_at.clone(),
            "updated_at": challenge.updated_at.clone(),
        })
    }

    #[tokio::test]
    async fn returns_ok_when_no_active_challenges() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "node_id": "NODE-test",
                "challenges": []
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("challenges_empty"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let result = sync_active_challenges(&client, &db).await;

        assert!(result.is_ok(), "empty pages should succeed");
        let count = Challenges::find().count(&db).await.unwrap();
        assert_eq!(count, 0, "no challenges should be inserted");
    }

    #[tokio::test]
    async fn inserts_only_missing_challenges() {
        let mock_server = MockServer::start().await;
        let existing_challenge = sample_challenge("chal_existing");
        let new_challenge = sample_challenge("chal_new");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 2,
                "node_id": "NODE-test",
                "challenges": [
                    challenge_json(&existing_challenge),
                    challenge_json(&new_challenge)
                ]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        // Seed an existing challenge that should not be duplicated.
        let seeded = challenges::ActiveModel {
            challenge_id: Set("chal_existing".into()),
            agreement_id: Set("AGREEMENT-existing".into()),
            block_height: Set(800000),
            challenge_count: Set(3),
            seed: Set("aabbccdd".into()),
            prover_id: Set("NODE-existing".into()),
            deadline_height: Set(800100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2024-02-01T12:00:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2024-02-01T12:00:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("mixed"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        sync_active_challenges(&client, &db).await.unwrap();

        let stored = Challenges::find().all(&db).await.unwrap();
        assert_eq!(stored.len(), 2, "should contain seeded and new challenges");

        let inserted = stored
            .iter()
            .find(|model| model.challenge_id == "chal_new")
            .expect("new challenge should be inserted");
        assert_eq!(inserted.agreement_id, new_challenge.agreement_id);
        assert_eq!(inserted.block_height, 850000);
        assert_eq!(inserted.challenge_count, 5);
        assert_eq!(inserted.seed, new_challenge.seed);
        assert_eq!(inserted.prover_id, new_challenge.prover_id);
        assert_eq!(inserted.deadline_height, 850100);
        assert_eq!(inserted.status, "active");
        assert!(inserted.proof.is_none());
        assert!(inserted.bls_signature.is_none());
    }

    #[tokio::test]
    async fn returns_early_when_all_challenges_already_stored() {
        let mock_server = MockServer::start().await;
        let challenge = sample_challenge("chal_existing");

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "node_id": "NODE-test",
                "challenges": [challenge_json(&challenge)]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        let existing = challenges::ActiveModel {
            challenge_id: Set(challenge.challenge_id.clone()),
            agreement_id: Set(challenge.agreement_id.clone()),
            block_height: Set(challenge.block_height as i64),
            challenge_count: Set(challenge.challenge_count as i64),
            seed: Set(challenge.seed.clone()),
            prover_id: Set(challenge.prover_id.clone()),
            deadline_height: Set(challenge.deadline_height as i64),
            status: Set(challenge.status.clone()),
            proof: Set(challenge.proof.clone()),
            bls_signature: Set(challenge.bls_signature.clone()),
            created_at: Set(DateTime::parse_from_rfc3339(&challenge.created_at).unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339(&challenge.updated_at).unwrap()),
        };
        existing.insert(&db).await.unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("all_existing"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        sync_active_challenges(&client, &db).await.unwrap();

        let count = Challenges::find().count(&db).await.unwrap();
        assert_eq!(count, 1, "no additional inserts should occur");
    }

    #[test]
    fn challenge_to_active_model_rejects_invalid_created_at() {
        let challenge = Challenge {
            created_at: "invalid".to_string(),
            ..sample_challenge("chal_bad_ts")
        };

        let err = challenge_to_active_model(&challenge).unwrap_err();
        assert!(
            err.to_string().contains("invalid created_at timestamp"),
            "should surface timestamp parsing failures"
        );
    }

    #[test]
    fn challenge_to_active_model_rejects_invalid_updated_at() {
        let challenge = Challenge {
            updated_at: "invalid".to_string(),
            ..sample_challenge("chal_bad_updated")
        };

        let err = challenge_to_active_model(&challenge).unwrap_err();
        assert!(
            err.to_string().contains("invalid updated_at timestamp"),
            "should surface timestamp parsing failures"
        );
    }

    #[tokio::test]
    async fn updates_existing_challenge_status_when_portal_marks_failed() {
        let mock_server = MockServer::start().await;
        let mut remote = sample_challenge("chal_fail");
        remote.status = "failed".into();
        remote.updated_at = "2025-01-16T11:00:00Z".into();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "challenges": [challenge_json(&remote)]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        let seeded = challenges::ActiveModel {
            challenge_id: Set("chal_fail".into()),
            agreement_id: Set("AGREEMENT-123".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set("0102030405060708".into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("challenges_status_failed"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );

        sync_active_challenges(&client, &db).await.unwrap();

        let stored = Challenges::find()
            .filter(challenges::Column::ChallengeId.eq("chal_fail"))
            .one(&db)
            .await
            .unwrap()
            .expect("challenge should exist");
        assert_eq!(
            stored.status, "failed",
            "challenge status must transition from active to failed after reconcile"
        );
        assert_eq!(
            stored.proof, None,
            "proof should remain None when remote does not provide one"
        );
        assert_eq!(
            stored.bls_signature, None,
            "bls_signature should remain None when remote does not provide one"
        );
        assert_eq!(
            stored.block_height, 850000,
            "block_height must be preserved"
        );
        assert_eq!(stored.seed, "0102030405060708", "seed must be preserved");
        assert_eq!(
            stored.created_at,
            DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap(),
            "created_at must not be touched by reconcile"
        );
    }

    #[tokio::test]
    async fn transition_to_failed_is_counted() {
        let mock_server = MockServer::start().await;
        let mut remote = sample_challenge("chal_count_fail");
        remote.status = "failed".into();
        remote.updated_at = "2025-01-16T11:00:00Z".into();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "challenges": [challenge_json(&remote)]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        let seeded = challenges::ActiveModel {
            challenge_id: Set("chal_count_fail".into()),
            agreement_id: Set("AGREEMENT-123".into()),
            block_height: Set(850000),
            challenge_count: Set(5),
            seed: Set("0102030405060708".into()),
            prover_id: Set("NODE-test".into()),
            deadline_height: Set(850100),
            status: Set("active".into()),
            proof: Set(None),
            bls_signature: Set(None),
            created_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
            updated_at: Set(DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("challenges_count_failed"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );

        let failed_count = sync_active_challenges(&client, &db).await.unwrap();
        assert_eq!(
            failed_count, 1,
            "transition from active to failed should be counted once"
        );
    }

    async fn sync_with_remote(remote: Vec<Challenge>, local_status: &str) -> (String, usize) {
        let mock_server = MockServer::start().await;
        let total = remote.len();
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/challenges"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": total,
                "challenges": remote.iter().map(challenge_json).collect::<Vec<_>>()
            })))
            .mount(&mock_server)
            .await;

        let db = setup_challenges_db().await;
        let mut local = challenge_to_active_model(&sample_challenge("chal_1")).unwrap();
        local.status = Set(local_status.to_string());
        local.insert(&db).await.unwrap();

        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("challenge_status"),
            Arc::new(BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        let failed = sync_active_challenges(&client, &db).await.unwrap();
        let stored = Challenges::find_by_id("chal_1")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        (stored.status, failed)
    }

    /// Since the staking upgrade a rejected proof leaves the challenge open,
    /// and the Portal reports it `active` again. Mirroring that is what puts it
    /// back in front of the prover.
    #[tokio::test]
    async fn a_proved_challenge_the_portal_reopens_becomes_active_again() {
        let mut remote = sample_challenge("chal_1");
        remote.status = "active".into();
        remote.updated_at = "2025-01-15T11:00:00Z".into();
        let (status, failed) = sync_with_remote(vec![remote], "proved").await;
        assert_eq!(status, "active");
        assert_eq!(failed, 0);
    }

    /// A status the node does not know is stored as it is, without an error and
    /// without counting as a failure; it is simply not `active`.
    #[tokio::test]
    async fn an_unknown_remote_status_is_mirrored_without_error() {
        let mut remote = sample_challenge("chal_1");
        remote.status = "settled".into();
        let (status, failed) = sync_with_remote(vec![remote], "proved").await;
        assert_eq!(status, "settled");
        assert_eq!(failed, 0, "only `failed` triggers the nonce resync");
    }
}
