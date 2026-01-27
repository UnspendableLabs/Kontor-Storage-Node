#![allow(dead_code)] // Temporary until wired into daemon loop.

use crate::clients::PortalClient;
use crate::entities::{challenges, prelude::Challenges};
use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset};
use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::collections::HashSet;
use tracing::info;

pub async fn sync_active_challenges(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
) -> Result<()> {
    let page = portal_client
        .get_node_challenges()
        .await
        .context("fetching active challenges failed")?;

    if page.challenges.is_empty() {
        info!("No active challenges found");
        return Ok(());
    }

    let requested_ids: Vec<String> = page
        .challenges
        .iter()
        .map(|challenge| challenge.challenge_id.clone())
        .collect();

    let existing_ids: HashSet<String> = Challenges::find()
        .filter(challenges::Column::ChallengeId.is_in(requested_ids.clone()))
        .all(database)
        .await?
        .into_iter()
        .map(|model| model.challenge_id)
        .collect();

    let new_models: Vec<challenges::ActiveModel> = page
        .challenges
        .iter()
        .filter(|challenge| !existing_ids.contains(&challenge.challenge_id))
        .map(challenge_to_active_model)
        .collect::<Result<Vec<_>>>()?;

    if new_models.is_empty() {
        info!("All {} challenges already stored", page.challenges.len());
        return Ok(());
    }

    Challenges::insert_many(new_models.clone())
        .exec(database)
        .await
        .context("failed to insert new challenges")?;

    info!("Inserted {} new challenges", new_models.len());

    Ok(())
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
    use super::*;
    use crate::bls::BlsKeyPair;
    use crate::clients::portal::Challenge;
    use crate::entities::prelude::Challenges;
    use chrono::DateTime;
    use sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, DatabaseBackend, EntityTrait, PaginatorTrait,
        Schema, Set,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_storage_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kontor_sync_active_challenges_{name}_{id}"))
    }

    async fn setup_in_memory_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DatabaseBackend::Sqlite);
        let stmt = schema.create_table_from_entity(Challenges);
        db.execute(&stmt).await.unwrap();
        db
    }

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
            .and(query_param("status", "active"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "node_id": "NODE-test",
                "challenges": []
            })))
            .mount(&mock_server)
            .await;

        let db = setup_in_memory_db().await;
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            unique_storage_dir("empty"),
            keypair,
            "NODE-test",
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
            .and(query_param("status", "active"))
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

        let db = setup_in_memory_db().await;
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
            .and(query_param("status", "active"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "node_id": "NODE-test",
                "challenges": [challenge_json(&challenge)]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_in_memory_db().await;
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
}
