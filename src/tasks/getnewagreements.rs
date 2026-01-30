use super::{sync_new_items, ITEM_TYPE_AGREEMENTS};
use crate::clients::PortalClient;
use crate::entities::{agreements, prelude::Agreements};
use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset};
use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::JsonValue;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::collections::HashSet;

pub async fn sync_ready_agreements(
    portal_client: &PortalClient,
    database: &DatabaseConnection,
) -> Result<()> {
    let agreements = portal_client
        .get_new_agreements()
        .await
        .context("fetching new agreements failed")?;

    let requested_ids: Vec<String> = agreements
        .iter()
        .map(|agreement| agreement.agreement_id.clone())
        .collect();

    let existing_ids: HashSet<String> = Agreements::find()
        .filter(agreements::Column::AgreementId.is_in(requested_ids.clone()))
        .all(database)
        .await?
        .into_iter()
        .map(|model| model.agreement_id)
        .collect();

    sync_new_items(
        agreements,
        existing_ids,
        ITEM_TYPE_AGREEMENTS,
        |a| a.agreement_id.clone(),
        agreement_to_active_model,
        database,
    )
    .await
}

fn agreement_to_active_model(
    agreement: &crate::clients::portal::Agreement,
) -> Result<agreements::ActiveModel> {
    let nodes_json = JsonValue::Array(
        agreement
            .nodes
            .iter()
            .cloned()
            .map(JsonValue::String)
            .collect(),
    );

    let created_at: DateTimeWithTimeZone =
        DateTime::<FixedOffset>::parse_from_rfc3339(&agreement.created_at)
            .with_context(|| format!("invalid created_at timestamp {}", agreement.created_at))?;

    let original_size: i64 = agreement
        .original_size
        .try_into()
        .context("original_size does not fit into i64")?;

    Ok(agreements::ActiveModel {
        agreement_id: Set(agreement.agreement_id.clone()),
        user_id: Set(agreement.user_id.clone()),
        file_id: Set(agreement.file_id.clone()),
        filename: Set(agreement.filename.clone()),
        mime_type: Set(agreement.mime_type.clone()),
        original_size: Set(original_size),
        nodes: Set(nodes_json),
        root: Set(None),
        padded_len: Set(None),
        downloaded: Set(false),
        transaction_id: Set(agreement.transaction_id.clone()),
        curation: Set(agreement.curation.clone()),
        status: Set(agreement.status.clone()),
        created_at: Set(created_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::portal::Agreement;
    use crate::entities::prelude::Agreements;
    use crate::testutils::{setup_agreements_db, unique_storage_dir};
    use chrono::DateTime;
    use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_agreement(id: &str) -> Agreement {
        Agreement {
            agreement_id: id.to_string(),
            user_id: "user_1".to_string(),
            file_id: "FILE-123".to_string(),
            filename: "contract.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            original_size: 1_024,
            nodes: vec!["NODE-1".to_string()],
            transaction_id: None,
            curation: json!({"notes": "ok"}),
            status: "new".to_string(),
            created_at: "2024-01-15T10:30:00Z".to_string(),
        }
    }

    fn agreement_json(agreement: &Agreement) -> serde_json::Value {
        json!({
            "agreement_id": agreement.agreement_id.clone(),
            "user_id": agreement.user_id.clone(),
            "file_id": agreement.file_id.clone(),
            "filename": agreement.filename.clone(),
            "mime_type": agreement.mime_type.clone(),
            "original_size": agreement.original_size,
            "nodes": agreement.nodes.clone(),
            "transaction_id": agreement.transaction_id.clone(),
            "curation": agreement.curation.clone(),
            "status": agreement.status.clone(),
            "created_at": agreement.created_at.clone(),
        })
    }

    #[tokio::test]
    async fn returns_ok_when_no_ready_agreements() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let db = setup_agreements_db().await;
        let result = sync_ready_agreements(
            &PortalClient::new(mock_server.uri(), unique_storage_dir("empty")),
            &db,
        )
        .await;

        assert!(result.is_ok(), "empty pages should succeed");
        let count = Agreements::find().count(&db).await.unwrap();
        assert_eq!(count, 0, "no agreements should be inserted");
    }

    #[tokio::test]
    async fn inserts_only_missing_agreements() {
        let mock_server = MockServer::start().await;
        let existing_agreement = sample_agreement("AGREEMENT-existing");
        let new_agreement = sample_agreement("AGREEMENT-new");

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 2,
                "agreements": [
                    agreement_json(&existing_agreement),
                    agreement_json(&new_agreement)
                ]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_agreements_db().await;
        // Seed an existing agreement that should not be duplicated.
        let seeded = agreements::ActiveModel {
            agreement_id: Set("AGREEMENT-existing".into()),
            user_id: Set("user_existing".into()),
            file_id: Set("FILE-existing".into()),
            filename: Set("existing.pdf".into()),
            mime_type: Set("application/pdf".into()),
            original_size: Set(555),
            nodes: Set(json!(["NODE-existing"])),
            root: Set(None),
            padded_len: Set(None),
            downloaded: Set(false),
            transaction_id: Set(Some("TX-existing".into())),
            curation: Set(json!({"curated": true})),
            status: Set("ready".into()),
            created_at: Set(DateTime::parse_from_rfc3339("2024-02-01T12:00:00Z").unwrap()),
        };
        seeded.insert(&db).await.unwrap();

        sync_ready_agreements(
            &PortalClient::new(mock_server.uri(), unique_storage_dir("mixed")),
            &db,
        )
        .await
        .unwrap();

        let stored = Agreements::find().all(&db).await.unwrap();
        assert_eq!(stored.len(), 2, "should contain seeded and new agreements");

        let inserted = stored
            .iter()
            .find(|model| model.agreement_id == "AGREEMENT-new")
            .expect("new agreement should be inserted");
        assert_eq!(inserted.user_id, new_agreement.user_id);
        assert_eq!(inserted.file_id, new_agreement.file_id);
        assert_eq!(inserted.filename, new_agreement.filename);
        assert_eq!(inserted.mime_type, new_agreement.mime_type);
        assert_eq!(inserted.original_size, 1_024);
        assert_eq!(inserted.nodes, json!(["NODE-1"]));
        assert!(inserted.transaction_id.is_none());
        assert_eq!(inserted.curation, json!({"notes": "ok"}));
        assert_eq!(inserted.status, "new");
        assert!(
            !inserted.downloaded,
            "new agreements should start as not downloaded"
        );
        assert_eq!(
            inserted.created_at,
            DateTime::parse_from_rfc3339(&new_agreement.created_at).unwrap()
        );
    }

    #[tokio::test]
    async fn returns_early_when_all_agreements_already_stored() {
        let mock_server = MockServer::start().await;
        let agreement = sample_agreement("AGREEMENT-existing");

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "agreements": [agreement_json(&agreement)]
            })))
            .mount(&mock_server)
            .await;

        let db = setup_agreements_db().await;
        let existing = agreements::ActiveModel {
            agreement_id: Set(agreement.agreement_id.clone()),
            user_id: Set(agreement.user_id.clone()),
            file_id: Set(agreement.file_id.clone()),
            filename: Set(agreement.filename.clone()),
            mime_type: Set(agreement.mime_type.clone()),
            original_size: Set(agreement.original_size as i64),
            nodes: Set(json!(agreement.nodes)),
            root: Set(None),
            padded_len: Set(None),
            downloaded: Set(false),
            transaction_id: Set(agreement.transaction_id.clone()),
            curation: Set(agreement.curation.clone()),
            status: Set(agreement.status.clone()),
            created_at: Set(DateTime::parse_from_rfc3339(&agreement.created_at).unwrap()),
        };
        existing.insert(&db).await.unwrap();

        sync_ready_agreements(
            &PortalClient::new(mock_server.uri(), unique_storage_dir("all_existing")),
            &db,
        )
        .await
        .unwrap();

        let count = Agreements::find().count(&db).await.unwrap();
        assert_eq!(count, 1, "no additional inserts should occur");
    }

    #[test]
    fn agreement_to_active_model_rejects_invalid_timestamp() {
        let agreement = Agreement {
            created_at: "invalid".to_string(),
            ..sample_agreement("AGREEMENT-bad-ts")
        };

        let err = agreement_to_active_model(&agreement).unwrap_err();
        assert!(
            err.to_string().contains("invalid created_at timestamp"),
            "should surface timestamp parsing failures"
        );
    }

    #[test]
    fn agreement_to_active_model_rejects_original_size_overflow() {
        let agreement = Agreement {
            original_size: u64::MAX,
            ..sample_agreement("AGREEMENT-big-size")
        };

        let err = agreement_to_active_model(&agreement).unwrap_err();
        assert!(
            err.to_string()
                .contains("original_size does not fit into i64"),
            "oversized original_size should be rejected"
        );
    }
}
