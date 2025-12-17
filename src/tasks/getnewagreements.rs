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
    let page = portal_client
        .get_agreements_to_sign()
        .await
        .context("fetching agreements to sign failed")?;

    if page.agreements.is_empty() {
        return Ok(());
    }

    let requested_ids: Vec<String> = page
        .agreements
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

    let new_models: Vec<agreements::ActiveModel> = page
        .agreements
        .iter()
        .filter(|agreement| !existing_ids.contains(&agreement.agreement_id))
        .map(agreement_to_active_model)
        .collect::<Result<Vec<_>>>()?;

    if new_models.is_empty() {
        return Ok(());
    }

    Agreements::insert_many(new_models)
        .exec(database)
        .await
        .context("failed to insert new agreements")?;

    Ok(())
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
        transaction_id: Set(agreement.transaction_id.clone()),
        curation: Set(agreement.curation.clone()),
        status: Set(agreement.status.clone()),
        created_at: Set(created_at),
    })
}
