pub mod computeproofs;
pub mod downloadagreements;
pub mod getactivechallenges;
pub mod getnewagreements;
pub mod reconcile;

use anyhow::{Context, Result};

/// Status constants for challenges and agreements.
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_PROVED: &str = "proved";
pub const STATUS_FAILED: &str = "failed";
#[allow(dead_code)]
pub const STATUS_RESOLVED: &str = "resolved";
#[allow(dead_code)]
pub const STATUS_SUBMITTED: &str = "submitted";
#[allow(dead_code)]
pub const STATUS_CONFIRMED: &str = "confirmed";
#[allow(dead_code)]
pub const STATUS_READY: &str = "ready";
#[allow(dead_code)]
pub const STATUS_PENDING: &str = "pending";

/// Item type names for logging and sync operations.
pub const ITEM_TYPE_CHALLENGES: &str = "challenges";
pub const ITEM_TYPE_AGREEMENTS: &str = "agreements";

/// Decode a hex-encoded Poseidon field element from its 32-byte canonical
/// little-endian representation.
///
/// `what` names the value for error messages (e.g. `"root"`). Non-canonical
/// encodings are rejected rather than reduced: these values mirror on-chain
/// commitments, so anything the contract could not have produced is a bug or
/// corruption, not something to silently normalize.
pub fn field_from_hex(hex_str: &str, what: &str) -> Result<kontor_crypto::FieldElement> {
    use ff::PrimeField;

    let bytes = hex::decode(hex_str).with_context(|| format!("decoding {what} hex"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} hex is not 32 bytes"))?;

    kontor_crypto::FieldElement::from_repr(array.into())
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("invalid {what} field element"))
}
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, InsertResult, QueryFilter,
    TryInsertResult,
};
use std::collections::HashSet;
use tracing::info;

/// Load the subset of `ids` that already exist in the database for entity `E`,
/// using `column` as the column to filter against and `extract` to pull the
/// string identifier out of each loaded model.
///
/// Short-circuits to an empty set when `ids` is empty; this avoids issuing a
/// `WHERE col IN ()` query, which is invalid on some SQL backends.
pub async fn load_existing_ids<E, C>(
    database: &DatabaseConnection,
    column: C,
    ids: &[String],
    extract: impl Fn(<E as EntityTrait>::Model) -> String,
) -> Result<HashSet<String>>
where
    E: EntityTrait,
    C: ColumnTrait + Copy,
{
    if ids.is_empty() {
        return Ok(HashSet::new());
    }
    Ok(E::find()
        .filter(column.is_in(ids.to_vec()))
        .all(database)
        .await
        .context("loading existing IDs")?
        .into_iter()
        .map(extract)
        .collect())
}

/// Helper for syncing items from an API to the database.
///
/// This encapsulates the common sync pattern:
/// 1. Check if items list is empty
/// 2. Extract IDs from fetched items
/// 3. Query existing IDs from database
/// 4. Filter to only new items
/// 5. Convert and insert new items
///
/// # Type Parameters
/// - `T`: The API item type
/// - `M`: The database model type
/// - `A`: The database active model type
/// - `E`: The SeaORM entity type
///
/// # Arguments
/// - `items`: The fetched API items
/// - `existing_ids`: Set of IDs that already exist in the database
/// - `item_name`: Human-readable name for logging (e.g., "challenges", "agreements")
/// - `get_id`: Function to extract ID from an API item
/// - `to_model`: Function to convert API item to active model
/// - `database`: Database connection for insertion
pub async fn sync_new_items<T, A, E>(
    items: Vec<T>,
    existing_ids: HashSet<String>,
    item_name: &str,
    get_id: impl Fn(&T) -> String,
    to_model: impl Fn(&T) -> Result<A>,
    database: &DatabaseConnection,
) -> Result<()>
where
    A: ActiveModelTrait<Entity = E> + Send,
    E: EntityTrait,
    InsertResult<A>: Send,
    TryInsertResult<A>: Send,
{
    if items.is_empty() {
        info!("No {} found", item_name);
        return Ok(());
    }

    let new_models: Vec<A> = items
        .iter()
        .filter(|item| !existing_ids.contains(&get_id(item)))
        .map(to_model)
        .collect::<Result<Vec<_>>>()?;

    if new_models.is_empty() {
        info!("All {} {} already stored", items.len(), item_name);
        return Ok(());
    }

    E::insert_many(new_models.clone())
        .exec(database)
        .await
        .with_context(|| format!("failed to insert new {}", item_name))?;

    info!("Inserted {} new {}", new_models.len(), item_name);

    Ok(())
}
