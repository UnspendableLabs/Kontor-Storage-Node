pub mod computeproofs;
pub mod downloadagreements;
pub mod getactivechallenges;
pub mod getnewagreements;
pub mod reconcile;

use anyhow::{Context, Result};

/// Status constants for challenges and agreements.
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_PROVED: &str = "proved";

/// Item type names for logging and sync operations.
pub const ITEM_TYPE_CHALLENGES: &str = "challenges";
pub const ITEM_TYPE_AGREEMENTS: &str = "agreements";
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, InsertResult, TryInsertResult};
use std::collections::HashSet;
use tracing::info;

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
