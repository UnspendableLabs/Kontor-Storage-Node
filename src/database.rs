mod client;
mod sqlite;

pub use client::{
    connect_without_migrating, default_app_dir, default_database_url, default_storage_dir, DBClient,
};

/// Re-export the migration module so application code can access the migrator easily.
pub mod migration {
    pub use crate::migration::Migrator;
}
