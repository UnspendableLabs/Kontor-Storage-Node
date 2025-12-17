mod client;
mod sqlite;

pub use client::{default_database_url, default_storage_dir, DBClient};

/// Re-export the migration module so application code can access the migrator easily.
pub mod migration {
    pub use ::migration::Migrator;
}
