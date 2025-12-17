use anyhow::{Context, Result};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::prelude::MigratorTrait;
use std::time::Duration;

use super::{migration, sqlite};

const DEFAULT_DB_DIR: &str = "Kontor-Storage-Node";
const DEFAULT_DB_FILE: &str = "storage.db";

/// Convenience wrapper around a SeaORM database connection that ensures
/// migrations are applied on initialization.
pub struct DBClient {
    connection: DatabaseConnection,
}

impl DBClient {
    /// Create a new database client, ensuring migrations are run when needed.
    pub async fn new(database_url: &str) -> Result<Self> {
        let should_run_migrations = sqlite::prepare_sqlite(database_url)?;
        let connection = connect(database_url).await?;

        if should_run_migrations {
            migration::Migrator::up(&connection, None)
                .await
                .context("failed to apply database migrations")?;
        }

        Ok(Self { connection })
    }

    /// Access the underlying database connection.
    #[must_use]
    pub fn connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

/// Returns a SQLite database URL under the user's data directory.
#[must_use]
pub fn default_database_url() -> String {
    if let Some(data_dir) = dirs::data_dir() {
        let db_path = data_dir.join(DEFAULT_DB_DIR).join(DEFAULT_DB_FILE);
        return format!("sqlite://{}", db_path.display());
    }

    // Safe fallback if the platform does not expose a data directory.
    "sqlite::memory:".to_string()
}

/// Establishes a database connection using SeaORM.
async fn connect(database_url: &str) -> Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(database_url);
    options
        .max_connections(5)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(60))
        .sqlx_logging(false);

    Database::connect(options)
        .await
        .with_context(|| format!("unable to connect to database {database_url}"))
}
