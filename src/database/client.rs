use anyhow::{Context, Result};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sea_orm_migration::prelude::MigratorTrait;
#[cfg(test)]
use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

use super::{migration, sqlite};

const DEFAULT_DB_DIR: &str = "Kontor-Storage-Node";
const DEFAULT_DB_FILE: &str = "storage.db";
const DEFAULT_FILES_DIR: &str = "files";

#[cfg(test)]
thread_local! {
    static DATA_DIR_OVERRIDE: RefCell<Option<Option<PathBuf>>> = const { RefCell::new(None) };
}

fn data_dir() -> Option<PathBuf> {
    #[cfg(test)]
    {
        if let Some(overridden) = DATA_DIR_OVERRIDE.with(|cell| cell.borrow().clone()) {
            return overridden;
        }
    }

    dirs::data_dir()
}

#[cfg(test)]
fn with_data_dir_override<F, T>(value: Option<PathBuf>, f: F) -> T
where
    F: FnOnce() -> T,
{
    DATA_DIR_OVERRIDE.with(|cell| {
        let previous = cell.replace(Some(value));
        let result = f();
        cell.replace(previous);
        result
    })
}

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
    if let Some(app_dir) = default_app_dir() {
        let db_path = app_dir.join(DEFAULT_DB_FILE);
        return format!("sqlite://{}", db_path.display());
    }

    // Safe fallback if the platform does not expose a data directory.
    "sqlite::memory:".to_string()
}

/// Returns the default application data directory (e.g. `~/.local/share/Kontor-Storage-Node`).
#[must_use]
pub fn default_app_dir() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join(DEFAULT_DB_DIR))
}

/// Returns the default directory used to store downloaded files.
#[must_use]
pub fn default_storage_dir() -> PathBuf {
    if let Some(app_dir) = default_app_dir() {
        app_dir.join(DEFAULT_FILES_DIR)
    } else {
        PathBuf::from(DEFAULT_FILES_DIR)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::SchemaManager;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("database_client")
    }

    fn unique_db_path(prefix: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        test_root().join(format!("kontor_storage_node_test_{prefix}_{id}.sqlite"))
    }

    #[test]
    fn default_database_url_uses_data_dir_override() {
        let dir = test_root().join("data_dir_override");
        fs::create_dir_all(&dir).unwrap();

        let url = with_data_dir_override(Some(dir.clone()), default_database_url);
        let expected_prefix = dir.join(DEFAULT_DB_DIR).join(DEFAULT_DB_FILE);

        assert!(
            url.contains(&expected_prefix.display().to_string()),
            "expected database url to contain {} but got {url}",
            expected_prefix.display()
        );
    }

    #[test]
    fn default_storage_dir_uses_app_dir_override() {
        let dir = test_root().join("storage_dir_override");
        fs::create_dir_all(&dir).unwrap();

        let storage_dir = with_data_dir_override(Some(dir.clone()), default_storage_dir);
        let expected = dir.join(DEFAULT_DB_DIR).join(DEFAULT_FILES_DIR);

        assert_eq!(
            storage_dir,
            expected,
            "expected storage dir to be {} but got {}",
            expected.display(),
            storage_dir.display()
        );
    }

    #[test]
    fn default_database_url_falls_back_when_no_dir_available() {
        let url = with_data_dir_override(None, default_database_url);
        assert_eq!(url, "sqlite::memory:");
    }

    #[tokio::test]
    async fn dbclient_runs_migrations_for_new_sqlite_file() -> Result<()> {
        let db_path = unique_db_path("runs_migrations");
        let db_url = format!("sqlite://{}", db_path.display());

        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let client = DBClient::new(&db_url).await?;
        assert!(db_path.exists(), "database file should be created");
        client.connection().ping().await?;

        fs::remove_file(&db_path).ok();

        Ok(())
    }

    #[tokio::test]
    async fn dbclient_skips_migrations_when_file_exists() -> Result<()> {
        let db_path = unique_db_path("skip_migrations");
        let db_url = format!("sqlite://{}", db_path.display());

        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::File::create(&db_path)?;

        let client = DBClient::new(&db_url).await?;
        assert!(db_path.exists(), "existing database file should persist");
        client.connection().ping().await?;

        fs::remove_file(&db_path).ok();

        Ok(())
    }

    #[tokio::test]
    async fn migrations_apply_and_revert_in_memory() -> Result<()> {
        let db_url = "sqlite::memory:";
        let conn = connect(db_url).await?;
        let schema = SchemaManager::new(&conn);

        migration::Migrator::up(&conn, None).await?;
        assert!(
            schema.has_table("agreements").await?,
            "expected agreements table to exist after running migrations"
        );

        let steps = migration::Migrator::migrations().len() as u32;
        migration::Migrator::down(&conn, Some(steps)).await?;

        assert!(
            !schema.has_table("agreements").await?,
            "expected agreements table to be dropped after rolling back migrations"
        );

        Ok(())
    }
}
