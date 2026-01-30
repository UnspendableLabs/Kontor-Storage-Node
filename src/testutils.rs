//! Shared test utilities and fixtures.
//!
//! This module provides common test helpers used across multiple test modules
//! to avoid code duplication.

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Schema};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::entities::prelude::{Agreements, Challenges};

/// Global test counter for generating unique identifiers.
/// Used across all test modules to ensure unique paths.
static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Set up an in-memory SQLite database with both agreements and challenges tables.
///
/// This creates a fresh database for each test to ensure isolation.
pub async fn setup_in_memory_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("failed to connect to in-memory database");
    let schema = Schema::new(DatabaseBackend::Sqlite);

    // Create agreements table
    let agreements_stmt = schema.create_table_from_entity(Agreements);
    db.execute(&agreements_stmt)
        .await
        .expect("failed to create agreements table");

    // Create challenges table
    let challenges_stmt = schema.create_table_from_entity(Challenges);
    db.execute(&challenges_stmt)
        .await
        .expect("failed to create challenges table");

    db
}

/// Set up an in-memory SQLite database with only the agreements table.
pub async fn setup_agreements_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("failed to connect to in-memory database");
    let schema = Schema::new(DatabaseBackend::Sqlite);
    let stmt = schema.create_table_from_entity(Agreements);
    db.execute(&stmt)
        .await
        .expect("failed to create agreements table");
    db
}

/// Set up an in-memory SQLite database with only the challenges table.
pub async fn setup_challenges_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("failed to connect to in-memory database");
    let schema = Schema::new(DatabaseBackend::Sqlite);
    let stmt = schema.create_table_from_entity(Challenges);
    db.execute(&stmt)
        .await
        .expect("failed to create challenges table");
    db
}

/// Generate a unique test directory path with the given prefix.
///
/// Uses the system temp directory and includes a counter to avoid collisions
/// between tests running in parallel or sequentially.
///
/// # Arguments
/// * `prefix` - A prefix to include in the directory name for identification
pub fn unique_test_path(prefix: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("kontor_test_{prefix}_{id}"))
}

/// Generate a unique database path for tests.
///
/// Returns a path suitable for SQLite database files (with .db extension).
pub fn unique_db_path(prefix: &str) -> PathBuf {
    unique_test_path(prefix).with_extension("db")
}

/// Generate a unique storage directory path for tests.
///
/// This is an alias for [`unique_test_path`] for backwards compatibility.
pub fn unique_storage_dir(prefix: &str) -> PathBuf {
    unique_test_path(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::EntityTrait;

    #[tokio::test]
    async fn setup_in_memory_db_creates_both_tables() {
        let db = setup_in_memory_db().await;

        // Verify we can query both tables
        let agreements = Agreements::find().all(&db).await;
        assert!(agreements.is_ok(), "agreements table should exist");

        let challenges = Challenges::find().all(&db).await;
        assert!(challenges.is_ok(), "challenges table should exist");
    }

    #[test]
    fn unique_test_path_returns_different_paths() {
        let path1 = unique_test_path("test");
        let path2 = unique_test_path("test");
        assert_ne!(path1, path2, "should return unique paths");
    }

    #[test]
    fn unique_test_path_includes_prefix() {
        let path = unique_test_path("myprefix");
        assert!(
            path.to_string_lossy().contains("myprefix"),
            "should include prefix in path"
        );
    }

    #[test]
    fn unique_db_path_adds_db_extension() {
        let path = unique_db_path("database");
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("db"),
            "should have .db extension"
        );
    }

    #[test]
    fn unique_db_path_returns_different_paths() {
        let path1 = unique_db_path("test");
        let path2 = unique_db_path("test");
        assert_ne!(path1, path2, "should return unique paths");
    }

    #[test]
    fn unique_storage_dir_is_alias_for_unique_test_path() {
        // Both functions should produce paths with the same format
        let dir = unique_storage_dir("alias");
        assert!(
            dir.to_string_lossy().contains("kontor_test_alias"),
            "should use the same naming convention"
        );
    }
}
