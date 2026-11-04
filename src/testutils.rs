//! Shared test utilities and fixtures.
//!
//! This module provides common test helpers used across multiple test modules
//! to avoid code duplication.

use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Schema, Set};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::entities::agreements;
use crate::entities::prelude::{Agreements, Challenges, NodeState};

/// Global test counter for generating unique identifiers.
/// Used across all test modules to ensure unique paths.
static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// RSA test private key (PKCS#8 PEM) used by GCS service-account fixtures and other crypto tests.
///
/// This must remain byte-identical to the literal previously embedded in each test
/// module that exercises GCS signing — any change would invalidate the deterministic
/// signatures the tests depend on.
pub const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnumunEUnoZIs5\nDhEXTNTyJPFxsZMxgRhLs7m6aiVu7GrDgoWFMoLy/B6Ccl2c9ml/RzuK5uKbJKM9\ntcwA90gpp536aLWB0BbQuWtfceU3BmQWFtQRXqCww/o462cujXhcMe5bVPvE9b/5\nyV+oWmKa42tw4x5//Cj8LGAw8aQwlC+OQ19iA+vmKx7xjs0uBFtQHnjGxekT71vp\nLgv53SVi5yUscz9Scy/VuBkNfOCaEz5zV+EUplYuvRMVEJ0Pvk1wOYjby4Gz+OVI\nrp1+1RFBEeTu2zo06E4o23pfz5DbZaBMZ8qK3WkNx6eQOuYK6Zrq+zM5/Uoq6fqQ\nAIuYpCNxAgMBAAECggEAB1pTx9IpNEfcFpc4RpY2q5rU/s/zDPOE1iS92p82nuM8\nVu/M3Kb3OKG20K8kzXG79DlyMcenXXfAtD7Y/53XiwPvGAApHNS7e1D1lQyQKNZd\n4t4DU/ObBcTBnmcrcc3/3cLOmTBjjSHc1Z1vVRkJQ5L+rcc3GhM61Ls5SEv/j6WN\nFw/fnYGtxUUXBz1gVvok0o89qTgW0Pt7SWrUkbAhrsGeTFpzNbicgRsBUXJJdRcl\nvK5rwKSPUhiIVhpQ78usSLdO30X3Bfvf/GQpR56/UgDqkn20ZMpJhKrAxSbmLSu9\nhgkIbLAlABxdYUbGFp5aTALAJ8EyZn8MU9RRuL9DcQKBgQDp263xaTlx8BgbKnq1\nwY+SxuDlGz/LoGYjF6v6FNHM1hQ5v2FpxaxF5EDUm3fdh+Z9yegL/g8GQdQQnelG\nA43VACvGAESw1ilsBDl6TZ+LZY4MTQrWSGUqQxt3APu3lHDAXkipHu2X3cv/3VrO\nDGs2WYWPiMxg1ZkIBojyZQ0SnQKBgQC3m910nvJIJ+WLXeXiG2qN147/5GU7Yma2\n0pEhQ4XVN/f7joGzUXLeB0BXNNbdKuRqEQ1r2VkH3qqY6HAL6/fK01qEhWBLv1hu\ndkEhEruK9WxzA/vLgmqFBsi04IFlnK70RCXckWZEHFjnnoutqAWpl7FTRiTeT8Bv\nHgmX2+lh5QKBgDAuADIiWaFts6m1IL7dd/TnYGITMRuEmkZUlCvbqjWnTVdwZGNk\nRE/J7Mlglltfqk70EAiYeQPy//vEbNDt3oSpmlsapww/sxz76dOWtm4DqDZEkR0A\noUcJuFjWLQXvYSNgyVt+cbi+C09VjWWyDUyPOQMPTfwNRY/vuLsnsn/JAoGBAKrW\n0Ri46DBxRukFJmfbIKr3/etlZTf7GB1WEYnE3RsGZ6vd7hqeV2X1k01RMfc5+Kwk\nT7ug0XE8IroB1HeTSM2lGJ0jyPTSBoNJbtJKLsxeDVl7RGcYYuqB5HBAUMXuIu/P\nFPeFJoWLZsGkyMx9AT/KkEkuhBGCXUhGx6BQE3htAoGAbEGbhHV8oU7NYKEmVyWM\nwfEQXGH2QQpHsj7xkTywOKEneaMkVUzA5GwF7CQEvk/2xXEgze+haaRGxFQJTO5m\nGK2ECeQhTwXvNi+3/MEMCdoPYuckF4hCVzsGwfkVBPf1zcOw0k0+EEsqbWwtXi2l\njIyC7b2m2fgAI0Ltt1btCfo=\n-----END PRIVATE KEY-----";

/// Connect to a fresh in-memory SQLite database with no schema.
///
/// Internal building block for the `setup_*_db` helpers below. Tests that need a
/// specific subset of tables should layer them on top of this.
async fn connect_in_memory_db() -> DatabaseConnection {
    Database::connect("sqlite::memory:")
        .await
        .expect("failed to connect to in-memory database")
}

/// Create the `agreements` table on an existing connection.
async fn create_agreements_table(db: &DatabaseConnection) {
    let schema = Schema::new(DatabaseBackend::Sqlite);
    let stmt = schema.create_table_from_entity(Agreements);
    db.execute(&stmt)
        .await
        .expect("failed to create agreements table");
}

/// Create the `challenges` table on an existing connection.
async fn create_challenges_table(db: &DatabaseConnection) {
    let schema = Schema::new(DatabaseBackend::Sqlite);
    let stmt = schema.create_table_from_entity(Challenges);
    db.execute(&stmt)
        .await
        .expect("failed to create challenges table");
}

/// Create the `node_state` table on an existing connection.
async fn create_node_state_table(db: &DatabaseConnection) {
    let schema = Schema::new(DatabaseBackend::Sqlite);
    let stmt = schema.create_table_from_entity(NodeState);
    db.execute(&stmt)
        .await
        .expect("failed to create node_state table");
}

/// Set up an in-memory SQLite database with the agreements, challenges and
/// node_state tables — the daemon's whole schema.
///
/// This creates a fresh database for each test to ensure isolation.
pub async fn setup_in_memory_db() -> DatabaseConnection {
    let db = connect_in_memory_db().await;
    create_agreements_table(&db).await;
    create_challenges_table(&db).await;
    create_node_state_table(&db).await;
    db
}

/// Set up an in-memory SQLite database with only the agreements table.
pub async fn setup_agreements_db() -> DatabaseConnection {
    let db = connect_in_memory_db().await;
    create_agreements_table(&db).await;
    db
}

/// Set up an in-memory SQLite database with only the challenges table.
pub async fn setup_challenges_db() -> DatabaseConnection {
    let db = connect_in_memory_db().await;
    create_challenges_table(&db).await;
    db
}

/// Generate a unique test directory path with the given prefix.
///
/// Uses the system temp directory and includes a counter to avoid collisions
/// between tests running in parallel or sequentially.
///
/// **Note:** prefer [`tempdir`] in new tests — it auto-cleans on drop instead of
/// leaving stale directories under `/tmp`. This helper remains for legacy callers
/// that pass a `PathBuf` reference around.
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

/// Create a self-cleaning temporary directory for tests.
///
/// Wraps [`tempfile::Builder`] with the `kontor-` prefix so test artifacts are
/// easy to identify. The returned [`tempfile::TempDir`] removes its directory
/// when dropped — keep the binding alive for the lifetime of the test.
///
/// New tests should prefer this over [`unique_storage_dir`] / [`unique_test_path`],
/// which leak files under `/tmp`.
pub fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kontor-")
        .tempdir()
        .expect("failed to create test tempdir")
}

/// Builder for `agreements::ActiveModel` test rows.
///
/// Carries plain field values rather than `ActiveValue` wrappers so tests can
/// tweak individual fields without re-stating the 14-field literal each time.
/// Call [`AgreementFixture::into_active_model`] to materialize the row, then
/// `.insert(&db)` it.
pub struct AgreementFixture {
    pub agreement_id: String,
    pub user_id: String,
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub original_size: i64,
    pub nodes: serde_json::Value,
    pub root: Option<String>,
    pub padded_len: Option<i64>,
    pub object_id: Option<String>,
    pub ledger_index: Option<i64>,
    pub downloaded: bool,
    pub transaction_id: Option<String>,
    pub curation: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
}

impl AgreementFixture {
    /// Reasonable defaults for tests. Customize fields as needed before calling
    /// [`AgreementFixture::into_active_model`].
    pub fn new(agreement_id: impl Into<String>, file_id: impl Into<String>) -> Self {
        Self {
            agreement_id: agreement_id.into(),
            user_id: "user_1".to_string(),
            file_id: file_id.into(),
            filename: "test.bin".to_string(),
            mime_type: "application/octet-stream".to_string(),
            original_size: 123,
            nodes: json!(["NODE-test"]),
            root: None,
            padded_len: None,
            object_id: None,
            ledger_index: None,
            downloaded: false,
            transaction_id: None,
            curation: json!({}),
            status: "ready".to_string(),
            created_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        }
    }

    /// Convert into a `SeaORM` `ActiveModel` ready to be inserted.
    pub fn into_active_model(self) -> agreements::ActiveModel {
        agreements::ActiveModel {
            agreement_id: Set(self.agreement_id),
            user_id: Set(self.user_id),
            file_id: Set(self.file_id),
            filename: Set(self.filename),
            mime_type: Set(self.mime_type),
            original_size: Set(self.original_size),
            nodes: Set(self.nodes),
            root: Set(self.root),
            padded_len: Set(self.padded_len),
            object_id: Set(self.object_id),
            ledger_index: Set(self.ledger_index),
            downloaded: Set(self.downloaded),
            transaction_id: Set(self.transaction_id),
            curation: Set(self.curation),
            status: Set(self.status),
            created_at: Set(self.created_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::EntityTrait;

    #[tokio::test]
    async fn setup_in_memory_db_creates_both_tables() {
        let db = setup_in_memory_db().await;

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
        let dir = unique_storage_dir("alias");
        assert!(
            dir.to_string_lossy().contains("kontor_test_alias"),
            "should use the same naming convention"
        );
    }
}
