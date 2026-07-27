//! Server state types.

use crate::app::tasks::downloadagreements::StorageBackend;
use crate::server::admin::AdminState;
use sea_orm::DatabaseConnection;
use std::path::PathBuf;

/// State shared across all routes in the download server.
#[derive(Clone)]
pub struct DownloadServerState {
    pub db: DatabaseConnection,
    pub storage_dir: PathBuf,
    pub storage_backend: StorageBackend,
    pub node_id: String,
    /// Credentials for the operator UI. [`AdminState::disabled`] when no
    /// `ADMIN_PASSWORD` is configured, which is the default.
    pub admin: AdminState,
}
