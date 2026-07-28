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
    /// `None` while the node is unregistered: the Portal assigns the id at
    /// registration, so a node the Portal has never heard of does not have one
    /// yet. The server still runs — that is the only way `/admin` is reachable
    /// to fix it — so every reader has to cope with its absence.
    pub node_id: Option<String>,
    /// Credentials for the operator UI. [`AdminState::disabled`] when no
    /// `ADMIN_PASSWORD` is configured, which is the default.
    pub admin: AdminState,
}
