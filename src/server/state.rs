//! Server state types.

use crate::app::lifecycle::NodeRuntime;
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
    /// What the node currently is: which phase, which node id, which key.
    ///
    /// The server now starts before any of that is known — that is the whole
    /// point of a node that can be configured through its own UI — so none of
    /// it can be a constant fixed when this struct is built. Readers have to
    /// cope with every field being absent, which on a node still in setup they
    /// all are.
    pub runtime: NodeRuntime,
    /// Credentials for the operator UI.
    pub admin: AdminState,
}
