//! Route definitions for the download server.

use crate::server::handlers::{dashboard, download_file, list_files, node_info};
use crate::server::state::DownloadServerState;
use axum::{routing::get, Router};
use tower_http::services::ServeDir;

/// Create the router with all routes.
pub fn router(state: DownloadServerState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/info", get(node_info))
        .route("/files", get(list_files))
        .route("/files/:file_id", get(download_file))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state)
}
