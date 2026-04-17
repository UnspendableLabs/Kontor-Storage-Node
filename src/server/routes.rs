//! Public HTTP API for the storage node.
//!
//! # Security model
//!
//! All routes are PUBLIC (no authentication). The dashboard at `/`, the file
//! listing at `/files`, the node info at `/api/info`, and file downloads at
//! `/files/:id` can be accessed by anyone who can reach the bind address.
//!
//! Operators are expected to deploy this server behind a trusted network or
//! reverse proxy (with auth, rate limiting, TLS termination, etc.) when used
//! in production. CORS is intentionally permissive (`Allow-Origin: *`) to
//! allow browser dashboards from any origin.
//!
//! # CORS
//!
//! A single [`tower_http::cors::CorsLayer`] is the source of truth for CORS
//! headers. Handlers MUST NOT inject `Access-Control-*` headers manually; the
//! layer applies them uniformly to every response (including redirects).

use crate::server::handlers::{dashboard, download_file, list_files, node_info};
use crate::server::state::DownloadServerState;
use axum::{routing::get, Router};
use http::{header, Method};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

/// Create the router with all routes.
pub fn router(state: DownloadServerState) -> Router {
    // Single source of truth for CORS headers. Handlers must not duplicate
    // these via response builders.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::HEAD, Method::OPTIONS])
        .allow_headers(Any)
        // Browser clients need to read Content-Disposition to recover the
        // original filename for downloads.
        .expose_headers([header::CONTENT_DISPOSITION]);

    Router::new()
        .route("/", get(dashboard))
        .route("/api/info", get(node_info))
        .route("/files", get(list_files))
        .route("/files/:file_id", get(download_file))
        .nest_service("/static", ServeDir::new("static"))
        .layer(cors)
        .with_state(state)
}
