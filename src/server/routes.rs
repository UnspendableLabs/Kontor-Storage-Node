//! Public HTTP API for the storage node.
//!
//! # Security model
//!
//! The serving routes are PUBLIC (no authentication). The dashboard at `/`, the
//! file listing at `/files`, the node info at `/api/info`, and file downloads
//! at `/files/:id` can be accessed by anyone who can reach the bind address.
//!
//! Operators are expected to deploy this server behind a trusted network or
//! reverse proxy (with auth, rate limiting, TLS termination, etc.) when used
//! in production. CORS is intentionally permissive (`Allow-Origin: *`) to
//! allow browser dashboards from any origin.
//!
//! The one exception is the operator UI under `/admin` and `/api/admin/*`,
//! which carries its own password gate — see [`crate::server::admin`].
//!
//! # CORS
//!
//! A single [`tower_http::cors::CorsLayer`] is the source of truth for CORS
//! headers. Handlers MUST NOT inject `Access-Control-*` headers manually; the
//! layer applies them uniformly to every response (including redirects).
//!
//! The admin routes are merged *after* the layer, so they deliberately get no
//! CORS headers at all: they are only ever called same-origin by the embedded
//! page, and no `Access-Control-Allow-Origin` means a browser refuses to hand
//! another origin their responses.

use crate::server::admin;
use crate::server::assets;
use crate::server::handlers::{dashboard, download_file, list_files, node_info};
use crate::server::state::DownloadServerState;
use axum::{routing::get, Router};
use http::{header, Method};
use tower_http::cors::{Any, CorsLayer};

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
        // Served out of the binary, not out of the working directory — an
        // installed node has no `static/` beside it. See [`crate::server::assets`].
        .route("/static/*path", get(assets::serve))
        .layer(cors)
        .merge(admin::router())
        .with_state(state)
}
