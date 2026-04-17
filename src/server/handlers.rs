//! HTTP request handlers.

use crate::app::config::StorageMethod;
use crate::entities::{agreements, prelude::Agreements};
use crate::server::state::DownloadServerState;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use http::response::Builder;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use tracing::error;

const DEFAULT_LIMIT: u64 = 20;
const MAX_LIMIT: u64 = 100;

#[derive(Serialize)]
pub struct NodeInfoResponse {
    node_id: String,
}

pub async fn node_info(State(state): State<DownloadServerState>) -> Json<NodeInfoResponse> {
    Json(NodeInfoResponse {
        node_id: state.node_id.clone(),
    })
}

pub async fn dashboard() -> Response {
    const INDEX_HTML: &str = include_str!("../../static/index.html");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(INDEX_HTML))
        .unwrap()
}

#[derive(Debug, Deserialize)]
pub struct DownloadFileQuery {
    /// When true, serve with `Content-Disposition: inline` and do not force attachment on GCS.
    #[serde(default)]
    pub inline: bool,
}

pub async fn download_file(
    State(state): State<DownloadServerState>,
    Path(file_id): Path<String>,
    Query(query): Query<DownloadFileQuery>,
) -> Result<Response, DownloadError> {
    let agreement = Agreements::find()
        .filter(agreements::Column::FileId.eq(file_id.clone()))
        .one(&state.db)
        .await
        .map_err(|err| DownloadError::Internal(format!("database error: {err}")))?
        .ok_or(DownloadError::NotFound)?;

    if !agreement.downloaded {
        return Err(DownloadError::NotReady);
    }

    match state.storage_backend.method {
        StorageMethod::Local => serve_local(&state, &agreement, &file_id, query.inline).await,
        StorageMethod::Gcs => serve_gcs(&state, &agreement, &file_id, query.inline).await,
    }
}

#[derive(Debug, Deserialize)]
pub struct FilesQuery {
    offset: Option<u64>,
    limit: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilesResponse {
    pub offset: u64,
    pub limit: u64,
    pub total: u64,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub original_size: Option<u64>,
    pub status: String,
    pub downloaded: bool,
    pub created_at: String,
    pub download_path: String,
}

impl From<agreements::Model> for FileEntry {
    fn from(model: agreements::Model) -> Self {
        let original_size = model.original_size.try_into().ok();
        FileEntry {
            download_path: format!("/files/{}", model.file_id),
            file_id: model.file_id,
            filename: model.filename,
            mime_type: model.mime_type,
            original_size,
            status: model.status,
            downloaded: model.downloaded,
            created_at: model.created_at.to_rfc3339(),
        }
    }
}

pub async fn list_files(
    State(state): State<DownloadServerState>,
    Query(query): Query<FilesQuery>,
) -> Result<Json<FilesResponse>, ListFilesError> {
    let offset = query.offset.unwrap_or(0);
    let requested_limit = query.limit.unwrap_or(DEFAULT_LIMIT);

    if requested_limit == 0 {
        return Err(ListFilesError::BadRequest(
            "limit must be greater than 0".into(),
        ));
    }

    let limit = requested_limit.min(MAX_LIMIT);

    let base_query = Agreements::find().filter(agreements::Column::Downloaded.eq(true));

    let total = base_query
        .clone()
        .count(&state.db)
        .await
        .map_err(|err| ListFilesError::Internal(format!("database error: {err}")))?;

    let files = base_query
        .order_by_desc(agreements::Column::CreatedAt)
        .offset(offset)
        .limit(limit)
        .all(&state.db)
        .await
        .map_err(|err| ListFilesError::Internal(format!("database error: {err}")))?
        .into_iter()
        .map(FileEntry::from)
        .collect();

    Ok(Json(FilesResponse {
        offset,
        limit,
        total,
        files,
    }))
}

async fn serve_local(
    state: &DownloadServerState,
    agreement: &agreements::Model,
    file_id: &str,
    inline: bool,
) -> Result<Response, DownloadError> {
    let path = state.storage_dir.join(file_id);
    let metadata = tokio::fs::metadata(&path).await.map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            DownloadError::NotFound
        } else {
            DownloadError::Internal(format!(
                "failed to read local file metadata {}: {err}",
                path.display()
            ))
        }
    })?;

    if !metadata.is_file() {
        return Err(DownloadError::Internal(format!(
            "local path is not a file: {}",
            path.display()
        )));
    }

    let file = File::open(&path).await.map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            DownloadError::NotFound
        } else {
            DownloadError::Internal(format!(
                "failed to open local file {}: {err}",
                path.display()
            ))
        }
    })?;

    let stream = ReaderStream::new(file);
    let builder = response_builder(agreement, inline)?;
    builder
        .body(Body::from_stream(stream))
        .map_err(|err| DownloadError::Internal(err.to_string()))
}

async fn serve_gcs(
    state: &DownloadServerState,
    agreement: &agreements::Model,
    file_id: &str,
    inline: bool,
) -> Result<Response, DownloadError> {
    let client = state
        .storage_backend
        .gcs_client()
        .ok_or(DownloadError::StorageUnavailable)?;

    let force_download = !inline;
    let download_url = client
        .create_signed_download_url(
            file_id,
            force_download,
            Some(&agreement.filename),
            if inline {
                Some(agreement.mime_type.as_str())
            } else {
                None
            },
        )
        .map_err(|err| DownloadError::Upstream(format!("gcs signed url failed: {err}")))?;

    let location = HeaderValue::from_str(&download_url)
        .map_err(|err| DownloadError::Internal(format!("invalid redirect URL: {err}")))?;

    // CORS headers are added uniformly by the CorsLayer in routes::router.
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .map_err(|err| DownloadError::Internal(err.to_string()))
}

/// Build the response headers for a file download.
pub fn response_builder(
    agreement: &agreements::Model,
    inline: bool,
) -> Result<Builder, DownloadError> {
    let mut builder: Builder = Response::builder().status(StatusCode::OK);

    let mime = header_value_or_default(&agreement.mime_type, "application/octet-stream")
        .map_err(DownloadError::Internal)?;
    builder = builder.header(header::CONTENT_TYPE, mime);

    if let Some(value) = content_disposition(&agreement.filename, inline)? {
        builder = builder.header(header::CONTENT_DISPOSITION, value);
    }

    if let Some(len) = original_size_header(agreement)? {
        builder = builder.header(header::CONTENT_LENGTH, len);
    }

    // Files are immutable (content-addressed by hash), cache for 1 year
    builder = builder.header(header::CACHE_CONTROL, "public, max-age=31536000, immutable");

    // CORS headers are added uniformly by the CorsLayer in routes::router.

    Ok(builder)
}

fn header_value_or_default(value: &str, default: &str) -> Result<HeaderValue, String> {
    let chosen = if value.trim().is_empty() {
        default
    } else {
        value
    };
    HeaderValue::from_str(chosen).map_err(|err| err.to_string())
}

fn content_disposition(filename: &str, inline: bool) -> Result<Option<HeaderValue>, DownloadError> {
    if filename.trim().is_empty() {
        return Ok(None);
    }
    let escaped = filename.replace('"', "\\\"");
    let disposition = if inline {
        format!("inline; filename=\"{}\"", escaped)
    } else {
        format!("attachment; filename=\"{}\"", escaped)
    };
    HeaderValue::from_str(&disposition)
        .map(Some)
        .map_err(|err| DownloadError::Internal(format!("invalid filename: {err}")))
}

fn original_size_header(
    agreement: &agreements::Model,
) -> Result<Option<HeaderValue>, DownloadError> {
    let size: u64 = match agreement.original_size.try_into() {
        Ok(len) => len,
        Err(_) => return Ok(None),
    };
    HeaderValue::from_str(&size.to_string())
        .map(Some)
        .map_err(|err| DownloadError::Internal(format!("invalid content length: {err}")))
}

#[derive(Debug)]
pub enum DownloadError {
    NotFound,
    NotReady,
    StorageUnavailable,
    Upstream(String),
    Internal(String),
}

impl IntoResponse for DownloadError {
    fn into_response(self) -> Response {
        match self {
            DownloadError::NotFound => (StatusCode::NOT_FOUND, "file not found").into_response(),
            DownloadError::NotReady => (
                StatusCode::CONFLICT,
                "file is not yet available on this node",
            )
                .into_response(),
            DownloadError::StorageUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage backend unavailable",
            )
                .into_response(),
            DownloadError::Upstream(reason) => {
                tracing::error!("download upstream error: {reason}");
                (StatusCode::BAD_GATEWAY, "bad gateway").into_response()
            }
            DownloadError::Internal(reason) => {
                tracing::error!("download internal error: {reason}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

#[derive(Debug)]
pub enum ListFilesError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ListFilesError {
    fn into_response(self) -> Response {
        match self {
            ListFilesError::BadRequest(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
            ListFilesError::Internal(reason) => {
                error!("List files failed: {}", reason);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// Test helper to access response_builder from tests.
#[cfg(test)]
pub fn response_builder_test(agreement: &agreements::Model) -> Result<Builder, DownloadError> {
    response_builder(agreement, false)
}
