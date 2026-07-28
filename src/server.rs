//! HTTP download server module.
//!
//! Provides a REST API for downloading stored files and listing available files.

pub mod admin;
pub mod handlers;
pub mod routes;
pub mod state;

pub use routes::router;
pub use state::DownloadServerState;

use anyhow::{Context, Result};
use std::future::Future;
use std::net::SocketAddr;
use tracing::info;

/// Start the download server and serve requests until shutdown is signaled.
pub async fn serve(
    addr: SocketAddr,
    state: DownloadServerState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding download server to {}", addr))?;

    if let Ok(addr) = listener.local_addr() {
        info!("Download server listening on {}", addr);
    }

    // `into_make_service_with_connect_info` is what gives the admin login
    // throttle a peer address to key on; without it every client would share
    // one bucket.
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("download server failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::StorageMethod;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::clients::gcs::GcsClient;
    use crate::entities::agreements;
    use crate::server::admin::AdminState;
    use crate::server::handlers::{DownloadError, FilesResponse, ListFilesError};
    use crate::testutils::{unique_storage_dir, AgreementFixture, TEST_PRIVATE_KEY};
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::IntoResponse;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, DatabaseConnection};
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    /// Setup database using migrations (different from testutils::setup_in_memory_db which uses schema).
    async fn setup_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:")
            .await
            .expect("connect memory db");
        Migrator::up(&db, None).await.expect("migrate");
        db
    }

    async fn insert_agreement(
        db: &DatabaseConnection,
        file_id: &str,
        filename: &str,
        size: i64,
        downloaded: bool,
    ) {
        let mut fx = AgreementFixture::new(format!("AGREEMENT-{file_id}"), file_id);
        fx.user_id = "user".into();
        fx.filename = filename.into();
        fx.original_size = size;
        fx.nodes = serde_json::json!([]);
        fx.padded_len = Some(size);
        fx.downloaded = downloaded;
        fx.created_at = chrono::Utc::now().fixed_offset();
        fx.into_active_model()
            .insert(db)
            .await
            .expect("insert agreement");
    }

    fn dummy_agreement(file_id: &str, filename: &str, mime: &str, size: i64) -> agreements::Model {
        agreements::Model {
            agreement_id: format!("AGREEMENT-{file_id}"),
            user_id: "user".into(),
            file_id: file_id.into(),
            filename: filename.into(),
            mime_type: mime.into(),
            original_size: size,
            nodes: serde_json::json!([]),
            root: None,
            padded_len: Some(size),
            object_id: None,
            ledger_index: None,
            downloaded: true,
            transaction_id: None,
            curation: serde_json::json!({}),
            status: "ready".into(),
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    fn write_service_account_json(dir: &Path, key: &str) -> PathBuf {
        let path = dir.join("service_account.json");
        fs::create_dir_all(dir).unwrap();
        let json = serde_json::json!({
            "private_key": key,
            "client_email": "svc@example.com",
            "token_uri": "https://auth.example/token"
        });
        fs::write(&path, json.to_string()).unwrap();
        path
    }

    async fn gcs_backend_with_key(key: &str) -> StorageBackend {
        let dir = unique_storage_dir("server").join("gcs");
        let sa = write_service_account_json(&dir, key);
        let client = GcsClient::from_path_or_inline_json("bucket", &sa.to_string_lossy())
            .expect("service account should parse");
        StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: Some(Arc::new(client)),
        }
    }

    #[tokio::test]
    async fn serves_local_file_streaming() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        let file_id = "FILE-123";
        let filename = "contract.pdf";
        let content = Bytes::from_static(b"hello world");
        let path = storage_dir.join(file_id);
        tokio::fs::write(&path, &content).await.unwrap();

        insert_agreement(&db, file_id, filename, content.len() as i64, true).await;

        let state = DownloadServerState {
            db: db.clone(),
            storage_dir: storage_dir.clone(),
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{file_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"contract.pdf\"")
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, content);
    }

    #[tokio::test]
    async fn returns_conflict_when_not_downloaded() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        insert_agreement(&db, "FILE-999", "x.bin", 1, false).await;

        let state = DownloadServerState {
            db: db.clone(),
            storage_dir: storage_dir.clone(),
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/files/FILE-999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn lists_downloaded_files_with_pagination() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        insert_agreement(&db, "FILE-1", "one.pdf", 10, true).await;
        insert_agreement(&db, "FILE-2", "two.pdf", 20, true).await;
        insert_agreement(&db, "FILE-3", "three.pdf", 30, false).await;

        let state = DownloadServerState {
            db: db.clone(),
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/files?offset=0&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: FilesResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload.total, 2);
        assert_eq!(payload.limit, 1);
        assert_eq!(payload.files.len(), 1);
        assert!(
            payload.files[0].file_id == "FILE-1" || payload.files[0].file_id == "FILE-2",
            "expected only downloaded files to appear"
        );

        // fetch the next page
        let next = router(DownloadServerState {
            db,
            storage_dir: PathBuf::new(),
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        });
        let response = next
            .oneshot(
                Request::builder()
                    .uri("/files?offset=1&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: FilesResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.total, 2);
        assert_eq!(payload.offset, 1);
        assert_eq!(payload.files.len(), 1);
    }

    #[tokio::test]
    async fn list_files_rejects_zero_limit() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        insert_agreement(&db, "FILE-1", "one.pdf", 10, true).await;

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/files?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serve_binds_and_exits_on_shutdown() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        let (tx, rx) = oneshot::channel();

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = tokio::spawn(serve(addr, state, async move {
            let _ = rx.await;
        }));

        tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server should stop");
        result
            .expect("server task should complete")
            .expect("serve should succeed");
    }

    /// The admin routes over a real socket rather than `oneshot`, which is the
    /// only way to exercise `into_make_service_with_connect_info` — the wiring
    /// the login throttle keys its per-client buckets on.
    #[tokio::test]
    async fn serve_exposes_the_admin_ui_over_a_real_socket() {
        use crate::app::config::AdminPassword;

        const PASSWORD: &str = "correct horse battery";

        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server-admin");
        let (tx, rx) = oneshot::channel();

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-socket".to_string()),
            admin: AdminState::with_password(AdminPassword::new(Some(PASSWORD))),
        };

        // Bind first so the test knows the port before the server owns it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = tokio::spawn(serve(addr, state, async move {
            let _ = rx.await;
        }));

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // The server may not have finished binding yet.
        let page = loop {
            match client.get(format!("{base}/admin")).send().await {
                Ok(response) => break response,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        assert_eq!(page.status(), 200);
        assert!(page.text().await.unwrap().contains("Kontor Storage Node"));

        let login: serde_json::Value = client
            .post(format!("{base}/api/admin/login"))
            .json(&serde_json::json!({ "password": PASSWORD }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = login["token"].as_str().expect("token in response");

        let status = client
            .get(format!("{base}/api/admin/status"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(status.status(), 200);
        let payload: serde_json::Value = status.json().await.unwrap();
        assert_eq!(payload["node_id"], "NODE-socket");

        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server should stop")
            .expect("server task should complete")
            .expect("serve should succeed");
    }

    #[tokio::test]
    async fn serve_local_returns_not_found_when_file_missing() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        insert_agreement(&db, "FILE-missing", "missing.bin", 10, true).await;

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/files/FILE-missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_local_returns_internal_when_path_not_file() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        let file_path = storage_dir.join("FILE-dir");
        tokio::fs::create_dir_all(&file_path).await.unwrap();

        insert_agreement(&db, "FILE-dir", "dir.bin", 10, true).await;

        let response = router(DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        })
        .oneshot(
            Request::builder()
                .uri("/files/FILE-dir")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn gcs_download_redirects_with_signed_url() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        insert_agreement(&db, "FILE-gcs", "gcs.bin", 12, true).await;

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: gcs_backend_with_key(TEST_PRIVATE_KEY).await,
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/files/FILE-gcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        assert!(
            location.contains("X-Goog-Signature="),
            "expected signed URL, got {location}"
        );
    }

    #[tokio::test]
    async fn gcs_download_returns_storage_unavailable_without_client() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        insert_agreement(&db, "FILE-gcs-none", "gcs.bin", 12, true).await;

        let response = router(DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend {
                method: StorageMethod::Gcs,
                gcs_client: None,
            },
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        })
        .oneshot(
            Request::builder()
                .uri("/files/FILE-gcs-none")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn gcs_download_surfaces_signed_url_errors() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        insert_agreement(&db, "FILE-gcs-bad", "gcs.bin", 12, true).await;

        let response = router(DownloadServerState {
            db,
            storage_dir,
            storage_backend: gcs_backend_with_key("not-a-key").await,
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        })
        .oneshot(
            Request::builder()
                .uri("/files/FILE-gcs-bad")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn response_builder_uses_defaults_for_missing_fields() {
        let agreement = dummy_agreement("FILE-meta", "", "", -1);
        let response = handlers::response_builder_test(&agreement)
            .unwrap()
            .body(Body::empty())
            .unwrap();

        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert!(headers.get(header::CONTENT_DISPOSITION).is_none());
        assert!(headers.get(header::CONTENT_LENGTH).is_none());
    }

    #[test]
    fn download_error_into_response_maps_status_codes() {
        let responses = [
            (
                DownloadError::NotFound.into_response(),
                StatusCode::NOT_FOUND,
            ),
            (
                DownloadError::StorageUnavailable.into_response(),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                DownloadError::Upstream("boom".into()).into_response(),
                StatusCode::BAD_GATEWAY,
            ),
            (
                DownloadError::Internal("oops".into()).into_response(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (resp, expected) in responses {
            assert_eq!(resp.status(), expected);
        }
    }

    #[test]
    fn list_files_error_internal_masks_message() {
        let resp = ListFilesError::Internal("boom".into()).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn node_info_returns_node_id() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-info-test".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["node_id"], "NODE-info-test");
    }

    #[tokio::test]
    async fn dashboard_returns_html() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-dash".to_string()),
            admin: AdminState::disabled(),
        };

        let app = router(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains("text/html"),
            "expected text/html content type, got {ct}"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(!html.is_empty(), "dashboard HTML should not be empty");
    }

    #[test]
    fn download_error_not_ready_returns_conflict() {
        let resp = DownloadError::NotReady.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn cors_layer_injects_access_control_allow_origin_for_file_download() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        let file_id = "FILE-cors";
        let content = Bytes::from_static(b"cors body");
        let path = storage_dir.join(file_id);
        tokio::fs::write(&path, &content).await.unwrap();

        insert_agreement(&db, file_id, "cors.bin", content.len() as i64, true).await;

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/files/{file_id}"))
                    // Provide an Origin header so the CorsLayer is exercised
                    // in the same way a browser would.
                    .header(header::ORIGIN, "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*"),
            "CorsLayer should set Access-Control-Allow-Origin: *"
        );
        assert_eq!(
            headers
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .and_then(|v| v.to_str().ok()),
            Some("content-disposition"),
            "CorsLayer should expose Content-Disposition for browser downloads"
        );
        // Sanity: the handler must NOT inject CORS headers itself anymore;
        // this means there should only be one Allow-Origin value.
        assert_eq!(
            headers
                .get_all(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .iter()
                .count(),
            1,
            "Allow-Origin must be set exactly once (by the layer, not the handler)"
        );
    }

    #[tokio::test]
    async fn cors_layer_injects_access_control_allow_origin_for_gcs_redirect() {
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        insert_agreement(&db, "FILE-gcs-cors", "gcs.bin", 12, true).await;

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: gcs_backend_with_key(TEST_PRIVATE_KEY).await,
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/files/FILE-gcs-cors")
                    .header(header::ORIGIN, "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*"),
            "CorsLayer should also cover redirect responses"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serve_local_returns_internal_when_file_not_readable() {
        use std::os::unix::fs::PermissionsExt;

        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        let file_path = storage_dir.join("FILE-noperm");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();
        tokio::fs::write(&file_path, b"data").await.unwrap();

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        insert_agreement(&db, "FILE-noperm", "noperm.bin", 4, true).await;

        let response = router(DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        })
        .oneshot(
            Request::builder()
                .uri("/files/FILE-noperm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644)).ok();
    }

    #[test]
    fn list_files_error_bad_request_returns_400() {
        let resp = ListFilesError::BadRequest("bad".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serves_local_file_with_inline_disposition_when_inline_query() {
        // Cover the inline content-disposition branch (line 278 in handlers.rs).
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");
        tokio::fs::create_dir_all(&storage_dir).await.unwrap();

        let file_id = "FILE-inline";
        let filename = "image.png";
        let content = Bytes::from_static(b"PNGdata");
        tokio::fs::write(storage_dir.join(file_id), &content)
            .await
            .unwrap();

        insert_agreement(&db, file_id, filename, content.len() as i64, true).await;

        let response = router(DownloadServerState {
            db,
            storage_dir,
            storage_backend: StorageBackend::local(),
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        })
        .oneshot(
            Request::builder()
                .uri(format!("/files/{file_id}?inline=true"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let disposition = response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            disposition.starts_with("inline;"),
            "expected inline disposition, got: {disposition}"
        );
        assert!(
            disposition.contains(filename),
            "filename should be included: {disposition}"
        );
    }

    #[tokio::test]
    async fn gcs_download_uses_mime_type_when_inline_query() {
        // Cover the inline=true branch on serve_gcs (line 218 in handlers.rs)
        // by including ?inline=true so mime_type is forwarded to the signed URL.
        let db = setup_db().await;
        let storage_dir = unique_storage_dir("server");

        let mut fx = AgreementFixture::new("AGREEMENT-FILE-gcs-inline", "FILE-gcs-inline");
        fx.user_id = "user".into();
        fx.filename = "photo.png".into();
        fx.mime_type = "image/png".into();
        fx.original_size = 12;
        fx.nodes = serde_json::json!([]);
        fx.padded_len = Some(12);
        fx.downloaded = true;
        fx.created_at = chrono::Utc::now().fixed_offset();
        fx.into_active_model().insert(&db).await.unwrap();

        let state = DownloadServerState {
            db,
            storage_dir,
            storage_backend: gcs_backend_with_key(TEST_PRIVATE_KEY).await,
            node_id: Some("NODE-TEST".to_string()),
            admin: AdminState::disabled(),
        };

        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/files/FILE-gcs-inline?inline=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        assert!(
            location.contains("response-content-type=image%2Fpng"),
            "expected image/png mime in signed URL when inline=true, got {location}"
        );
        assert!(
            location.contains("inline"),
            "expected inline disposition in signed URL, got {location}"
        );
    }
}
