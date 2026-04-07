//! HTTP download server module.
//!
//! Provides a REST API for downloading stored files and listing available files.

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

    axum::serve(listener, router(state))
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
    use crate::server::handlers::{DownloadError, FilesResponse, ListFilesError};
    use crate::testutils::unique_storage_dir;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::IntoResponse;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
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
        let active = agreements::ActiveModel {
            agreement_id: Set(format!("AGREEMENT-{}", file_id)),
            user_id: Set("user".into()),
            file_id: Set(file_id.into()),
            filename: Set(filename.into()),
            mime_type: Set("application/octet-stream".into()),
            original_size: Set(size),
            nodes: Set(serde_json::json!([])),
            root: Set(None),
            padded_len: Set(Some(size)),
            downloaded: Set(downloaded),
            transaction_id: Set(None),
            curation: Set(serde_json::json!({})),
            status: Set("ready".into()),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };

        active.insert(db).await.expect("insert agreement");
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
            downloaded: true,
            transaction_id: None,
            curation: serde_json::json!({}),
            status: "ready".into(),
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnumunEUnoZIs5\nDhEXTNTyJPFxsZMxgRhLs7m6aiVu7GrDgoWFMoLy/B6Ccl2c9ml/RzuK5uKbJKM9\ntcwA90gpp536aLWB0BbQuWtfceU3BmQWFtQRXqCww/o462cujXhcMe5bVPvE9b/5\nyV+oWmKa42tw4x5//Cj8LGAw8aQwlC+OQ19iA+vmKx7xjs0uBFtQHnjGxekT71vp\nLgv53SVi5yUscz9Scy/VuBkNfOCaEz5zV+EUplYuvRMVEJ0Pvk1wOYjby4Gz+OVI\nrp1+1RFBEeTu2zo06E4o23pfz5DbZaBMZ8qK3WkNx6eQOuYK6Zrq+zM5/Uoq6fqQ\nAIuYpCNxAgMBAAECggEAB1pTx9IpNEfcFpc4RpY2q5rU/s/zDPOE1iS92p82nuM8\nVu/M3Kb3OKG20K8kzXG79DlyMcenXXfAtD7Y/53XiwPvGAApHNS7e1D1lQyQKNZd\n4t4DU/ObBcTBnmcrcc3/3cLOmTBjjSHc1Z1vVRkJQ5L+rcc3GhM61Ls5SEv/j6WN\nFw/fnYGtxUUXBz1gVvok0o89qTgW0Pt7SWrUkbAhrsGeTFpzNbicgRsBUXJJdRcl\nvK5rwKSPUhiIVhpQ78usSLdO30X3Bfvf/GQpR56/UgDqkn20ZMpJhKrAxSbmLSu9\nhgkIbLAlABxdYUbGFp5aTALAJ8EyZn8MU9RRuL9DcQKBgQDp263xaTlx8BgbKnq1\nwY+SxuDlGz/LoGYjF6v6FNHM1hQ5v2FpxaxF5EDUm3fdh+Z9yegL/g8GQdQQnelG\nA43VACvGAESw1ilsBDl6TZ+LZY4MTQrWSGUqQxt3APu3lHDAXkipHu2X3cv/3VrO\nDGs2WYWPiMxg1ZkIBojyZQ0SnQKBgQC3m910nvJIJ+WLXeXiG2qN147/5GU7Yma2\n0pEhQ4XVN/f7joGzUXLeB0BXNNbdKuRqEQ1r2VkH3qqY6HAL6/fK01qEhWBLv1hu\ndkEhEruK9WxzA/vLgmqFBsi04IFlnK70RCXckWZEHFjnnoutqAWpl7FTRiTeT8Bv\nHgmX2+lh5QKBgDAuADIiWaFts6m1IL7dd/TnYGITMRuEmkZUlCvbqjWnTVdwZGNk\nRE/J7Mlglltfqk70EAiYeQPy//vEbNDt3oSpmlsapww/sxz76dOWtm4DqDZEkR0A\noUcJuFjWLQXvYSNgyVt+cbi+C09VjWWyDUyPOQMPTfwNRY/vuLsnsn/JAoGBAKrW\n0Ri46DBxRukFJmfbIKr3/etlZTf7GB1WEYnE3RsGZ6vd7hqeV2X1k01RMfc5+Kwk\nT7ug0XE8IroB1HeTSM2lGJ0jyPTSBoNJbtJKLsxeDVl7RGcYYuqB5HBAUMXuIu/P\nFPeFJoWLZsGkyMx9AT/KkEkuhBGCXUhGx6BQE3htAoGAbEGbhHV8oU7NYKEmVyWM\nwfEQXGH2QQpHsj7xkTywOKEneaMkVUzA5GwF7CQEvk/2xXEgze+haaRGxFQJTO5m\nGK2ECeQhTwXvNi+3/MEMCdoPYuckF4hCVzsGwfkVBPf1zcOw0k0+EEsqbWwtXi2l\njIyC7b2m2fgAI0Ltt1btCfo=\n-----END PRIVATE KEY-----";

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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
            node_id: "NODE-info-test".to_string(),
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
            node_id: "NODE-dash".to_string(),
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
            node_id: "NODE-TEST".to_string(),
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
}
