#![allow(dead_code)] // Temporary until new Portal client methods are wired into commands.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

#[derive(Clone, Debug)]
pub struct PortalClient {
    base_url: String,
    api_key: String,
    storage_dir: PathBuf,
    http: Client,
}

impl PortalClient {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
    ) -> Self {
        let base_url = base_url.into();
        Self {
            base_url,
            api_key: api_key.into(),
            storage_dir: storage_dir.into(),
            http: Client::new(),
        }
    }

    pub async fn ping(&self) -> Result<String> {
        let url = format!("{}/health", self.base_url.trim_end_matches('/'));
        let resp = self.http.get(url).bearer_auth(&self.api_key).send().await?;
        let status = resp.status();
        let body = resp.text().await?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(anyhow!("Portal ping failed with status {status}: {body}"))
        }
    }

    /// Fetch agreements that are marked as new.
    pub async fn get_new_agreements(&self) -> Result<AgreementsPage> {
        let url = format!(
            "{}/api/agreements?status=new",
            self.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(url).bearer_auth(&self.api_key).send().await?;
        let status = resp.status();

        if status.is_success() {
            let page = resp
                .json::<AgreementsPage>()
                .await
                .context("failed to deserialize agreements page")?;
            Ok(page)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!(
                "failed to fetch new agreements with status {status}: {body}"
            ))
        }
    }

    /// Join an agreement using the provided UTXO.
    pub async fn join_agreement(
        &self,
        agreement_id: &str,
        utxo: &str,
    ) -> Result<JoinAgreementResponse> {
        let url = format!(
            "{}/api/agreements/{agreement_id}/join",
            self.base_url.trim_end_matches('/')
        );
        let payload = JoinAgreementRequest {
            utxo: utxo.to_string(),
        };

        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await?;
        let status = resp.status();

        if status.is_success() {
            let body = resp
                .json::<JoinAgreementResponse>()
                .await
                .context("failed to deserialize join response")?;
            Ok(body)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!(
                "failed to join agreement {agreement_id} with status {status}: {body}"
            ))
        }
    }

    /// Download an agreement file into the configured storage directory.
    pub async fn download_file(
        &self,
        agreement_id: &str,
        filename: &str,
    ) -> Result<DownloadedFile> {
        let download_url = self.fetch_download_url(agreement_id).await?;
        let target_path = self.storage_dir.join(filename);

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("unable to create storage directory {}", parent.display())
            })?;
        }

        let bytes = self
            .http
            .get(download_url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("failed to download file for agreement {agreement_id}"))?
            .bytes()
            .await
            .context("failed to read downloaded bytes")?;

        fs::write(&target_path, &bytes).await.with_context(|| {
            format!(
                "unable to write downloaded file to {}",
                target_path.display()
            )
        })?;

        Ok(DownloadedFile {
            path: target_path,
            bytes,
        })
    }

    async fn fetch_download_url(&self, agreement_id: &str) -> Result<String> {
        let url = format!(
            "{}/api/agreements/{agreement_id}/download?no_redirect=true",
            self.base_url.trim_end_matches('/')
        );
        let resp = self.http.get(url).bearer_auth(&self.api_key).send().await?;
        let status = resp.status();

        if status.is_success() {
            let body = resp
                .json::<DownloadUrlResponse>()
                .await
                .context("failed to parse download url response")?;
            Ok(body.download_url)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!(
                "failed to request download url for agreement {agreement_id} with status {status}: {body}"
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AgreementsPage {
    pub offset: u32,
    pub limit: u32,
    pub total: u32,
    pub agreements: Vec<Agreement>,
}

#[derive(Debug, Deserialize)]
pub struct Agreement {
    pub agreement_id: String,
    pub user_id: String,
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub original_size: u64,
    pub nodes: Vec<String>,
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub curation: serde_json::Value,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct JoinAgreementResponse {
    pub agreement_id: String,
    pub node_id: String,
    pub utxo: String,
    pub joined_at: String,
    pub created: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct JoinAgreementRequest {
    utxo: String,
}

#[derive(Debug, Deserialize)]
struct DownloadUrlResponse {
    download_url: String,
}

#[derive(Debug, Clone)]
pub struct DownloadedFile {
    pub path: PathBuf,
    pub bytes: Bytes,
}

#[cfg(test)]
mod tests {
    use super::PortalClient;
    use bytes::Bytes;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn storage_dir(name: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join("portal_client")
            .join(format!("{name}_{id}"));
        fs::create_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn portal_client_new_stores_base_url() {
        let client = PortalClient::new("https://example.com/api", "secret", "/tmp/storage");
        assert_eq!(client.base_url, "https://example.com/api");
    }

    #[test]
    fn portal_client_new_trims_trailing_slash_in_ping() {
        let client = PortalClient::new("https://example.com/api/", "secret", "/tmp/storage");
        // The trailing slash trimming happens in ping(), not in new()
        assert_eq!(client.base_url, "https://example.com/api/");
    }

    #[tokio::test]
    async fn ping_success_returns_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("ping_success"));
        let result = client.ping().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "OK");
    }

    #[tokio::test]
    async fn ping_success_with_trailing_slash() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("healthy"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(
            format!("{}/", mock_server.uri()),
            "secret",
            storage_dir("ping_trailing"),
        );
        let result = client.ping().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "healthy");
    }

    #[tokio::test]
    async fn ping_failure_returns_error_with_status_and_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("ping_fail"));
        let result = client.ping().await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("500"));
        assert!(error_message.contains("Internal Server Error"));
    }

    #[tokio::test]
    async fn ping_failure_on_404() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("ping_404"));
        let result = client.ping().await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("404"));
    }

    #[tokio::test]
    async fn get_new_agreements_requests_new_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "agreements": [{
                    "agreement_id": "AGREEMENT-123",
                    "user_id": "user_1",
                    "file_id": "FILE-abc",
                    "filename": "contract.pdf",
                    "mime_type": "application/pdf",
                    "original_size": 1024,
                    "nodes": ["NODE-1"],
                    "transaction_id": null,
                    "curation": {},
                    "status": "new",
                    "created_at": "2024-01-15T10:30:00Z"
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("agreements"));
        let page = client.get_new_agreements().await.unwrap();

        assert_eq!(page.total, 1);
        assert_eq!(page.agreements.len(), 1);
        assert_eq!(page.agreements[0].agreement_id, "AGREEMENT-123");
    }

    #[tokio::test]
    async fn join_agreement_posts_utxo() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-join";

        Mock::given(method("POST"))
            .and(path(format!("/api/agreements/{agreement_id}/join")))
            .and(header("authorization", "Bearer secret"))
            .and(body_json(json!({ "utxo": "txid:1" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agreement_id": agreement_id,
                "node_id": "NODE-9f8e",
                "utxo": "txid:1",
                "joined_at": "2025-01-01T00:00:00Z",
                "created": true
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("join"));
        let response = client.join_agreement(agreement_id, "txid:1").await.unwrap();

        assert_eq!(response.agreement_id, agreement_id);
        assert!(response.created);
    }

    #[tokio::test]
    async fn download_file_writes_to_storage_dir() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-download";
        let download_url_path = "/files/sample.txt";
        let download_url = format!("{}{}", mock_server.uri(), download_url_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_url_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&mock_server)
            .await;

        let dir = storage_dir("download");
        let client = PortalClient::new(mock_server.uri(), "secret", dir.clone());
        let downloaded = client
            .download_file(agreement_id, "sample.txt")
            .await
            .unwrap();

        let contents = fs::read_to_string(&downloaded.path).unwrap();
        assert_eq!(contents, "hello world");
        assert_eq!(downloaded.bytes, Bytes::from_static(b"hello world"));
    }

    #[tokio::test]
    async fn join_agreement_returns_error_on_failure() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-error";

        Mock::given(method("POST"))
            .and(path(format!("/api/agreements/{agreement_id}/join")))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("join_error"));
        let err = client
            .join_agreement(agreement_id, "txid:0")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 400"),
            "expected error to include status, got {err}"
        );
    }

    #[tokio::test]
    async fn download_file_propagates_http_error() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-http-error";
        let download_url = format!("{}/files/error", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/files/error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), "secret", storage_dir("download_http"));
        let err = client
            .download_file(agreement_id, "file.bin")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("failed to download file"),
            "expected http error to be surfaced, got {err}"
        );
    }

    #[tokio::test]
    async fn download_file_errors_when_storage_dir_is_file() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-bad-dir";
        let download_url = format!("{}/files/ok", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .and(header("authorization", "Bearer secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/files/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let storage_file = storage_dir("storage_file");
        std::fs::remove_dir_all(&storage_file).ok();
        std::fs::create_dir_all(storage_file.parent().unwrap()).unwrap();
        std::fs::write(&storage_file, "not a dir").unwrap();

        let client = PortalClient::new(mock_server.uri(), "secret", storage_file.clone());
        let err = client
            .download_file(agreement_id, "ignored.bin")
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("unable to create storage directory"),
            "expected directory creation error, got {err}"
        );
    }
}
