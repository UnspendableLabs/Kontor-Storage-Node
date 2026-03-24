use super::http_helpers::{build_http_client, check_response_status};
use super::http_signature;
use crate::crypto::BlsKeyPair;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::OnceCell;

/// Instruction names for BLS-signed Portal operations.
const INSTRUCTION_JOIN_AGREEMENT: &str = "join_agreement";
const INSTRUCTION_SEND_PROOF: &str = "send_proof";

/// Authentication credentials for Portal API requests.
#[derive(Clone)]
pub struct PortalAuth {
    keypair: Arc<BlsKeyPair>,
    node_id: String,
    signer_id: u64,
    token: String,
}

impl std::fmt::Debug for PortalAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalAuth")
            .field("node_id", &self.node_id)
            .field("signer_id", &self.signer_id)
            .field("keypair", &"<BlsKeyPair>")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct PortalClient {
    base_url: String,
    storage_dir: PathBuf,
    http: Client,
    /// Optional authentication for signed requests.
    auth: Option<PortalAuth>,
    /// Cached portal signing xpub (fetched lazily on first use).
    cached_portal_xpub: Arc<OnceCell<String>>,
}

impl std::fmt::Debug for PortalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalClient")
            .field("base_url", &self.base_url)
            .field("storage_dir", &self.storage_dir)
            .field("auth", &self.auth)
            .field("cached_portal_xpub", &self.cached_portal_xpub.get())
            .finish()
    }
}

impl PortalClient {
    /// Create an unauthenticated client for public endpoints only.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built (e.g., TLS initialization fails).
    pub fn new(base_url: impl Into<String>, storage_dir: impl Into<PathBuf>) -> Self {
        Self::try_new(base_url, storage_dir).expect("building Portal HTTP client")
    }

    /// Create an unauthenticated client, returning an error if building fails.
    pub fn try_new(base_url: impl Into<String>, storage_dir: impl Into<PathBuf>) -> Result<Self> {
        let http = build_http_client().context("building Portal HTTP client")?;
        // Normalize URL by trimming trailing slashes once at construction time
        let normalized_url = base_url.into().trim_end_matches('/').to_string();
        Ok(Self {
            base_url: normalized_url,
            storage_dir: storage_dir.into(),
            http,
            auth: None,
            cached_portal_xpub: Arc::new(OnceCell::new()),
        })
    }

    /// Create an authenticated client with BLS keypair for signed requests.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built (e.g., TLS initialization fails).
    pub fn with_auth(
        base_url: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
        keypair: Arc<BlsKeyPair>,
        node_id: impl Into<String>,
        signer_id: u64,
        token: impl Into<String>,
    ) -> Self {
        Self::try_with_auth(base_url, storage_dir, keypair, node_id, signer_id, token)
            .expect("building Portal HTTP client")
    }

    /// Create an authenticated client, returning an error if building fails.
    pub fn try_with_auth(
        base_url: impl Into<String>,
        storage_dir: impl Into<PathBuf>,
        keypair: Arc<BlsKeyPair>,
        node_id: impl Into<String>,
        signer_id: u64,
        token: impl Into<String>,
    ) -> Result<Self> {
        let http = build_http_client().context("building Portal HTTP client")?;
        // Normalize URL by trimming trailing slashes once at construction time
        let normalized_url = base_url.into().trim_end_matches('/').to_string();
        Ok(Self {
            base_url: normalized_url,
            storage_dir: storage_dir.into(),
            http,
            auth: Some(PortalAuth {
                keypair,
                node_id: node_id.into(),
                signer_id,
                token: token.into(),
            }),
            cached_portal_xpub: Arc::new(OnceCell::new()),
        })
    }

    /// Get the node ID if authenticated.
    pub fn node_id(&self) -> Option<&str> {
        self.auth.as_ref().map(|a| a.node_id.as_str())
    }

    /// Get the signer ID if authenticated.
    #[allow(dead_code)]
    pub fn signer_id(&self) -> Option<u64> {
        self.auth.as_ref().map(|a| a.signer_id)
    }

    fn auth_headers(
        &self,
        _method: &str,
        _target_uri: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<Option<reqwest::header::HeaderMap>> {
        match &self.auth {
            Some(auth) => {
                let mut headers = reqwest::header::HeaderMap::new();
                let bearer = format!("Bearer {}", auth.token);
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&bearer)
                        .map_err(|e| anyhow!("invalid authorization header: {e}"))?,
                );
                if let Some((body_bytes, content_type)) = body {
                    let digest = http_signature::content_digest(body_bytes);
                    headers.insert(
                        "Content-Digest",
                        reqwest::header::HeaderValue::from_str(&digest)
                            .map_err(|e| anyhow!("invalid content-digest header: {e}"))?,
                    );
                    headers.insert(
                        "Content-Type",
                        reqwest::header::HeaderValue::from_str(content_type)
                            .map_err(|e| anyhow!("invalid content-type header: {e}"))?,
                    );
                    headers.insert(
                        "Content-Length",
                        reqwest::header::HeaderValue::from(body_bytes.len()),
                    );
                }
                Ok(Some(headers))
            }
            None => Ok(None),
        }
    }

    /// Build a request with optional auth headers.
    ///
    /// This helper consolidates the common pattern of creating an HTTP request
    /// and adding JWT Bearer auth headers when authentication is configured.
    ///
    /// # Arguments
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `url` - Full URL for the request
    /// * `path` - API path used for auth (without base URL)
    /// * `body` - Optional tuple of (body bytes, content type) for POST requests
    ///
    /// # Returns
    /// A `RequestBuilder` with auth headers added if authenticated
    fn build_signed_request(
        &self,
        method: reqwest::Method,
        url: &str,
        path: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut request = self.http.request(method.clone(), url);

        if let Some(headers) = self.auth_headers(method.as_str(), path, body)? {
            for (name, value) in headers.iter() {
                request = request.header(name, value);
            }
        }

        Ok(request)
    }

    /// Get the full URL for an API path (for signing).
    fn api_path(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Fetches all pages using the provided page fetcher function.
    ///
    /// This generic helper handles the common pagination pattern used across
    /// multiple API endpoints. It repeatedly calls the fetcher with increasing
    /// offsets until all items have been retrieved.
    ///
    /// # Arguments
    /// * `fetch_page` - An async function that takes an offset and returns a paginated response
    ///
    /// # Returns
    /// A vector containing all items from all pages
    async fn paginate<T, P, F, Fut>(&self, mut fetch_page: F) -> Result<Vec<T>>
    where
        P: PaginatedResponse<Item = T>,
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = Result<P>>,
    {
        let mut all_items = Vec::new();
        let mut offset = 0u32;

        loop {
            let page = fetch_page(offset).await?;
            let total = page.total();
            let items = page.into_items();
            let fetched = items.len() as u32;
            all_items.extend(items);

            // Check if we've fetched everything
            if offset + fetched >= total {
                break;
            }
            offset += fetched;
        }

        Ok(all_items)
    }

    pub async fn ping(&self) -> Result<String> {
        let url = format!("{}/health", self.base_url);
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(anyhow!("portal ping failed with status {status}: {body}"))
        }
    }

    /// Look up a node by its BLS public key.
    pub async fn lookup_node(&self, bls_pubkey: &str) -> Result<NodeLookupResult> {
        let url = format!("{}/api/nodes/lookup", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("bls_pubkey", bls_pubkey)])
            .send()
            .await?;
        let resp = check_response_status(resp, "lookup node by BLS pubkey").await?;
        resp.json::<NodeLookupResult>()
            .await
            .context("failed to deserialize node lookup result")
    }

    /// Request a login challenge for the given user/node ID.
    pub async fn login_challenge(&self, user_id: &str) -> Result<LoginChallenge> {
        let url = format!("{}/api/users/login", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("user_id", user_id)])
            .send()
            .await?;
        let resp = check_response_status(resp, "fetch login challenge").await?;
        resp.json::<LoginChallenge>()
            .await
            .context("failed to deserialize login challenge")
    }

    /// Submit a signed login challenge to obtain a JWT.
    pub async fn login_submit(
        &self,
        user_id: &str,
        challenge: &str,
        signature: &str,
    ) -> Result<LoginResponse> {
        let url = format!("{}/api/users/login", self.base_url);
        let payload = LoginRequest {
            user_id: user_id.to_string(),
            challenge: challenge.to_string(),
            signature: signature.to_string(),
        };
        let resp = self.http.post(&url).json(&payload).send().await?;
        let resp = check_response_status(resp, "submit login").await?;
        resp.json::<LoginResponse>()
            .await
            .context("failed to deserialize login response")
    }

    /// Fetch a registry entry by signer ID.
    pub async fn get_registry_entry(&self, signer_id: u64) -> Result<RegistryEntry> {
        let url = format!("{}/api/registry/entry/{}", self.base_url, signer_id);
        let resp = self.http.get(&url).send().await?;
        let resp = check_response_status(resp, "fetch registry entry").await?;
        resp.json::<RegistryEntry>()
            .await
            .context("failed to deserialize registry entry")
    }

    /// Fetch the Portal signing xpub from the public API endpoint.
    /// This xpub is used to bind agreement signatures to this Portal.
    #[cfg(test)]
    pub async fn get_portal_signing_xpub(&self) -> Result<String> {
        self.get_or_fetch_portal_xpub().await.cloned()
    }

    /// Get the cached portal signing xpub, or fetch it if not yet cached.
    /// The xpub is cached for the lifetime of the client.
    async fn get_or_fetch_portal_xpub(&self) -> Result<&String> {
        self.cached_portal_xpub
            .get_or_try_init(|| async {
                let url = format!("{}/api/", self.base_url);
                let resp = self.http.get(&url).send().await?;
                let resp = check_response_status(resp, "fetch portal signing xpub").await?;
                let body = resp
                    .json::<PortalInfoResponse>()
                    .await
                    .context("failed to deserialize portal info")?;
                Ok(body.portal_signing_xpub)
            })
            .await
    }

    /// Fetch all agreements that are marked as new or ready.
    ///
    /// This method handles pagination automatically, fetching all pages.
    /// Requires authentication via JWT Bearer token.
    pub async fn get_new_agreements(&self) -> Result<Vec<Agreement>> {
        self.paginate(|offset| self.get_agreements_page(offset))
            .await
    }

    /// Fetch a single page of agreements with the given offset.
    async fn get_agreements_page(&self, offset: u32) -> Result<AgreementsPage> {
        let path = format!("/api/agreements?status=new|ready&offset={offset}");
        let url = self.api_path(&path);

        let request = self.build_signed_request(Method::GET, &url, &path, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(resp, "fetch new agreements").await?;
        let page = resp
            .json::<AgreementsPage>()
            .await
            .context("failed to deserialize agreements page")?;
        Ok(page)
    }

    /// Sign a Portal instruction with BLS.
    ///
    /// This helper:
    /// 1. Fetches the Portal signing xpub (cached)
    /// 2. Serializes `(portal_signing_xpub, instruction)` with postcard
    /// 3. Signs with the BLS keypair using the agreement DST
    ///
    /// Returns the hex-encoded BLS signature.
    async fn sign_instruction(&self, instruction: Vec<String>) -> Result<String> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| anyhow!("authentication required: no keypair configured"))?;

        let portal_xpub = self.get_or_fetch_portal_xpub().await?;

        let message = postcard::to_allocvec(&(portal_xpub, instruction))
            .context("failed to serialize instruction")?;

        auth.keypair.sign_agreement_instruction(&message)
    }

    /// Join an agreement as a storage node.
    ///
    /// This method:
    /// 1. Fetches the Portal signing xpub (cached after first fetch)
    /// 2. Creates a BLS signature over `(portal_signing_xpub, ["join_agreement", node_id, agreement_id])`
    /// 3. Submits the join request with both JWT auth and agreement signature
    ///
    /// Requires authentication via JWT Bearer token.
    pub async fn join_agreement(&self, agreement_id: &str) -> Result<JoinAgreementResponse> {
        let node_id = self
            .node_id()
            .ok_or_else(|| anyhow!("authentication required to join agreement"))?
            .to_string();

        let instruction = vec![
            INSTRUCTION_JOIN_AGREEMENT.to_string(),
            node_id,
            agreement_id.to_string(),
        ];
        let bls_signature = self.sign_instruction(instruction).await?;

        let path = format!("/api/agreements/{agreement_id}/join");
        let url = self.api_path(&path);

        let payload = JoinAgreementRequest { bls_signature };
        let body_bytes =
            serde_json::to_vec(&payload).context("failed to serialize join request")?;

        let request = self.build_signed_request(
            Method::POST,
            &url,
            &path,
            Some((&body_bytes, "application/json")),
        )?;

        let resp = request.body(body_bytes).send().await?;
        let resp = check_response_status(resp, &format!("join agreement {agreement_id}")).await?;
        let body = resp
            .json::<JoinAgreementResponse>()
            .await
            .context("failed to deserialize join response")?;
        Ok(body)
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
        let path = format!("/api/agreements/{agreement_id}/download?no_redirect=true");
        let url = self.api_path(&path);

        let request = self.build_signed_request(Method::GET, &url, &path, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(
            resp,
            &format!("request download url for agreement {agreement_id}"),
        )
        .await?;
        let body = resp
            .json::<DownloadUrlResponse>()
            .await
            .context("failed to parse download url response")?;
        Ok(body.download_url)
    }

    /// Fetch all active challenges for this node.
    ///
    /// This method handles pagination automatically, fetching all pages.
    /// Requires authentication via JWT Bearer token.
    pub async fn get_node_challenges(&self) -> Result<Vec<Challenge>> {
        self.paginate(|offset| self.get_challenges_page(offset))
            .await
    }

    /// Fetch a single page of challenges with the given offset.
    async fn get_challenges_page(&self, offset: u32) -> Result<ChallengesPage> {
        let auth = self.auth.as_ref().ok_or_else(|| {
            anyhow!("authentication required to fetch challenges: no keypair configured")
        })?;

        let path = format!(
            "/api/nodes/{}/challenges?status=active&offset={offset}",
            auth.node_id
        );
        let url = self.api_path(&path);

        let request = self.build_signed_request(Method::GET, &url, &path, None)?;

        let resp = request.send().await?;
        let resp =
            check_response_status(resp, &format!("fetch challenges for node {}", auth.node_id))
                .await?;
        let page = resp
            .json::<ChallengesPage>()
            .await
            .context("failed to deserialize challenges page")?;
        Ok(page)
    }

    /// Submit a storage proof for a challenge.
    ///
    /// This method:
    /// 1. Fetches the Portal signing xpub (cached)
    /// 2. Creates a BLS signature over `(portal_signing_xpub, ["send_proof", node_id, proof_hex])`
    /// 3. Submits the proof with both JWT auth and BLS signature
    ///
    /// Requires authentication.
    pub async fn submit_proof(
        &self,
        challenge_id: &str,
        proof_hex: &str,
    ) -> Result<SubmitProofResponse> {
        let node_id = self
            .node_id()
            .ok_or_else(|| anyhow!("authentication required to submit proof"))?
            .to_string();

        let instruction = vec![
            INSTRUCTION_SEND_PROOF.to_string(),
            node_id,
            proof_hex.to_string(),
        ];
        let bls_signature = self.sign_instruction(instruction).await?;

        let path = format!("/api/challenges/{challenge_id}");
        let url = self.api_path(&path);

        let payload = SubmitProofRequest {
            proof: proof_hex.to_string(),
            bls_signature,
        };
        let body_bytes =
            serde_json::to_vec(&payload).context("failed to serialize submit proof request")?;

        let request = self.build_signed_request(
            Method::POST,
            &url,
            &path,
            Some((&body_bytes, "application/json")),
        )?;

        let resp = request.body(body_bytes).send().await?;
        let resp =
            check_response_status(resp, &format!("submit proof for challenge {challenge_id}"))
                .await?;
        let body = resp
            .json::<SubmitProofResponse>()
            .await
            .context("failed to deserialize submit proof response")?;
        Ok(body)
    }
}

/// Trait for paginated API responses.
///
/// This trait allows the generic `paginate` helper to work with different
/// paginated response types (agreements, challenges, etc.).
trait PaginatedResponse {
    type Item;

    /// Returns the total number of items across all pages.
    fn total(&self) -> u32;

    /// Consumes the response and returns the items from this page.
    fn into_items(self) -> Vec<Self::Item>;
}

#[derive(Debug, Deserialize)]
struct AgreementsPage {
    total: u32,
    agreements: Vec<Agreement>,
}

impl PaginatedResponse for AgreementsPage {
    type Item = Agreement;

    fn total(&self) -> u32 {
        self.total
    }

    fn into_items(self) -> Vec<Self::Item> {
        self.agreements
    }
}

#[derive(Debug, Deserialize)]
struct ChallengesPage {
    total: u32,
    challenges: Vec<Challenge>,
}

impl PaginatedResponse for ChallengesPage {
    type Item = Challenge;

    fn total(&self) -> u32 {
        self.total
    }

    fn into_items(self) -> Vec<Self::Item> {
        self.challenges
    }
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub agreement_id: String,
    pub block_height: u64,
    pub challenge_count: u64,
    pub seed: String,
    pub prover_id: String,
    pub deadline_height: u64,
    pub status: String,
    pub proof: Option<String>,
    pub bls_signature: Option<String>,
    pub created_at: String,
    pub updated_at: String,
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

/// Response from the Portal API root endpoint.
#[derive(Debug, Deserialize)]
struct PortalInfoResponse {
    portal_signing_xpub: String,
}

#[derive(Debug, Deserialize)]
pub struct JoinAgreementResponse {
    pub node_id: String,
    pub created: bool,
}

#[derive(Debug, Serialize)]
struct JoinAgreementRequest {
    bls_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitProofResponse {
    pub status: String,
    pub proof: Option<String>,
    pub bls_signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitProofRequest {
    proof: String,
    bls_signature: String,
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

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct NodeLookupResult {
    pub node_id: String,
    /// `None` when the `RegisterBlsKey` transaction has not been confirmed yet.
    pub signer_id: Option<u64>,
    pub bls_public_key: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct LoginChallenge {
    pub challenge: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
struct LoginRequest {
    user_id: String,
    challenge: String,
    signature: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub role: String,
    pub expires_in: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryEntry {
    pub signer_id: u64,
    pub x_only_pubkey: String,
    pub bls_pubkey: String,
    pub next_nonce: u64,
}

#[cfg(test)]
mod tests {
    use super::PortalClient;
    use crate::crypto::BlsKeyPair;
    use bytes::Bytes;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::matchers::{header_exists, method, path, query_param};
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
        let client = PortalClient::new("https://example.com/api", "/tmp/storage");
        assert_eq!(client.base_url, "https://example.com/api");
        assert!(client.auth.is_none());
    }

    #[test]
    fn portal_client_with_auth_stores_credentials() {
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            "https://example.com/api",
            "/tmp/storage",
            keypair,
            "NODE-test123",
            42,
            "test-jwt-token",
        );
        assert_eq!(client.base_url, "https://example.com/api");
        assert!(client.auth.is_some());
        assert_eq!(client.node_id(), Some("NODE-test123"));
    }

    #[test]
    fn portal_client_new_normalizes_trailing_slash() {
        let client = PortalClient::new("https://example.com/api/", "/tmp/storage");
        // The trailing slash is now trimmed at construction time
        assert_eq!(client.base_url, "https://example.com/api");
    }

    #[tokio::test]
    async fn ping_success_returns_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("ping_success"));
        let result = client.ping().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "OK");
    }

    #[tokio::test]
    async fn ping_success_with_trailing_slash() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("healthy"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(
            format!("{}/", mock_server.uri()),
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
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("ping_fail"));
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
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("ping_404"));
        let result = client.ping().await;

        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("404"));
    }

    #[tokio::test]
    async fn get_portal_signing_xpub_fetches_from_api_root() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("portal_xpub"));
        let xpub = client.get_portal_signing_xpub().await.unwrap();

        assert_eq!(xpub, "xpub661MyMwAqRbctest");
    }

    #[tokio::test]
    async fn get_new_agreements_requests_new_ready_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
            .and(query_param("offset", "0"))
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

        let client = PortalClient::new(mock_server.uri(), storage_dir("agreements"));
        let agreements = client.get_new_agreements().await.unwrap();

        assert_eq!(agreements.len(), 1);
        assert_eq!(agreements[0].agreement_id, "AGREEMENT-123");
    }

    #[tokio::test]
    async fn get_new_agreements_includes_auth_headers_when_authenticated() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "new|ready"))
            .and(query_param("offset", "0"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 0,
                "agreements": []
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("agreements_auth"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let agreements = client.get_new_agreements().await.unwrap();

        assert!(agreements.is_empty());
    }

    #[tokio::test]
    async fn join_agreement_requires_authentication() {
        let client = PortalClient::new("http://localhost:1234", storage_dir("join_no_auth"));
        let err = client.join_agreement("AGREEMENT-test").await.unwrap_err();

        assert!(
            err.to_string().contains("authentication required"),
            "expected auth error, got {err}"
        );
    }

    #[tokio::test]
    async fn join_agreement_sends_bls_signature() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-join";

        // Mock the portal xpub endpoint
        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        // Mock the join endpoint - verify it receives auth headers and bls_signature in body
        Mock::given(method("POST"))
            .and(path(format!("/api/agreements/{agreement_id}/join")))
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "agreement_id": agreement_id,
                "node_id": "NODE-test",
                "bls_signature": "0xabcdef...",
                "joined_at": "2025-01-01T00:00:00Z",
                "created": true
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("join"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let response = client.join_agreement(agreement_id).await.unwrap();

        assert!(response.created);
    }

    #[tokio::test]
    async fn join_agreement_returns_error_on_failure() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-error";

        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/agreements/{agreement_id}/join")))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("join_error"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let err = client.join_agreement(agreement_id).await.unwrap_err();

        assert!(
            err.to_string().contains("status 400"),
            "expected error to include status, got {err}"
        );
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
        let client = PortalClient::new(mock_server.uri(), dir.clone());
        let downloaded = client
            .download_file(agreement_id, "sample.txt")
            .await
            .unwrap();

        let contents = fs::read_to_string(&downloaded.path).unwrap();
        assert_eq!(contents, "hello world");
        assert_eq!(downloaded.bytes, Bytes::from_static(b"hello world"));
    }

    #[tokio::test]
    async fn download_file_propagates_http_error() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-http-error";
        let download_url = format!("{}/files/error", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
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

        let client = PortalClient::new(mock_server.uri(), storage_dir("download_http"));
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

        let client = PortalClient::new(mock_server.uri(), storage_file.clone());
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

    #[tokio::test]
    async fn download_file_errors_when_write_fails() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-permission";
        let download_url = format!("{}/files/read-only", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/files/read-only"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let storage_dir = storage_dir("write_fail");
        fs::create_dir_all(&storage_dir).unwrap();
        let mut perms = fs::metadata(&storage_dir).unwrap().permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&storage_dir, perms).unwrap();

        let client = PortalClient::new(mock_server.uri(), storage_dir.clone());
        let err = client
            .download_file(agreement_id, "read-only.bin")
            .await
            .unwrap_err();

        // Restore permissions for cleanup to avoid flaky FS state.
        let mut cleanup_perms = fs::metadata(&storage_dir).unwrap().permissions();
        cleanup_perms.set_mode(0o755);
        fs::set_permissions(&storage_dir, cleanup_perms).unwrap();

        assert!(
            err.to_string().contains("unable to write downloaded file"),
            "expected write error, got {err}"
        );
    }

    #[tokio::test]
    async fn download_file_surfaces_download_url_errors() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-missing";

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("download_url_error"));
        let err = client
            .download_file(agreement_id, "ignored.txt")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 404"),
            "expected status code to be in error, got {err}"
        );
    }

    #[tokio::test]
    async fn download_file_includes_auth_headers_when_authenticated() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-auth-download";
        let download_url_path = "/files/auth-sample.txt";
        let download_url = format!("{}{}", mock_server.uri(), download_url_path);

        Mock::given(method("GET"))
            .and(path(format!("/api/agreements/{agreement_id}/download")))
            .and(query_param("no_redirect", "true"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "download_url": download_url
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(download_url_path))
            .respond_with(ResponseTemplate::new(200).set_body_string("authenticated content"))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let dir = storage_dir("download_auth");
        let client = PortalClient::with_auth(
            mock_server.uri(),
            dir.clone(),
            keypair,
            "NODE-auth",
            42,
            "test-jwt-token",
        );
        let downloaded = client
            .download_file(agreement_id, "auth-sample.txt")
            .await
            .unwrap();

        let contents = fs::read_to_string(&downloaded.path).unwrap();
        assert_eq!(contents, "authenticated content");
    }

    #[tokio::test]
    async fn portal_signing_xpub_is_cached_across_multiple_join_calls() {
        let mock_server = MockServer::start().await;

        // Mock the portal xpub endpoint - expect exactly 1 call due to caching
        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbcCached"
            })))
            .expect(1) // Should only be called once due to caching
            .mount(&mock_server)
            .await;

        // Mock the join endpoint for multiple agreements
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGREEMENT-1/join"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "agreement_id": "AGREEMENT-1",
                "node_id": "NODE-cache-test",
                "bls_signature": "0xsig1",
                "joined_at": "2025-01-01T00:00:00Z",
                "created": true
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/agreements/AGREEMENT-2/join"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "agreement_id": "AGREEMENT-2",
                "node_id": "NODE-cache-test",
                "bls_signature": "0xsig2",
                "joined_at": "2025-01-01T00:00:00Z",
                "created": true
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("cache_test"),
            keypair,
            "NODE-cache-test",
            42,
            "test-jwt-token",
        );

        // Join two agreements - xpub should only be fetched once
        let resp1 = client.join_agreement("AGREEMENT-1").await.unwrap();
        let resp2 = client.join_agreement("AGREEMENT-2").await.unwrap();

        assert!(resp1.created);
        assert!(resp2.created);

        // The expect(1) on the mock will fail if xpub was fetched more than once
    }

    #[tokio::test]
    async fn submit_proof_requires_authentication() {
        let client = PortalClient::new("http://localhost:1234", storage_dir("proof_no_auth"));
        let err = client
            .submit_proof("CHALLENGE-test", "0102030405")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("authentication required"),
            "expected auth error, got {err}"
        );
    }

    #[tokio::test]
    async fn submit_proof_sends_proof_and_bls_signature() {
        let mock_server = MockServer::start().await;
        let challenge_id = "CHALLENGE-proof";

        // Mock the portal xpub endpoint
        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        // Mock the submit proof endpoint - verify it receives auth headers
        Mock::given(method("POST"))
            .and(path(format!("/api/challenges/{challenge_id}")))
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge_id": challenge_id,
                "status": "proved",
                "proof": "0102030405060708",
                "bls_signature": "8a3b4c5d6e7f..."
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("proof_submit"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let response = client
            .submit_proof(challenge_id, "0102030405060708")
            .await
            .unwrap();

        assert_eq!(response.status, "proved");
        assert_eq!(response.proof, Some("0102030405060708".to_string()));
    }

    #[tokio::test]
    async fn submit_proof_returns_error_on_failure() {
        let mock_server = MockServer::start().await;
        let challenge_id = "CHALLENGE-error";

        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/challenges/{challenge_id}")))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid proof"))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("proof_error"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let err = client
            .submit_proof(challenge_id, "badproof")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 400"),
            "expected error to include status, got {err}"
        );
    }

    #[tokio::test]
    async fn submit_proof_returns_error_on_not_found() {
        let mock_server = MockServer::start().await;
        let challenge_id = "CHALLENGE-notfound";

        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbctest"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/challenges/{challenge_id}")))
            .respond_with(ResponseTemplate::new(404).set_body_string("challenge not found"))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("proof_notfound"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
        );
        let err = client
            .submit_proof(challenge_id, "0102030405")
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 404"),
            "expected error to include status, got {err}"
        );
    }

    #[tokio::test]
    async fn submit_proof_uses_cached_portal_xpub() {
        let mock_server = MockServer::start().await;

        // Mock the portal xpub endpoint - expect exactly 1 call due to caching
        Mock::given(method("GET"))
            .and(path("/api/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "portal_signing_xpub": "xpub661MyMwAqRbcCached"
            })))
            .expect(1) // Should only be called once due to caching
            .mount(&mock_server)
            .await;

        // Mock the submit proof endpoint for multiple challenges
        Mock::given(method("POST"))
            .and(path("/api/challenges/CHALLENGE-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge_id": "CHALLENGE-1",
                "status": "proved",
                "proof": "proof1",
                "bls_signature": "sig1"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/challenges/CHALLENGE-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge_id": "CHALLENGE-2",
                "status": "proved",
                "proof": "proof2",
                "bls_signature": "sig2"
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("proof_cache"),
            keypair,
            "NODE-cache-test",
            42,
            "test-jwt-token",
        );

        // Submit two proofs - xpub should only be fetched once
        let resp1 = client.submit_proof("CHALLENGE-1", "proof1").await.unwrap();
        let resp2 = client.submit_proof("CHALLENGE-2", "proof2").await.unwrap();

        assert_eq!(resp1.status, "proved");
        assert_eq!(resp2.status, "proved");

        // The expect(1) on the mock will fail if xpub was fetched more than once
    }
}
