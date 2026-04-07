use super::http_helpers::{build_http_client, check_response_status};
use super::http_signature;
use crate::crypto::BlsKeyPair;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs;

/// Prefix for Kontor operation signing messages.
const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

/// Filestorage contract address in Kontor (native contract at genesis).
const FILESTORAGE_CONTRACT: &str = "filestorage_0_0";

/// Default gas limit for filestorage contract calls.
const DEFAULT_GAS_LIMIT: u64 = 100_000;

/// Kontor BlsBulkOp::Call representation for signing.
///
/// This must serialize identically to Kontor's `BlsBulkOp::Call` variant via postcard.
/// The `contract` field uses `String` because Kontor serializes `ContractAddress`
/// as its Display string (`"{name}_{height}_{tx_index}"`) via `serde_as(as = "DisplayFromStr")`.
#[derive(Serialize)]
enum BlsBulkOp {
    Call {
        signer_id: u64,
        nonce: u64,
        gas_limit: u64,
        contract: String,
        expr: String,
    },
}

impl BlsBulkOp {
    /// Build the domain-separated signing message: `KONTOR-OP-V1 || postcard(self)`.
    fn signing_message(&self) -> Result<Vec<u8>> {
        let op_bytes = postcard::to_allocvec(self).context("failed to serialize BlsBulkOp")?;
        let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
        msg.extend_from_slice(KONTOR_OP_PREFIX);
        msg.extend_from_slice(&op_bytes);
        Ok(msg)
    }
}

/// Build a WASM Wave expression for the `join-agreement` filestorage function.
fn join_agreement_expr(agreement_id: &str, node_id: &str) -> String {
    format!("join-agreement(\"{agreement_id}\", \"{node_id}\")")
}

/// Build a WASM Wave expression for the `verify-proof` filestorage function.
fn verify_proof_expr(proof_bytes: &[u8]) -> String {
    let items: Vec<String> = proof_bytes.iter().map(|b| b.to_string()).collect();
    format!("verify-proof([{}])", items.join(", "))
}

/// Authentication credentials for Portal API requests.
#[derive(Clone)]
pub struct PortalAuth {
    keypair: Arc<BlsKeyPair>,
    node_id: String,
    signer_id: u64,
    token: String,
    next_nonce: Arc<AtomicU64>,
}

impl std::fmt::Debug for PortalAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalAuth")
            .field("node_id", &self.node_id)
            .field("signer_id", &self.signer_id)
            .field("next_nonce", &self.next_nonce.load(Ordering::Relaxed))
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
}

impl std::fmt::Debug for PortalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalClient")
            .field("base_url", &self.base_url)
            .field("storage_dir", &self.storage_dir)
            .field("auth", &self.auth)
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
        initial_nonce: u64,
    ) -> Self {
        Self::try_with_auth(
            base_url,
            storage_dir,
            keypair,
            node_id,
            signer_id,
            token,
            initial_nonce,
        )
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
        initial_nonce: u64,
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
                next_nonce: Arc::new(AtomicU64::new(initial_nonce)),
            }),
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

    /// Announce this node's public URL to the Portal.
    ///
    /// Requires authentication via JWT Bearer token.
    pub async fn announce_node(&self, public_url: &str) -> Result<()> {
        let path = "/api/nodes/announce";
        let url = self.api_path(path);

        let body = serde_json::json!({ "public_url": public_url });
        let body_bytes =
            serde_json::to_vec(&body).context("failed to serialize announce request")?;

        let request = self.build_signed_request(
            Method::PUT,
            &url,
            path,
            Some((&body_bytes, "application/json")),
        )?;

        let resp = request.body(body_bytes).send().await?;
        check_response_status(resp, "announce node URL").await?;
        Ok(())
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
        expiration: Option<u64>,
    ) -> Result<LoginResponse> {
        let url = format!("{}/api/users/login", self.base_url);
        let payload = LoginRequest {
            user_id: user_id.to_string(),
            challenge: challenge.to_string(),
            signature: signature.to_string(),
            expiration,
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

    /// Fetch all agreements that are marked as ready.
    ///
    /// This method handles pagination automatically, fetching all pages.
    /// Requires authentication via JWT Bearer token.
    pub async fn get_new_agreements(&self) -> Result<Vec<Agreement>> {
        self.paginate(|offset| self.get_agreements_page(offset))
            .await
    }

    /// Fetch a single page of agreements with the given offset.
    async fn get_agreements_page(&self, offset: u32) -> Result<AgreementsPage> {
        let path = format!("/api/agreements?status=ready&offset={offset}");
        let url = self.api_path(&path);

        let request = self.build_signed_request(Method::GET, &url, &path, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(resp, "fetch ready agreements").await?;
        let page = resp
            .json::<AgreementsPage>()
            .await
            .context("failed to deserialize agreements page")?;
        Ok(page)
    }

    /// Sign a Kontor operation with BLS using the BlsBulkOp::Call protocol.
    ///
    /// This method:
    /// 1. Atomically reads and increments the nonce
    /// 2. Builds a `BlsBulkOp::Call` with the given Wave expression
    /// 3. Signs `KONTOR-OP-V1 || postcard(op)` with the BLS keypair
    ///
    /// Returns `(hex_signature, nonce_used)`.
    fn sign_kontor_op(&self, expr: String) -> Result<(String, u64)> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| anyhow!("authentication required: no keypair configured"))?;

        let nonce = auth.next_nonce.fetch_add(1, Ordering::Relaxed);

        let op = BlsBulkOp::Call {
            signer_id: auth.signer_id,
            nonce,
            gas_limit: DEFAULT_GAS_LIMIT,
            contract: FILESTORAGE_CONTRACT.to_string(),
            expr,
        };

        let msg = op.signing_message()?;
        let sig = auth.keypair.sign_kontor_op_message(&msg)?;
        Ok((sig, nonce))
    }

    /// Join an agreement as a storage node.
    ///
    /// Signs a `join-agreement` Kontor operation with BLS and submits it.
    /// Requires authentication via JWT Bearer token.
    pub async fn join_agreement(&self, agreement_id: &str) -> Result<JoinAgreementResponse> {
        let node_id = self
            .node_id()
            .ok_or_else(|| anyhow!("authentication required to join agreement"))?
            .to_string();

        let expr = join_agreement_expr(agreement_id, &node_id);
        let (bls_signature, nonce) = self.sign_kontor_op(expr)?;

        let path = format!("/api/agreements/{agreement_id}/join");
        let url = self.api_path(&path);

        let payload = JoinAgreementRequest {
            bls_signature,
            nonce,
        };
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
    /// Signs a `verify-proof` Kontor operation with BLS and submits it.
    /// The proof_hex is decoded to bytes for the Wave expression, then
    /// re-encoded as hex in the request body.
    ///
    /// Requires authentication.
    pub async fn submit_proof(
        &self,
        challenge_id: &str,
        proof_hex: &str,
    ) -> Result<SubmitProofResponse> {
        let proof_bytes = hex::decode(proof_hex).context("invalid hex in proof for BLS signing")?;
        let expr = verify_proof_expr(&proof_bytes);
        let (bls_signature, nonce) = self.sign_kontor_op(expr)?;

        let path = format!("/api/challenges/{challenge_id}");
        let url = self.api_path(&path);

        let payload = SubmitProofRequest {
            proof: proof_hex.to_string(),
            bls_signature,
            nonce,
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
    #[allow(dead_code)]
    pub merkle_root: Option<String>,
    #[allow(dead_code)]
    pub data_symbols: Option<u64>,
    #[allow(dead_code)]
    pub parity_symbols: Option<u64>,
    #[allow(dead_code)]
    pub padded_len: Option<u64>,
    #[allow(dead_code)]
    pub blob_size: Option<u64>,
    #[allow(dead_code)]
    pub file_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JoinAgreementResponse {
    pub node_id: String,
    pub created: bool,
}

#[derive(Debug, Serialize)]
struct JoinAgreementRequest {
    bls_signature: String,
    nonce: u64,
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
    nonce: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>,
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
    pub bls_pubkey: Option<String>,
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
            0,
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
    async fn get_new_agreements_requests_ready_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
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
                    "status": "ready",
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
            .and(query_param("status", "ready"))
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
            0,
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
            0,
        );
        let response = client.join_agreement(agreement_id).await.unwrap();

        assert!(response.created);
    }

    #[tokio::test]
    async fn join_agreement_returns_error_on_failure() {
        let mock_server = MockServer::start().await;
        let agreement_id = "AGREEMENT-error";

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
            0,
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
            0,
        );
        let downloaded = client
            .download_file(agreement_id, "auth-sample.txt")
            .await
            .unwrap();

        let contents = fs::read_to_string(&downloaded.path).unwrap();
        assert_eq!(contents, "authenticated content");
    }

    #[tokio::test]
    async fn join_agreement_works_for_multiple_agreements() {
        let mock_server = MockServer::start().await;

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
            storage_dir("join_multi"),
            keypair,
            "NODE-cache-test",
            42,
            "test-jwt-token",
            0,
        );

        let resp1 = client.join_agreement("AGREEMENT-1").await.unwrap();
        let resp2 = client.join_agreement("AGREEMENT-2").await.unwrap();

        assert!(resp1.created);
        assert!(resp2.created);
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
            0,
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
            0,
        );
        let err = client
            .submit_proof(challenge_id, "0102030405")
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
            0,
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

    #[test]
    fn portal_auth_debug_redacts_token_and_keypair() {
        use super::PortalAuth;
        use std::sync::atomic::AtomicU64;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let auth = PortalAuth {
            keypair,
            node_id: "NODE-debug".to_string(),
            signer_id: 42,
            token: "secret-token".to_string(),
            next_nonce: Arc::new(AtomicU64::new(7)),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("NODE-debug"));
        assert!(debug.contains("42"));
        assert!(debug.contains("<redacted>"), "token should be redacted");
        assert!(
            debug.contains("<BlsKeyPair>"),
            "keypair should be placeholder"
        );
        assert!(
            !debug.contains("secret-token"),
            "raw token should not appear"
        );
    }

    #[test]
    fn portal_client_debug_shows_base_url() {
        let client = PortalClient::new("https://example.com/api", "/tmp/storage");
        let debug = format!("{client:?}");
        assert!(debug.contains("PortalClient"));
        assert!(debug.contains("https://example.com/api"));
    }

    #[test]
    fn signer_id_returns_none_when_unauthenticated() {
        let client = PortalClient::new("https://example.com/api", "/tmp/storage");
        assert!(client.signer_id().is_none());
    }

    #[test]
    fn signer_id_returns_some_when_authenticated() {
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            "https://example.com/api",
            "/tmp/storage",
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );
        assert_eq!(client.signer_id(), Some(42));
    }

    #[tokio::test]
    async fn announce_node_sends_authenticated_request() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/api/nodes/announce"))
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("announce"),
            keypair,
            "NODE-announce",
            42,
            "test-jwt-token",
            0,
        );

        let result = client.announce_node("https://my-node.example.com").await;
        assert!(result.is_ok(), "announce should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn announce_node_returns_error_on_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/api/nodes/announce"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("announce_fail"),
            keypair,
            "NODE-announce",
            42,
            "test-jwt-token",
            0,
        );

        let err = client
            .announce_node("https://bad.example.com")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("status 403"),
            "expected 403 error, got {err}"
        );
    }

    #[tokio::test]
    async fn pagination_fetches_all_pages_for_agreements() {
        let mock_server = MockServer::start().await;

        // Page 1: offset=0, returns 2 of 3 total
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 2,
                "total": 3,
                "agreements": [
                    {
                        "agreement_id": "AGR-1", "user_id": "u1", "file_id": "F-1",
                        "filename": "a.pdf", "mime_type": "application/pdf", "original_size": 10,
                        "nodes": ["N1"], "transaction_id": null, "curation": {},
                        "status": "ready", "created_at": "2024-01-01T00:00:00Z"
                    },
                    {
                        "agreement_id": "AGR-2", "user_id": "u1", "file_id": "F-2",
                        "filename": "b.pdf", "mime_type": "application/pdf", "original_size": 20,
                        "nodes": ["N1"], "transaction_id": null, "curation": {},
                        "status": "ready", "created_at": "2024-01-02T00:00:00Z"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        // Page 2: offset=2, returns 1 of 3 total
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .and(query_param("offset", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 2,
                "limit": 2,
                "total": 3,
                "agreements": [
                    {
                        "agreement_id": "AGR-3", "user_id": "u1", "file_id": "F-3",
                        "filename": "c.pdf", "mime_type": "application/pdf", "original_size": 30,
                        "nodes": ["N1"], "transaction_id": null, "curation": {},
                        "status": "ready", "created_at": "2024-01-03T00:00:00Z"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("pagination"));
        let agreements = client.get_new_agreements().await.unwrap();

        assert_eq!(agreements.len(), 3, "should fetch all 3 agreements");
        assert_eq!(agreements[0].agreement_id, "AGR-1");
        assert_eq!(agreements[2].agreement_id, "AGR-3");
    }

    #[tokio::test]
    async fn get_node_challenges_fetches_challenges() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-chal/challenges"))
            .and(query_param("status", "active"))
            .and(query_param("offset", "0"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 1,
                "challenges": [{
                    "challenge_id": "CHAL-1",
                    "agreement_id": "AGR-1",
                    "block_height": 100,
                    "challenge_count": 5,
                    "seed": "abc123",
                    "prover_id": "NODE-chal",
                    "deadline_height": 200,
                    "status": "active",
                    "proof": null,
                    "bls_signature": null,
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z"
                }]
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("challenges"),
            keypair,
            "NODE-chal",
            42,
            "jwt-token",
            0,
        );
        let challenges = client.get_node_challenges().await.unwrap();

        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].challenge_id, "CHAL-1");
    }

    #[tokio::test]
    async fn get_node_challenges_requires_authentication() {
        let client = PortalClient::new("http://localhost:1234", storage_dir("chal_no_auth"));
        let err = client.get_node_challenges().await.unwrap_err();
        assert!(
            err.to_string().contains("authentication required"),
            "expected auth error, got {err}"
        );
    }
}
