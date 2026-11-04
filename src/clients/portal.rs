use super::http_helpers::{build_http_client, check_response_status, status_and_code};
use super::http_signature;
use super::kontor_op::{build_signing_message, Inst, InstKind, SignerRef, DEFAULT_GAS_LIMIT};
use super::kor::Kor;
use crate::crypto::BlsKeyPair;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs;

/// Filestorage contract address in Kontor (native contract at genesis).
///
/// Mirrors the Portal's `DEFAULT_KONTOR_CONTRACT_ADDRESS`. The address is part
/// of the signed `Inst`, so a deployment that points the Portal at a different
/// filestorage instance must point the node at the same one — see
/// [`PortalClient::with_contract_address`].
pub const DEFAULT_FILESTORAGE_CONTRACT: &str = "filestorage_0_0";

/// Staking contract address in Kontor (native contract at genesis).
///
/// Mirrors the Portal's `KONTOR_STAKING_CONTRACT_ADDRESS` default. Like the
/// filestorage address it is inside the signed `Inst` of every stake op, so the
/// two sides must name the same instance — see
/// [`PortalClient::with_staking_contract_address`].
pub const DEFAULT_STAKING_CONTRACT: &str = "staking_0_0";

/// How far past a signer's `next_nonce` Kontor accepts an op's nonce
/// (`MAX_NONCE_GAP` in `advance_nonce`, `core/indexer/src/protocol/v1/storage_identity.rs`).
/// A counter further ahead than this would have every op it signs refused.
pub const KONTOR_MAX_NONCE_GAP: u64 = 10_000;

/// Encode `s` as a Wave string literal, validating it contains only safe
/// characters.
///
/// Kontor identifiers (agreement IDs, node IDs, etc.) follow the pattern
/// `[A-Za-z0-9_-]+`. Restricting the allowlist to this character set means
/// the result can be embedded in a Wave expression without any escaping and
/// without risk of injecting code into the on-chain program.
///
/// Returns `Err` if `s` contains any character outside `[A-Za-z0-9_-]`
/// (notably `"`, `\`, `(`, `)`, whitespace, control characters, etc.).
fn wave_string_literal(s: &str) -> Result<String> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(anyhow!(
            "invalid character in identifier {s:?}: only [A-Za-z0-9_-] allowed"
        ));
    }
    Ok(format!("\"{s}\""))
}

/// Build a WASM Wave expression for the `join-agreement` filestorage function.
///
/// The joining node is NOT a parameter: the contract takes it from
/// `ctx.signer()` (one membership slot per signer per agreement), so the only
/// argument is the agreement id. Must stay byte-identical to the Portal's
/// `build_join_agreement_expr`, which reconstructs this expression to verify
/// the BLS signature.
///
/// `agreement_id` MUST consist of only `[A-Za-z0-9_-]`; otherwise an error is
/// returned to avoid Wave expression injection.
fn join_agreement_expr(agreement_id: &str) -> Result<String> {
    let agreement_lit = wave_string_literal(agreement_id)?;
    Ok(format!("join-agreement({agreement_lit})"))
}

/// Build a WASM Wave expression for the `verify-proof` filestorage function.
///
/// `challenge_ids` are the challenges the submitter claims this proof answers.
/// kontor-crypto 0.3.0's constant-size proof no longer carries them, so the
/// contract rebuilds the challenge set from these ids; the SNARK binds the set,
/// so a wrong or missing id fails verification instead of granting undeserved
/// credit.
///
/// Each proof byte serializes as its decimal representation, so the input bytes
/// cannot affect the structure of the expression. Challenge ids are validated as
/// `[A-Za-z0-9_-]` identifiers for the same reason. Must stay byte-identical to
/// the Portal's `build_verify_proof_expr`.
fn verify_proof_expr(proof_bytes: &[u8], challenge_ids: &[&str]) -> Result<String> {
    let items: Vec<String> = proof_bytes.iter().map(|b| b.to_string()).collect();
    let ids = challenge_ids
        .iter()
        .map(|id| wave_string_literal(id))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    Ok(format!("verify-proof([{}], [{}])", items.join(", "), ids))
}

/// A staking or rewards operation the node signs itself and the Portal relays
/// through `POST /api/nodes/{node_id}/ops` (Portal
/// `docs/node-portal-contract.md` §2).
///
/// The Portal never trusts an expression from the client: it rebuilds the
/// `Inst` from `op` (and `amount`) and verifies this node's signature over the
/// result. So [`NodeOp::contract_and_expr`] must produce exactly what the Portal
/// builds — the contract each op targets, and the WAVE expression with the
/// amount encoded by [`Kor::wave_literal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeOp {
    /// `staking::add-stake(amount)`: bond more collateral.
    AddStake(Kor),
    /// `staking::begin-unstake()`: start the withdrawal delay. The node can no
    /// longer join agreements, nor add stake, until it has withdrawn.
    BeginUnstake,
    /// `staking::withdraw-stake()`: take the whole bond back once the delay has
    /// elapsed and no storage obligation is left.
    WithdrawStake,
    /// `filestorage::claim-rewards()`: move accrued storage rewards into the
    /// node's spendable balance, where auto-stake can pick them up.
    ClaimRewards,
    /// `filestorage::leave-agreement(id)`: give up one membership. Part of
    /// leaving the network: `withdraw-stake` is refused while any membership
    /// remains.
    LeaveAgreement(String),
}

/// Which contract an op is a call on. The addresses themselves are
/// configuration and live on the client.
enum OpContract {
    Staking,
    Filestorage,
}

impl NodeOp {
    /// The `op` field of the relay request.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            NodeOp::AddStake(_) => "add_stake",
            NodeOp::BeginUnstake => "begin_unstake",
            NodeOp::WithdrawStake => "withdraw_stake",
            NodeOp::ClaimRewards => "claim_rewards",
            NodeOp::LeaveAgreement(_) => "leave_agreement",
        }
    }

    /// The amount, for the one op that carries one.
    #[must_use]
    pub fn amount(&self) -> Option<Kor> {
        match self {
            NodeOp::AddStake(amount) => Some(*amount),
            _ => None,
        }
    }

    /// The agreement, for the one op that names one.
    #[must_use]
    pub fn agreement_id(&self) -> Option<&str> {
        match self {
            NodeOp::LeaveAgreement(agreement_id) => Some(agreement_id),
            _ => None,
        }
    }

    /// The contract the op calls and its WAVE expression (Portal
    /// `docs/node-portal-contract.md` §2).
    ///
    /// `leave-agreement("<id>")` is quoted exactly like `join-agreement`, with
    /// the same `[A-Za-z0-9_-]` allowlist — the Portal rebuilds it from the
    /// `agreement_id` field and verifies the signature over it.
    fn contract_and_expr(&self) -> Result<(OpContract, String)> {
        Ok(match self {
            NodeOp::AddStake(amount) => (
                OpContract::Staking,
                format!("add-stake({})", amount.wave_literal()),
            ),
            NodeOp::BeginUnstake => (OpContract::Staking, "begin-unstake()".to_string()),
            NodeOp::WithdrawStake => (OpContract::Staking, "withdraw-stake()".to_string()),
            NodeOp::ClaimRewards => (OpContract::Filestorage, "claim-rewards()".to_string()),
            NodeOp::LeaveAgreement(agreement_id) => (
                OpContract::Filestorage,
                format!("leave-agreement({})", wave_string_literal(agreement_id)?),
            ),
        })
    }
}

/// The local nonce counter after a resync against Kontor's `next_nonce`:
/// `max(local, kontor)`, unless that is further ahead than Kontor accepts.
///
/// Kontor only moves `next_nonce` once an op has executed, and the Portal
/// relays ops a block (~10 minutes) at a time, so for most of a block the
/// counter is rightly ahead: every op signed since the last block is still
/// queued at the Portal under its nonce. Rewinding to Kontor's value — what
/// the node used to do every cycle — signed the next cycle's ops at nonces
/// those queued ops already held, and they collided. So the counter never
/// moves back, not after an op that failed on chain, nor across startup: an
/// op that never ran just leaves a gap, and gaps are fine — the Portal takes
/// strictly ascending nonces at or above `next_nonce`, and Kontor accepts any
/// nonce up to [`KONTOR_MAX_NONCE_GAP`] past it (Portal
/// `docs/node-portal-contract.md` §2).
///
/// Past that gap every op would be refused, so the counter falls back to
/// Kontor's value instead: a collision or two is recoverable, a node that can
/// sign nothing Kontor accepts is not.
#[must_use]
pub fn resynced_nonce(local: u64, kontor: u64) -> u64 {
    if local.saturating_sub(kontor) > KONTOR_MAX_NONCE_GAP {
        kontor
    } else {
        local.max(kontor)
    }
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
    /// Filestorage contract every signed Kontor op targets.
    contract_address: String,
    /// Staking contract the stake ops target.
    staking_contract_address: String,
}

impl std::fmt::Debug for PortalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalClient")
            .field("base_url", &self.base_url)
            .field("storage_dir", &self.storage_dir)
            .field("auth", &self.auth)
            .field("contract_address", &self.contract_address)
            .field("staking_contract_address", &self.staking_contract_address)
            .finish()
    }
}

impl PortalClient {
    /// Create an unauthenticated client for public endpoints only.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built (e.g., TLS initialization fails).
    #[deprecated(since = "0.2.0", note = "use try_new")]
    #[allow(dead_code)]
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
            contract_address: DEFAULT_FILESTORAGE_CONTRACT.to_string(),
            staking_contract_address: DEFAULT_STAKING_CONTRACT.to_string(),
        })
    }

    /// Point this client at a specific filestorage contract instance.
    ///
    /// Defaults to [`DEFAULT_FILESTORAGE_CONTRACT`]. The address is serialized
    /// into every `InstKind::Call` this client signs, and the Portal rebuilds
    /// the same `Inst` from its own `KONTOR_CONTRACT_ADDRESS` to verify the
    /// signature — the two must name the same contract.
    #[must_use]
    pub fn with_contract_address(mut self, contract_address: impl Into<String>) -> Self {
        self.contract_address = contract_address.into();
        self
    }

    /// Point this client at a specific staking contract instance.
    ///
    /// Defaults to [`DEFAULT_STAKING_CONTRACT`]. Same reasoning as
    /// [`Self::with_contract_address`]: `add-stake`, `begin-unstake` and
    /// `withdraw-stake` are signed against this address, and the Portal rebuilds
    /// them from its own `KONTOR_STAKING_CONTRACT_ADDRESS`.
    #[must_use]
    pub fn with_staking_contract_address(mut self, address: impl Into<String>) -> Self {
        self.staking_contract_address = address.into();
        self
    }

    /// Create an authenticated client with BLS keypair for signed requests.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built (e.g., TLS initialization fails).
    #[deprecated(since = "0.2.0", note = "use try_with_auth")]
    #[allow(dead_code)]
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
            contract_address: DEFAULT_FILESTORAGE_CONTRACT.to_string(),
            staking_contract_address: DEFAULT_STAKING_CONTRACT.to_string(),
        })
    }

    /// Get the node ID if authenticated.
    pub fn node_id(&self) -> Option<&str> {
        self.auth.as_ref().map(|a| a.node_id.as_str())
    }

    /// Get the Kontor signer ID if authenticated.
    ///
    /// This is the node's on-chain identity: the filestorage contract keys
    /// agreement membership and `challenge-data.prover-id` on it, and its
    /// decimal string is what a PoR challenge hashes as `prover_id`.
    pub fn signer_id(&self) -> Option<u64> {
        self.auth.as_ref().map(|a| a.signer_id)
    }

    /// Bring the local nonce counter up to Kontor's `next_nonce` — never down —
    /// keeping the registry entry it read.
    ///
    /// The daemon reads the entry once per cycle and makes every staking
    /// decision of that cycle from it: the balance and stake it reports are the
    /// same snapshot as the nonce the cycle signs from, which is what lets an
    /// op's nonce later say whether that op has landed.
    ///
    /// See [`resynced_nonce`] for why the counter only ever moves forward.
    pub async fn resync_from_registry(&self) -> Result<RegistryEntry> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| anyhow!("authentication required to resync nonce"))?;
        let entry = self.get_registry_entry(auth.signer_id).await?;
        let kontor = entry.next_nonce;
        // A compare-exchange loop rather than `fetch_update`, which the pinned
        // toolchain deprecates and the declared MSRV has no replacement for.
        let mut old = auth.next_nonce.load(Ordering::Relaxed);
        let new = loop {
            let new = resynced_nonce(old, kontor);
            match auth.next_nonce.compare_exchange_weak(
                old,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break new,
                Err(current) => old = current,
            }
        };
        if new < old {
            tracing::warn!(
                old,
                new,
                "the local nonce ran more than {KONTOR_MAX_NONCE_GAP} past Kontor's, which \
                 Kontor would refuse; falling back to Kontor's next_nonce"
            );
        } else if new > old {
            tracing::info!(old, new, "advanced the local nonce to Kontor's next_nonce");
        }
        Ok(entry)
    }

    /// Give back the nonce of an op the Portal refused outright.
    ///
    /// [`Self::sign_kontor_op`] takes the nonce before the request goes out. A
    /// 4xx means the Portal stored nothing, so that nonce will never be used on
    /// chain, and giving it back keeps the sequence without a hole. A hole is no
    /// longer fatal — the Portal and Kontor both accept one — but a Portal that
    /// predates that drops every later op of the cycle as out of sequence, and a
    /// proof dropped that way is a missed challenge, which costs collateral.
    ///
    /// Only rolls back if nothing was signed since, so it can never hand out a
    /// nonce twice. Network errors and 5xx do not come here: whether the Portal
    /// kept the op is unknown, so the nonce stays consumed — at worst a gap,
    /// which Kontor skips over (see [`resynced_nonce`]). Nor does
    /// `409 CONFLICT`, the one 4xx after which something *is* stored: the
    /// Portal already holds a different op of this node at that nonce, so the
    /// nonce is taken and handing it out again would only collide a second
    /// time.
    fn release_nonce(&self, nonce: u64) {
        if let Some(auth) = &self.auth {
            let _ = auth.next_nonce.compare_exchange(
                nonce.wrapping_add(1),
                nonce,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// Send a signed op and release its nonce if the Portal refuses it
    /// without storing anything — every 4xx except `409`, see
    /// [`Self::release_nonce`].
    async fn send_signed_op(
        &self,
        request: reqwest::RequestBuilder,
        nonce: u64,
        what: &str,
    ) -> Result<reqwest::Response> {
        let resp = request.send().await?;
        let status = resp.status();
        let nothing_stored = status.is_client_error() && status != reqwest::StatusCode::CONFLICT;
        let result = check_response_status(resp, what).await;
        if result.is_err() && nothing_stored {
            self.release_nonce(nonce);
        }
        result
    }

    /// Read the current local nonce counter (test-only helper).
    #[cfg(test)]
    pub fn current_nonce(&self) -> Option<u64> {
        self.auth
            .as_ref()
            .map(|a| a.next_nonce.load(Ordering::Relaxed))
    }

    fn jwt_and_digest_headers(
        &self,
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
    /// * `body` - Optional tuple of (body bytes, content type) for POST requests
    ///
    /// # Returns
    /// A `RequestBuilder` with auth headers added if authenticated
    fn build_signed_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut request = self.http.request(method, url);

        if let Some(headers) = self.jwt_and_digest_headers(body)? {
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
        let url = self.api_path("/api/nodes/announce");

        let body = serde_json::json!({ "public_url": public_url });
        let body_bytes =
            serde_json::to_vec(&body).context("failed to serialize announce request")?;

        let request =
            self.build_signed_request(Method::PUT, &url, Some((&body_bytes, "application/json")))?;

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
            // Guard against servers that report `total > 0` but return an empty `items` array,
            // which would otherwise spin forever because `offset` never advances.
            if fetched == 0 {
                break;
            }
            all_items.extend(items);

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
        let resp = check_response_status(resp, "portal ping").await?;
        resp.text().await.context("reading portal ping body")
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

    /// Look up a node by its `node_id`.
    ///
    /// The mirror image of [`Self::lookup_node`]: that one asks "which node owns
    /// this BLS key", this one asks "which BLS key does this Taproot identity
    /// hold". A node deriving itself from a mnemonic knows its own `node_id`
    /// before it knows anything else — it is a hash of the xpub — so this is how
    /// it tells "nobody has registered me yet" apart from "somebody registered
    /// this address with a different key".
    ///
    /// Unauthenticated, like the lookup: both are public on the Portal so a node
    /// holding nothing but keys can find its own footing.
    pub async fn check_node(&self, node_id: &str) -> Result<NodeCheckResult> {
        let url = format!(
            "{}/api/nodes/{}/check",
            self.base_url,
            urlencoding::encode(node_id)
        );
        let resp = self.http.get(&url).send().await?;
        let resp = check_response_status(resp, "check node by id").await?;
        resp.json::<NodeCheckResult>()
            .await
            .context("failed to deserialize node check result")
    }

    /// Register this node's BLS key with the Portal.
    ///
    /// Unauthenticated by design: the node has no credential to present until
    /// this call succeeds. The Portal authenticates the request from the
    /// signatures in the body instead, and gates it on the operator's Taproot
    /// address being whitelisted — a `403 ADDRESS_NOT_WHITELISTED` means a
    /// Portal admin has to act, so the error body is worth surfacing verbatim.
    ///
    /// Writing the row is all this does. Getting the key on-chain is the
    /// Portal daemon's job, and `signer_id` stays `null` in
    /// [`Self::lookup_node`] until that transaction confirms.
    pub async fn register_node(
        &self,
        request: &RegisterNodeRequest,
    ) -> Result<RegisterNodeResponse> {
        let url = format!("{}/api/nodes/register", self.base_url);
        let resp = self.http.post(&url).json(request).send().await?;
        let resp = check_response_status(resp, "register node").await?;
        resp.json::<RegisterNodeResponse>()
            .await
            .context("failed to deserialize node registration response")
    }

    /// Ask the Portal to whitelist this node's Taproot address.
    ///
    /// Unauthenticated like [`Self::register_node`], and for the same reason:
    /// a node that needs whitelisting has no credential at all. The Portal
    /// takes the same proof of possession a registration carries — which is
    /// what stops a stranger queueing requests for someone else's address —
    /// plus the operator's contact details, and holds the request until a
    /// Portal admin approves or rejects it.
    ///
    /// Submissions are quota'd per IP (and the quota is charged before the
    /// signatures are checked), so callers should validate what they can
    /// locally rather than let the Portal refuse a malformed body.
    pub async fn submit_whitelist_request(
        &self,
        request: &WhitelistRequestBody,
    ) -> Result<WhitelistRequestView> {
        let url = format!("{}/api/nodes/whitelist/request", self.base_url);
        let resp = self.http.post(&url).json(request).send().await?;
        let resp = check_response_status(resp, "submit whitelist request").await?;
        resp.json::<WhitelistRequestView>()
            .await
            .context("failed to deserialize whitelist request response")
    }

    /// Where a whitelist request for `bitcoin_address` stands.
    ///
    /// Public and unauthenticated. Answers 404 when the address has neither a
    /// request in the queue nor a whitelist entry; an address whitelisted by
    /// hand, without ever going through the queue, answers with
    /// `status: "approved"` and no `request_id`.
    pub async fn whitelist_request_status(
        &self,
        bitcoin_address: &str,
    ) -> Result<WhitelistRequestView> {
        let url = format!("{}/api/nodes/whitelist/request", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("bitcoin_address", bitcoin_address)])
            .send()
            .await?;
        let resp = check_response_status(resp, "check whitelist request status").await?;
        resp.json::<WhitelistRequestView>()
            .await
            .context("failed to deserialize whitelist request status")
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
        let url = format!("{}/api/signers/{}", self.base_url, signer_id);
        let resp = self.http.get(&url).send().await?;
        let resp = check_response_status(resp, "fetch registry entry").await?;
        resp.json::<RegistryEntry>()
            .await
            .context("failed to deserialize registry entry")
    }

    /// Request KOR from the Portal faucet.
    ///
    /// Public endpoint — does not require authentication. The Portal will compose,
    /// sign, and broadcast a BTC-anchored `Call::transfer` to the given recipient.
    pub async fn request_faucet(&self, recipient: &str, amount: f64) -> Result<FaucetResponse> {
        let url = format!("{}/api/faucet", self.base_url);
        let payload = FaucetRequest {
            recipient: recipient.to_string(),
            amount,
        };
        let resp = self.http.post(&url).json(&payload).send().await?;
        let resp = check_response_status(resp, "request faucet").await?;
        resp.json::<FaucetResponse>()
            .await
            .context("failed to deserialize faucet response")
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
        let url = self.api_path(&format!("/api/agreements?status=ready&offset={offset}"));

        let request = self.build_signed_request(Method::GET, &url, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(resp, "fetch ready agreements").await?;
        let page = resp
            .json::<AgreementsPage>()
            .await
            .context("failed to deserialize agreements page")?;
        Ok(page)
    }

    /// Fetch all agreements assigned to a specific node (across all statuses).
    ///
    /// This method handles pagination automatically, fetching all pages.
    /// Requires authentication via JWT Bearer token.
    pub async fn get_node_agreements(&self, node_id: &str) -> Result<Vec<Agreement>> {
        let node_id = node_id.to_string();
        self.paginate(|offset| self.get_node_agreements_page(&node_id, offset))
            .await
    }

    async fn get_node_agreements_page(&self, node_id: &str, offset: u32) -> Result<AgreementsPage> {
        let url = self.api_path(&format!("/api/agreements?nodes={node_id}&offset={offset}"));

        let request = self.build_signed_request(Method::GET, &url, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(resp, "fetch node agreements").await?;
        let page = resp
            .json::<AgreementsPage>()
            .await
            .context("failed to deserialize node agreements page")?;
        Ok(page)
    }

    /// Fetch one agreement, with this node's membership row whatever its
    /// status.
    ///
    /// The listings filtered by node (`GET /api/agreements?nodes=`) only cover
    /// agreements the node *validly* belongs to, so a membership the Portal
    /// has marked `left`, `invalid` or `failed` drops out of them; this is how
    /// the node finds out.
    ///
    /// # Errors
    /// If the request fails, or the Portal has no such agreement.
    pub async fn get_agreement(&self, agreement_id: &str) -> Result<Agreement> {
        let url = self.api_path(&format!(
            "/api/agreements/{}",
            urlencoding::encode(agreement_id)
        ));
        let request = self.build_signed_request(Method::GET, &url, None)?;
        let resp = request.send().await?;
        let resp = check_response_status(resp, &format!("fetch agreement {agreement_id}")).await?;
        resp.json::<Agreement>()
            .await
            .context("failed to deserialize agreement")
    }

    /// Sign a Kontor operation with BLS.
    ///
    /// This method:
    /// 1. Atomically reads and increments the nonce
    /// 2. Builds the signing message `KONTOR-OP-V1 || postcard((SignerClaim, nonce, sponsored, Inst))`
    ///    matching Kontor's `Inst::aggregate_signing_message` protocol
    /// 3. Signs the message with the BLS keypair
    ///
    /// Returns `(hex_signature, nonce_used)`.
    fn sign_kontor_op(&self, expr: String) -> Result<(String, u64)> {
        self.sign_kontor_call(self.contract_address.clone(), expr)
    }

    /// [`Self::sign_kontor_op`] against an explicit contract.
    fn sign_kontor_call(&self, contract: String, expr: String) -> Result<(String, u64)> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| anyhow!("authentication required: no keypair configured"))?;

        let nonce = auth.next_nonce.fetch_add(1, Ordering::Relaxed);

        let claim = SignerRef::SignerId(auth.signer_id);
        let inst = Inst {
            gas_limit: DEFAULT_GAS_LIMIT,
            kind: InstKind::Call { contract, expr },
        };

        // `sponsored = false`: a node self-pays gas for its own calls. Only
        // `RegisterBlsKey`, which the Portal publishes on the node's behalf
        // before it has an account to pay from, is sponsored.
        let msg = build_signing_message(&claim, nonce, false, &inst)?;

        let sig = auth.keypair.sign_kontor_op_message(&msg)?;
        Ok((sig, nonce))
    }

    /// Join an agreement as a storage node.
    ///
    /// Signs a `join-agreement` Kontor operation with BLS and submits it.
    /// Requires authentication via JWT Bearer token.
    pub async fn join_agreement(&self, agreement_id: &str) -> Result<JoinAgreementResponse> {
        if self.node_id().is_none() {
            return Err(anyhow!("authentication required to join agreement"));
        }

        let expr = join_agreement_expr(agreement_id)?;
        let (bls_signature, nonce) = self.sign_kontor_op(expr)?;

        let url = self.api_path(&format!("/api/agreements/{agreement_id}/join"));

        let payload = JoinAgreementRequest {
            bls_signature,
            nonce,
        };
        let body_bytes =
            serde_json::to_vec(&payload).context("failed to serialize join request")?;

        let request =
            self.build_signed_request(Method::POST, &url, Some((&body_bytes, "application/json")))?;

        let resp = self
            .send_signed_op(
                request.body(body_bytes),
                nonce,
                &format!("join agreement {agreement_id}"),
            )
            .await?;
        let mut body = resp
            .json::<JoinAgreementResponse>()
            .await
            .context("failed to deserialize join response")?;
        body.nonce = Some(nonce);
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
        let url = self.api_path(&format!(
            "/api/agreements/{agreement_id}/download?no_redirect=true"
        ));

        let request = self.build_signed_request(Method::GET, &url, None)?;

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
    #[allow(dead_code)]
    pub async fn get_node_challenges(&self) -> Result<Vec<Challenge>> {
        self.paginate(|offset| self.get_challenges_page(offset))
            .await
    }

    /// Fetch a single page of challenges with the given offset.
    #[allow(dead_code)]
    async fn get_challenges_page(&self, offset: u32) -> Result<ChallengesPage> {
        let auth = self.auth.as_ref().ok_or_else(|| {
            anyhow!("authentication required to fetch challenges: no keypair configured")
        })?;

        let url = self.api_path(&format!(
            "/api/nodes/{}/challenges?status=active&offset={offset}",
            auth.node_id
        ));

        let request = self.build_signed_request(Method::GET, &url, None)?;

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

    /// Fetch all challenges for this node, regardless of status.
    ///
    /// Used to reconcile local challenge statuses with Portal (e.g. picking up
    /// transitions to `failed`, `resolved`, etc.). Requires authentication.
    pub async fn get_all_node_challenges(&self) -> Result<Vec<Challenge>> {
        self.paginate(|offset| self.get_all_challenges_page(offset))
            .await
    }

    /// Fetch a single page of all challenges (no status filter).
    async fn get_all_challenges_page(&self, offset: u32) -> Result<ChallengesPage> {
        let auth = self.auth.as_ref().ok_or_else(|| {
            anyhow!("authentication required to fetch challenges: no keypair configured")
        })?;

        let url = self.api_path(&format!(
            "/api/nodes/{}/challenges?offset={offset}",
            auth.node_id
        ));

        let request = self.build_signed_request(Method::GET, &url, None)?;

        let resp = request.send().await?;
        let resp = check_response_status(
            resp,
            &format!("fetch all challenges for node {}", auth.node_id),
        )
        .await?;
        let page = resp
            .json::<ChallengesPage>()
            .await
            .context("failed to deserialize all challenges page")?;
        Ok(page)
    }

    /// Submit a storage proof for a challenge.
    ///
    /// Signs a `verify-proof` Kontor operation with BLS and submits it.
    /// The proof_hex is decoded to bytes for the Wave expression, then
    /// re-encoded as hex in the request body.
    ///
    /// `challenge_id` is both the route parameter and part of the signed
    /// expression: the contract needs the submitter to declare which challenges
    /// the proof answers (see [`verify_proof_expr`]), and the Portal rebuilds
    /// the same `verify-proof(bytes, [id])` to check the signature. One
    /// challenge per submission — the Portal's route is per-challenge.
    ///
    /// Requires authentication.
    pub async fn submit_proof(
        &self,
        challenge_id: &str,
        proof_hex: &str,
    ) -> Result<SubmitProofResponse> {
        let proof_bytes = hex::decode(proof_hex).context("invalid hex in proof for BLS signing")?;
        let expr = verify_proof_expr(&proof_bytes, &[challenge_id])?;
        let (bls_signature, nonce) = self.sign_kontor_op(expr)?;

        let url = self.api_path(&format!("/api/challenges/{challenge_id}"));

        let payload = SubmitProofRequest {
            proof: proof_hex.to_string(),
            bls_signature,
            nonce,
        };
        let body_bytes =
            serde_json::to_vec(&payload).context("failed to serialize submit proof request")?;

        let request =
            self.build_signed_request(Method::POST, &url, Some((&body_bytes, "application/json")))?;

        let resp = self
            .send_signed_op(
                request.body(body_bytes),
                nonce,
                &format!("submit proof for challenge {challenge_id}"),
            )
            .await?;
        let body = resp
            .json::<SubmitProofResponse>()
            .await
            .context("failed to deserialize submit proof response")?;
        Ok(body)
    }
}

impl PortalClient {
    /// Sign a staking or rewards op and hand it to the Portal's relay.
    ///
    /// `POST /api/nodes/{node_id}/ops` (Portal `docs/node-portal-contract.md`
    /// §2), authenticated like a join. Self-paid (`sponsored = false`) at
    /// [`DEFAULT_GAS_LIMIT`], exactly like the node's other calls. A `202` only
    /// means the op is queued: whether it executed is read back later from the
    /// registry entry — its nonce becomes consumed, and the balance or stake it
    /// moved changes.
    ///
    /// # Errors
    /// If the client is unauthenticated, the request fails, or the Portal
    /// refuses the op (the [`HttpStatusError`](super::http_helpers::HttpStatusError)
    /// carries the code, e.g. `BOND_CLEANUP_PENDING`).
    pub async fn submit_node_op(&self, op: &NodeOp) -> Result<NodeOpResponse> {
        let node_id = self
            .node_id()
            .ok_or_else(|| anyhow!("authentication required to submit a node op"))?
            .to_string();

        let (contract, expr) = op.contract_and_expr()?;
        let contract = match contract {
            OpContract::Staking => self.staking_contract_address.clone(),
            OpContract::Filestorage => self.contract_address.clone(),
        };
        let (bls_signature, nonce) = self.sign_kontor_call(contract, expr)?;

        let payload = NodeOpRequest {
            op: op.name(),
            amount: op.amount().map(|amount| amount.to_string()),
            agreement_id: op.agreement_id().map(str::to_string),
            bls_signature,
            nonce,
        };
        let body_bytes =
            serde_json::to_vec(&payload).context("failed to serialize node op request")?;

        let url = self.api_path(&format!("/api/nodes/{}/ops", urlencoding::encode(&node_id)));
        let request =
            self.build_signed_request(Method::POST, &url, Some((&body_bytes, "application/json")))?;

        // Every 4xx is the Portal saying what became of the op: refused and
        // not stored (the nonce came back, see `send_signed_op`), or `409`,
        // another op of this node at that nonce. Anything else — no answer, a
        // 5xx, a `202` that cannot be read — leaves the question open, and the
        // caller must assume the op may be queued.
        let unsettled = |err: anyhow::Error| match status_and_code(&err) {
            Some((status, _)) if (400..500).contains(&status) => err,
            _ => err.context(UnsettledOp { nonce }),
        };
        let resp = self
            .send_signed_op(
                request.body(body_bytes),
                nonce,
                &format!("submit {}", op.name()),
            )
            .await
            .map_err(unsettled)?;
        let mut body = resp
            .json::<NodeOpResponse>()
            .await
            .context("failed to deserialize node op response")
            .map_err(unsettled)?;
        // What the node signed is the authority on which nonce the op holds; an
        // echo that disagrees would be a Portal bug, not a reason to track the
        // wrong one.
        if body.nonce != Some(nonce) {
            tracing::warn!(
                op = op.name(),
                signed = nonce,
                echoed = ?body.nonce,
                "the Portal echoed a different nonce for a node op"
            );
        }
        body.nonce = Some(nonce);
        Ok(body)
    }

    /// List this node's relayed ops as the Portal holds them, newest first
    /// (Portal `docs/node-portal-contract.md` §2).
    ///
    /// `statuses` filters on `queued`, `submitted`, `confirmed`, `failed`;
    /// empty lists every status. One page of [`NODE_OPS_PAGE`] ops: the node
    /// sends one op at a time, so the one it is asking about is among the
    /// newest.
    ///
    /// # Errors
    /// If the client is unauthenticated or the request fails.
    pub async fn list_node_ops(&self, statuses: &[&str]) -> Result<Vec<NodeOpRecord>> {
        let node_id = self
            .node_id()
            .ok_or_else(|| anyhow!("authentication required to list node ops"))?;
        let mut url = self.api_path(&format!(
            "/api/nodes/{}/ops?limit={NODE_OPS_PAGE}",
            urlencoding::encode(node_id)
        ));
        if !statuses.is_empty() {
            url.push_str("&status=");
            url.push_str(&urlencoding::encode(&statuses.join("|")));
        }
        let request = self.build_signed_request(Method::GET, &url, None)?;
        let resp = request.send().await?;
        let resp = check_response_status(resp, "list node ops").await?;
        let page = resp
            .json::<NodeOpsPage>()
            .await
            .context("failed to deserialize node ops listing")?;
        Ok(page.ops)
    }
}

/// How many relayed ops [`PortalClient::list_node_ops`] asks for: the
/// Portal's page cap.
const NODE_OPS_PAGE: u32 = 100;

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

#[derive(Debug, Clone, Deserialize)]
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
    #[allow(dead_code)]
    pub transaction_id: Option<String>,
    #[allow(dead_code)]
    pub txid: Option<String>,
    #[allow(dead_code)]
    pub tx_block_height: Option<u64>,
    #[allow(dead_code)]
    pub tx_block_time: Option<u64>,
    #[allow(dead_code)]
    pub tx_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgreementNode {
    pub node_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Agreement {
    pub agreement_id: String,
    pub user_id: String,
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub original_size: u64,
    pub nodes: Vec<AgreementNode>,
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
    /// Content-addressed `obj_<sha256>` id of the file, i.e. the
    /// `object-id` field of the on-chain file descriptor. Carried through
    /// verbatim rather than recomputed so the node's `FileMetadata` is the
    /// descriptor the contract published.
    pub file_hash: Option<String>,
    /// Stable, append-only ledger slot the filestorage contract assigned this
    /// file (`agreement-data.ledger-index`).
    ///
    /// A public input of the PoR SNARK since kontor-crypto 0.3.0: the prover
    /// resolves it from its local `FileLedger` and the contract from its own
    /// registry, so the file must occupy exactly this slot locally or the proof
    /// will not verify. `None` until the Portal has reconciled the creating
    /// transaction against Kontor.
    ///
    /// Being an `Option`, serde also leaves it `None` when a Portal predating
    /// the field omits it entirely: such agreements are still downloaded and
    /// served, only proof computation refuses to proceed without a slot.
    pub ledger_index: Option<u64>,
    /// `agreement-data.required-collateral`: how much of the node's bonded
    /// stake joining this agreement reserves, as a decimal string (Portal
    /// `docs/node-portal-contract.md` §4). Kontor refuses the join unless the
    /// unreserved stake covers it, and a missed challenge on the agreement is
    /// slashed at 30× this amount.
    ///
    /// `None` until the Portal has reconciled the creating transaction — the
    /// same lifecycle as `ledger_index` — and on a Portal predating staking.
    #[serde(default)]
    pub required_collateral: Option<String>,
    /// `agreement-data.storage-weight`, the agreement's share of storage
    /// rewards. Carried for the operator's benefit; nothing decides on it.
    #[allow(dead_code)]
    #[serde(default)]
    pub storage_weight: Option<String>,
    #[allow(dead_code)]
    pub txid: Option<String>,
    #[allow(dead_code)]
    pub block_height: Option<u64>,
    #[allow(dead_code)]
    pub block_time: Option<u64>,
    #[allow(dead_code)]
    pub thumbnail_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JoinAgreementResponse {
    pub node_id: String,
    pub created: bool,
    #[allow(dead_code)]
    pub agreement_id: Option<String>,
    #[allow(dead_code)]
    pub joined_at: Option<String>,
    /// The nonce this node signed the join with. Filled in by the client, not
    /// read from the Portal: it is what tells the daemon when the join has
    /// executed and its collateral reservation shows up in the stake.
    #[serde(skip)]
    pub nonce: Option<u64>,
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

/// Result of `GET /api/nodes/{node_id}/check`.
///
/// `bls_public_key` is `null` on a row the Portal created without one, so it
/// stays optional here rather than becoming an empty string.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct NodeCheckResult {
    pub node_id: String,
    /// The whitelisted P2TR address this node registered from.
    pub address: String,
    pub xpubkey: String,
    pub bls_public_key: Option<String>,
    pub signer_id: Option<u64>,
}

/// Body of `POST /api/nodes/register`.
///
/// Built by [`crate::node::registration::build_registration_request`]; every
/// field is hex except `xpubkey`, which is base58.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterNodeRequest {
    pub xpubkey: String,
    pub bls_pubkey: String,
    pub schnorr_sig: String,
    pub bls_sig: String,
    pub registration_signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterNodeResponse {
    pub node_id: String,
    #[allow(dead_code)]
    pub x_only_pubkey: String,
    #[allow(dead_code)]
    pub bls_public_key: String,
}

/// Body of `POST /api/nodes/whitelist/request`.
///
/// Built by [`crate::node::registration::build_whitelist_request`]. The first
/// four fields are the same proof of possession a registration carries — the
/// Portal derives the P2TR address from `xpubkey` itself, which is why no
/// address travels here — and the rest are the operator's contact details for
/// the Portal admin reviewing the queue.
#[derive(Debug, Clone, Serialize)]
pub struct WhitelistRequestBody {
    pub xpubkey: String,
    pub bls_pubkey: String,
    pub schnorr_sig: String,
    pub bls_sig: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
}

/// What both whitelist-request endpoints answer.
///
/// `whitelisted` is the field a waiting node acts on — `status` is the
/// reviewer's verdict, and the two can differ if the address is removed from
/// the whitelist after an approval. `request_id` is absent for an address that
/// was whitelisted by hand without ever going through the queue.
#[derive(Debug, Clone, Deserialize)]
pub struct WhitelistRequestView {
    pub request_id: Option<i64>,
    pub bitcoin_address: String,
    pub status: String,
    pub whitelisted: bool,
    pub review_note: Option<String>,
    pub requested_at: Option<String>,
    pub updated_at: Option<String>,
    pub reviewed_at: Option<String>,
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
    pub kor_balance: Option<String>,
    pub user_id: Option<String>,
    /// Bonded stake in the staking contract, `"0"` when there is none.
    ///
    /// This and every field below are Portal `docs/node-portal-contract.md` §3
    /// additions, all optional: a Portal predating staking omits them, and one
    /// that could not reach Kontor may send `null`. Either way they read as
    /// "unknown", which the daemon treats as "keep the pre-staking behaviour",
    /// never as zero. They stay strings here so that a value the node cannot
    /// parse costs the staking decision of one cycle rather than the nonce
    /// resync that rides on the same request.
    #[serde(default)]
    pub stake: Option<String>,
    /// `filestorage::get-node-reservation`: stake held by joined agreements.
    #[serde(default)]
    pub stake_reserved: Option<String>,
    /// `max(stake − reserved, 0)`: what new joins can still reserve.
    #[serde(default)]
    pub stake_available: Option<String>,
    /// Set once `begin-unstake` has executed: the height from which
    /// `withdraw-stake` is allowed. Non-null means no more joins and no more
    /// stake.
    #[serde(default)]
    pub stake_withdrawal_height: Option<u64>,
    /// The stake was slashed to zero and Kontor is unwinding this node's
    /// memberships; it can neither join nor add stake until that finishes.
    #[serde(default)]
    pub bond_cleanup_pending: Option<bool>,
    /// Storage rewards claimable with `claim-rewards`.
    #[serde(default)]
    pub reward_balance: Option<String>,
}

/// Body of `POST /api/nodes/{node_id}/ops`.
#[derive(Debug, Serialize)]
struct NodeOpRequest {
    op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agreement_id: Option<String>,
    bls_signature: String,
    nonce: u64,
}

/// One relayed op as `GET /api/nodes/{node_id}/ops` lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeOpRecord {
    /// `add_stake`, `begin_unstake`, `withdraw_stake`, `claim_rewards` or
    /// `leave_agreement`.
    pub op: String,
    pub nonce: u64,
    /// `queued` → `submitted` (batched) → `confirmed` / `failed`.
    pub status: String,
    /// Kontor's rendering of the failure, for a `failed` op.
    #[serde(default)]
    pub error: Option<String>,
    /// The Bitcoin txid of the carrying batch, once composed.
    #[allow(dead_code)]
    #[serde(default)]
    pub txid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NodeOpsPage {
    ops: Vec<NodeOpRecord>,
}

/// The relay's `202`: the op is queued, not executed.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct NodeOpResponse {
    pub op: String,
    pub status: String,
    #[serde(default)]
    pub nonce: Option<u64>,
}

/// Attached to a [`PortalClient::submit_node_op`] error when the Portal may
/// hold the op all the same: the request failed in transit or timed out, the
/// Portal answered with a 5xx, or its `202` could not be read. The Portal
/// stores the op only after several Kontor reads, so a client timeout after
/// the row is written is routine. The op was signed at `nonce`, which stays
/// consumed (see `release_nonce`); the caller keeps it in flight until the
/// Portal's listing says what became of it, rather than signing it again and
/// having both execute. Read it with `err.downcast_ref::<UnsettledOp>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsettledOp {
    pub nonce: u64,
}

impl std::fmt::Display for UnsettledOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the op signed at nonce {} may have been stored by the Portal",
            self.nonce
        )
    }
}

#[derive(Debug, Serialize)]
struct FaucetRequest {
    recipient: String,
    amount: f64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct FaucetResponse {
    pub commit_txid: String,
    pub reveal_txid: String,
    pub recipient: String,
    pub amount: f64,
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::{
        join_agreement_expr, resynced_nonce, verify_proof_expr, wave_string_literal, NodeOp,
        OpContract, PortalClient, RegistryEntry, UnsettledOp, DEFAULT_FILESTORAGE_CONTRACT,
        DEFAULT_STAKING_CONTRACT, KONTOR_MAX_NONCE_GAP,
    };
    use crate::clients::kontor_op::{build_signing_message, Inst, InstKind, SignerRef};
    use crate::clients::kor::Kor;
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

    #[test]
    fn wave_string_literal_accepts_alphanumeric_and_underscore_dash() {
        assert_eq!(
            wave_string_literal("AGREEMENT-test_123").unwrap(),
            "\"AGREEMENT-test_123\""
        );
        assert_eq!(wave_string_literal("a").unwrap(), "\"a\"");
        assert_eq!(wave_string_literal("NODE-x").unwrap(), "\"NODE-x\"");
        assert_eq!(
            wave_string_literal("chal_existing").unwrap(),
            "\"chal_existing\""
        );
    }

    #[test]
    fn wave_string_literal_rejects_quote() {
        let err = wave_string_literal("foo\"bar").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid character"),
            "expected 'invalid character' in error, got {msg}"
        );
    }

    #[test]
    fn wave_string_literal_rejects_backslash() {
        assert!(wave_string_literal("foo\\bar").is_err());
    }

    #[test]
    fn wave_string_literal_rejects_parenthesis() {
        assert!(wave_string_literal("foo(bar").is_err());
        assert!(wave_string_literal("foo)bar").is_err());
    }

    #[test]
    fn wave_string_literal_rejects_empty() {
        assert!(wave_string_literal("").is_err());
    }

    #[test]
    fn wave_string_literal_rejects_other_special_chars() {
        for bad in [" ", ",", ".", "\n", "\t", "\0", "/", ";", "[", "]", "*"] {
            assert!(
                wave_string_literal(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    /// The joining node is taken from `ctx.signer()` by the contract, so the
    /// expression carries the agreement id alone. Must match the Portal's
    /// `build_join_agreement_expr` byte for byte, since the Portal rebuilds it
    /// to verify this node's BLS signature.
    #[test]
    fn join_agreement_expr_carries_only_the_agreement_id() {
        let expr = join_agreement_expr("AGREEMENT-test123").unwrap();
        assert_eq!(expr, "join-agreement(\"AGREEMENT-test123\")");
    }

    #[test]
    fn join_agreement_expr_rejects_injection() {
        // Attempt to break out of the string literal and append extra calls.
        let injection = "AGREEMENT-1\", \"evil\"); drop-table(\"";
        let err = join_agreement_expr(injection).unwrap_err();
        assert!(err.to_string().contains("invalid character"));

        // Backslash-based injection.
        let err3 = join_agreement_expr("AGREEMENT-1\\evil").unwrap_err();
        assert!(err3.to_string().contains("invalid character"));
    }

    /// Mirrors the Portal's `verify_proof_expr_format` /
    /// `verify_proof_expr_renders_multiple_challenge_ids` tests: the two sides
    /// must render the same string or the signature check fails.
    #[test]
    fn verify_proof_expr_declares_the_challenge_ids() {
        let expr = verify_proof_expr(&[1, 2, 3], &["chal_1"]).unwrap();
        assert_eq!(expr, "verify-proof([1, 2, 3], [\"chal_1\"])");

        let expr = verify_proof_expr(&[7], &["chal_1", "chal_2"]).unwrap();
        assert_eq!(expr, "verify-proof([7], [\"chal_1\", \"chal_2\"])");
    }

    #[test]
    fn verify_proof_expr_rejects_injection_in_challenge_ids() {
        let err = verify_proof_expr(&[1], &["chal\", \"evil"]).unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

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
        assert_eq!(client.contract_address, DEFAULT_FILESTORAGE_CONTRACT);
    }

    /// The contract address goes into the signed `Inst`, and the Portal
    /// rebuilds that `Inst` from its own `KONTOR_CONTRACT_ADDRESS` to check the
    /// signature. Signing the same expression against two different contracts
    /// must therefore produce two different signatures — otherwise the override
    /// would be silently ignored and a mis-targeted node would look fine until
    /// the Portal rejected every op.
    #[test]
    fn contract_address_is_bound_into_the_signature() {
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let build = |contract: &str| {
            PortalClient::with_auth(
                "https://example.com/api",
                "/tmp/storage",
                Arc::clone(&keypair),
                "NODE-test",
                42,
                "test-jwt-token",
                7,
            )
            .with_contract_address(contract)
        };

        let default_client = build(DEFAULT_FILESTORAGE_CONTRACT);
        let other_client = build("filestorage_1_0");
        assert_eq!(other_client.contract_address, "filestorage_1_0");

        let expr = join_agreement_expr("AGREEMENT-test").unwrap();
        let (default_sig, default_nonce) = default_client.sign_kontor_op(expr.clone()).unwrap();
        let (other_sig, other_nonce) = other_client.sign_kontor_op(expr).unwrap();

        assert_eq!(default_nonce, other_nonce, "both clients start at nonce 7");
        assert_ne!(
            default_sig, other_sig,
            "a different contract address must change the signed message"
        );
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

    /// The Portal leaves `bls_public_key` null on a node row it wrote without
    /// one, and the guard in onboarding branches on exactly that, so it must
    /// arrive as `None` rather than failing to deserialize.
    #[tokio::test]
    async fn check_node_accepts_a_row_without_a_bls_key() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/node-abc/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-abc",
                "address": "tb1pexample",
                "xpubkey": "tpubExample",
                "bls_public_key": null,
                "signer_id": null
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("check_node_null"));
        let result = client.check_node("node-abc").await.unwrap();

        assert_eq!(result.node_id, "node-abc");
        assert_eq!(result.address, "tb1pexample");
        assert!(result.bls_public_key.is_none());
        assert!(result.signer_id.is_none());
    }

    #[tokio::test]
    async fn check_node_surfaces_a_404_as_an_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/node-missing/check"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("check_node_404"));
        assert!(client.check_node("node-missing").await.is_err());
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
                    "nodes": [{"node_id": "NODE-1", "status": "valid"}],
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
    async fn get_new_agreements_deserializes_new_nodes_format() {
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
                    "agreement_id": "AGREEMENT-NEW",
                    "user_id": "user_1",
                    "file_id": "FILE-abc",
                    "filename": "contract.pdf",
                    "mime_type": "application/pdf",
                    "original_size": 1024,
                    "nodes": [
                        {"node_id": "NODE-1", "status": "valid"},
                        {"node_id": "NODE-2", "status": "failed"}
                    ],
                    "transaction_id": null,
                    "curation": {},
                    "status": "ready",
                    "created_at": "2024-01-15T10:30:00Z"
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("agreements_nodes_format"));
        let agreements = client.get_new_agreements().await.unwrap();

        assert_eq!(agreements.len(), 1);
        let nodes = &agreements[0].nodes;
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].node_id, "NODE-1");
        assert_eq!(nodes[0].status, "valid");
        assert_eq!(nodes[1].node_id, "NODE-2");
        assert_eq!(nodes[1].status, "failed");
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
                        "nodes": [{"node_id": "N1", "status": "valid"}],
                        "transaction_id": null, "curation": {},
                        "status": "ready", "created_at": "2024-01-01T00:00:00Z"
                    },
                    {
                        "agreement_id": "AGR-2", "user_id": "u1", "file_id": "F-2",
                        "filename": "b.pdf", "mime_type": "application/pdf", "original_size": 20,
                        "nodes": [{"node_id": "N1", "status": "valid"}],
                        "transaction_id": null, "curation": {},
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
                        "nodes": [{"node_id": "N1", "status": "valid"}],
                        "transaction_id": null, "curation": {},
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
    async fn pagination_terminates_when_total_positive_but_items_empty() {
        // Regression test for an infinite-loop bug: if the API reports
        // `total > 0` but returns an empty `agreements` array (e.g. because
        // status filtering happens after the count), the pagination loop must
        // bail out instead of spinning forever.
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .and(query_param("offset", "0"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 20,
                "total": 5,
                "agreements": []
            })))
            // Expect exactly one call: if the loop spins, this would be hit many times.
            .expect(1)
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::with_auth(
            mock_server.uri(),
            storage_dir("pagination_empty_items"),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            0,
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get_new_agreements(),
        )
        .await
        .expect("paginate should not hang when items array is empty")
        .expect("paginate should succeed");

        assert!(
            result.is_empty(),
            "expected empty result when API returns no items, got {result:?}"
        );
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

    fn client_with_nonce(uri: String, dir: &str, nonce: u64) -> PortalClient {
        PortalClient::with_auth(
            uri,
            storage_dir(dir),
            Arc::new(BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "test-jwt-token",
            nonce,
        )
    }

    async fn mount_registry_nonce(mock_server: &MockServer, next_nonce: u64) {
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abcd",
                "bls_pubkey": null,
                "next_nonce": next_nonce
            })))
            .mount(mock_server)
            .await;
    }

    /// Kontor ahead of the counter — a first start, or ops signed elsewhere —
    /// moves it forward.
    #[tokio::test]
    async fn resync_moves_the_local_nonce_up_to_kontors() {
        let mock_server = MockServer::start().await;
        mount_registry_nonce(&mock_server, 99).await;
        let client = client_with_nonce(mock_server.uri(), "resync_nonce", 5);

        let entry = client.resync_from_registry().await.unwrap();
        assert_eq!(entry.next_nonce, 99);
        assert_eq!(client.current_nonce(), Some(99));
    }

    /// The counter ahead of Kontor is the normal state between two blocks: the
    /// ops signed since are queued at the Portal under those nonces, and
    /// re-signing them is what collided.
    #[tokio::test]
    async fn resync_never_moves_the_local_nonce_back() {
        let mock_server = MockServer::start().await;
        mount_registry_nonce(&mock_server, 99).await;
        let client = client_with_nonce(mock_server.uri(), "resync_nonce_ahead", 120);

        client.resync_from_registry().await.unwrap();
        assert_eq!(client.current_nonce(), Some(120));
        client.resync_from_registry().await.unwrap();
        assert_eq!(client.current_nonce(), Some(120), "and not on the next one");
    }

    /// Further ahead than Kontor accepts, every op would be refused: fall back.
    #[tokio::test]
    async fn resync_falls_back_to_kontor_past_the_max_gap() {
        let mock_server = MockServer::start().await;
        mount_registry_nonce(&mock_server, 99).await;
        let client = client_with_nonce(
            mock_server.uri(),
            "resync_nonce_runaway",
            99 + KONTOR_MAX_NONCE_GAP + 1,
        );

        client.resync_from_registry().await.unwrap();
        assert_eq!(client.current_nonce(), Some(99));
    }

    #[test]
    fn resynced_nonce_is_monotonic_within_the_gap() {
        assert_eq!(resynced_nonce(5, 99), 99);
        assert_eq!(resynced_nonce(99, 99), 99);
        assert_eq!(resynced_nonce(120, 99), 120);
        assert_eq!(
            resynced_nonce(99 + KONTOR_MAX_NONCE_GAP, 99),
            99 + KONTOR_MAX_NONCE_GAP,
            "exactly the gap Kontor still accepts"
        );
        assert_eq!(resynced_nonce(100 + KONTOR_MAX_NONCE_GAP, 99), 99);
        assert_eq!(resynced_nonce(u64::MAX, 0), 0);
    }

    #[tokio::test]
    async fn resync_requires_authentication() {
        let client = PortalClient::new("http://localhost:1234", storage_dir("resync_no_auth"));
        let err = client.resync_from_registry().await.unwrap_err();
        assert!(
            err.to_string().contains("authentication required"),
            "expected auth error, got {err}"
        );
    }

    /// The relay rebuilds each op from its name alone (Portal
    /// `docs/node-portal-contract.md` §2), so the contract and expression here
    /// are what the Portal will verify the signature against.
    #[test]
    fn node_ops_target_the_contracts_the_relay_rebuilds() {
        let (contract, expr) = NodeOp::AddStake(Kor::parse("250.5").unwrap())
            .contract_and_expr()
            .unwrap();
        assert!(matches!(contract, OpContract::Staking));
        assert_eq!(
            expr,
            "add-stake({r0: 10692327041775828992, r1: 13, r2: 0, r3: 0, sign: plus})"
        );

        let (contract, expr) = NodeOp::BeginUnstake.contract_and_expr().unwrap();
        assert!(matches!(contract, OpContract::Staking));
        assert_eq!(expr, "begin-unstake()");

        let (contract, expr) = NodeOp::WithdrawStake.contract_and_expr().unwrap();
        assert!(matches!(contract, OpContract::Staking));
        assert_eq!(expr, "withdraw-stake()");

        let (contract, expr) = NodeOp::ClaimRewards.contract_and_expr().unwrap();
        assert!(matches!(contract, OpContract::Filestorage));
        assert_eq!(expr, "claim-rewards()");

        assert_eq!(NodeOp::AddStake(Kor::ONE).name(), "add_stake");
        assert_eq!(NodeOp::BeginUnstake.name(), "begin_unstake");
        assert_eq!(NodeOp::WithdrawStake.name(), "withdraw_stake");
        assert_eq!(NodeOp::ClaimRewards.name(), "claim_rewards");

        let leave = NodeOp::LeaveAgreement("agr_7f-3c".into());
        let (contract, expr) = leave.contract_and_expr().unwrap();
        assert!(matches!(contract, OpContract::Filestorage));
        assert_eq!(expr, "leave-agreement(\"agr_7f-3c\")");
        assert_eq!(leave.name(), "leave_agreement");
        assert_eq!(leave.agreement_id(), Some("agr_7f-3c"));
        assert!(
            NodeOp::LeaveAgreement("agr\", \"x".into())
                .contract_and_expr()
                .is_err(),
            "an id that could break out of the literal is refused"
        );
    }

    fn node_op_client(uri: &str, keypair: Arc<BlsKeyPair>, name: &str) -> PortalClient {
        PortalClient::with_auth(
            uri,
            storage_dir(name),
            keypair,
            "NODE-test",
            42,
            "test-jwt-token",
            7,
        )
    }

    /// The signature a correct client must produce for `expr` on `contract`:
    /// the same bytes join and proofs are signed over, self-paid.
    fn expected_signature(keypair: &BlsKeyPair, contract: &str, expr: &str, nonce: u64) -> String {
        let inst = Inst {
            gas_limit: 100_000,
            kind: InstKind::Call {
                contract: contract.to_string(),
                expr: expr.to_string(),
            },
        };
        let msg = build_signing_message(&SignerRef::SignerId(42), nonce, false, &inst).unwrap();
        keypair.sign_kontor_op_message(&msg).unwrap()
    }

    async fn mount_ops_accepting(mock_server: &MockServer, op: &str) {
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(header_exists("Authorization"))
            .and(header_exists("Content-Digest"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": op,
                "status": "queued",
                "nonce": 7
            })))
            .mount(mock_server)
            .await;
    }

    async fn sent_body(mock_server: &MockServer) -> serde_json::Value {
        let requests = mock_server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|r| r.url.path() == "/api/nodes/NODE-test/ops")
            .expect("the op was posted");
        serde_json::from_slice(&request.body).unwrap()
    }

    #[tokio::test]
    async fn add_stake_is_signed_against_the_staking_contract_with_an_exact_amount() {
        let mock_server = MockServer::start().await;
        mount_ops_accepting(&mock_server, "add_stake").await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), Arc::clone(&keypair), "add_stake");
        let response = client
            .submit_node_op(&NodeOp::AddStake(Kor::parse("250.50").unwrap()))
            .await
            .unwrap();

        assert_eq!(response.status, "queued");
        assert_eq!(response.nonce, Some(7));
        assert_eq!(client.current_nonce(), Some(8), "the op consumed nonce 7");

        let body = sent_body(&mock_server).await;
        assert_eq!(body["op"], "add_stake");
        assert_eq!(
            body["amount"], "250.5",
            "canonical decimal string, never a float"
        );
        assert_eq!(body["nonce"], 7);
        assert_eq!(
            body["bls_signature"],
            expected_signature(
                &keypair,
                DEFAULT_STAKING_CONTRACT,
                "add-stake({r0: 10692327041775828992, r1: 13, r2: 0, r3: 0, sign: plus})",
                7
            )
        );
    }

    #[tokio::test]
    async fn claim_rewards_is_a_filestorage_call_with_no_amount() {
        let mock_server = MockServer::start().await;
        mount_ops_accepting(&mock_server, "claim_rewards").await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), Arc::clone(&keypair), "claim")
            .with_contract_address("filestorage_9_1");
        client.submit_node_op(&NodeOp::ClaimRewards).await.unwrap();

        let body = sent_body(&mock_server).await;
        assert_eq!(body["op"], "claim_rewards");
        assert!(body.get("amount").is_none(), "{body}");
        assert_eq!(
            body["bls_signature"],
            expected_signature(&keypair, "filestorage_9_1", "claim-rewards()", 7)
        );
    }

    /// The staking address is configuration on both sides and part of the
    /// signed bytes, so overriding it must change what is signed.
    #[tokio::test]
    async fn the_staking_address_override_is_what_gets_signed() {
        let mock_server = MockServer::start().await;
        mount_ops_accepting(&mock_server, "begin_unstake").await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), Arc::clone(&keypair), "unstake")
            .with_staking_contract_address("staking_4_2");
        client.submit_node_op(&NodeOp::BeginUnstake).await.unwrap();

        let body = sent_body(&mock_server).await;
        assert_eq!(
            body["bls_signature"],
            expected_signature(&keypair, "staking_4_2", "begin-unstake()", 7)
        );
    }

    /// A 4xx means the Portal kept nothing, so the nonce goes back: otherwise
    /// every later op of the cycle would be one ahead and dropped. A 5xx is
    /// ambiguous and keeps it consumed until the next resync.
    #[tokio::test]
    async fn a_refused_op_gives_its_nonce_back_and_an_ambiguous_one_does_not() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(wiremock::matchers::body_partial_json(
                json!({"op": "add_stake"}),
            ))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "error": {"code": "BOND_CLEANUP_PENDING", "message": "cleanup", "status": 422}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(wiremock::matchers::body_partial_json(
                json!({"op": "claim_rewards"}),
            ))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "refused");

        let err = client
            .submit_node_op(&NodeOp::AddStake(Kor::ONE))
            .await
            .unwrap_err();
        assert_eq!(
            crate::clients::http_helpers::status_and_code(&err),
            Some((422, Some("BOND_CLEANUP_PENDING".to_string())))
        );
        assert_eq!(client.current_nonce(), Some(7), "refused: nonce released");
        assert_eq!(
            err.downcast_ref::<UnsettledOp>(),
            None,
            "a refusal is a settled outcome: nothing was stored"
        );

        let err = client
            .submit_node_op(&NodeOp::ClaimRewards)
            .await
            .unwrap_err();
        assert_eq!(client.current_nonce(), Some(8), "5xx: nonce stays consumed");
        assert_eq!(
            err.downcast_ref::<UnsettledOp>(),
            Some(&UnsettledOp { nonce: 7 }),
            "and the caller learns which nonce may be queued: {err:#}"
        );
        assert_eq!(
            crate::clients::http_helpers::status_and_code(&err),
            Some((503, None)),
            "the status is still readable through the marker"
        );
    }

    /// A Portal that cannot be reached at all is the same open question as a
    /// 5xx: the op never left, but the client cannot tell that from a request
    /// that timed out after the Portal stored it.
    #[tokio::test]
    async fn an_unreachable_portal_leaves_the_op_unsettled() {
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client("http://127.0.0.1:1", keypair, "unreachable");
        let err = client
            .submit_node_op(&NodeOp::ClaimRewards)
            .await
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<UnsettledOp>(),
            Some(&UnsettledOp { nonce: 7 }),
            "{err:#}"
        );
        assert_eq!(client.current_nonce(), Some(8), "nonce stays consumed");
    }

    /// The listing the node consults before giving an accepted op up for
    /// dropped: signed like every node request, one page, newest first, with
    /// the status filter pipe-separated as the Portal reads it.
    #[tokio::test]
    async fn list_node_ops_reads_one_page_with_an_optional_status_filter() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(query_param("limit", "100"))
            .and(query_param("status", "queued|submitted"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0,
                "limit": 100,
                "total": 2,
                "node_id": "NODE-test",
                "ops": [
                    {
                        "id": "b", "node_id": "NODE-test", "op": "add_stake", "amount": "995",
                        "agreement_id": null, "nonce": 8, "status": "submitted",
                        "transaction_id": "t1", "error": null, "txid": "deadbeef",
                        "created_at": "2026-11-03T10:00:00+00:00",
                        "updated_at": "2026-11-03T10:05:00+00:00"
                    },
                    {
                        "id": "a", "node_id": "NODE-test", "op": "leave_agreement",
                        "amount": null, "agreement_id": "agr_1", "nonce": 7,
                        "status": "failed", "transaction_id": null,
                        "error": "nonce 7 is below the signer's next nonce", "txid": null,
                        "created_at": "2026-11-03T09:00:00+00:00",
                        "updated_at": "2026-11-03T09:30:00+00:00"
                    }
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(query_param("limit", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 100, "total": 0, "node_id": "NODE-test", "ops": []
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "list_ops");
        let ops = client
            .list_node_ops(&["queued", "submitted"])
            .await
            .unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!((ops[0].op.as_str(), ops[0].nonce), ("add_stake", 8));
        assert_eq!(ops[0].status, "submitted");
        assert_eq!(ops[0].txid.as_deref(), Some("deadbeef"));
        assert_eq!(ops[1].status, "failed");
        assert!(ops[1].error.as_deref().unwrap().contains("nonce 7"));

        assert!(client.list_node_ops(&[]).await.unwrap().is_empty());
        let requests = mock_server.received_requests().await.unwrap();
        let unfiltered = requests
            .iter()
            .filter(|r| r.url.path() == "/api/nodes/NODE-test/ops")
            .filter(|r| !r.url.query().unwrap_or("").contains("status="))
            .count();
        assert_eq!(unfiltered, 1, "no filter means no status parameter");

        let unauthenticated =
            PortalClient::new("http://localhost:1234", storage_dir("list_ops_no_auth"));
        assert!(unauthenticated.list_node_ops(&[]).await.is_err());
    }

    #[tokio::test]
    async fn submit_node_op_requires_authentication() {
        let client = PortalClient::new("http://localhost:1234", storage_dir("op_no_auth"));
        let err = client
            .submit_node_op(&NodeOp::ClaimRewards)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("authentication required"), "{err}");
    }

    /// Same release for a join the Portal turns down at its pre-check
    /// (Portal `docs/node-portal-contract.md` §5),
    /// which the daemon now survives instead of aborting the cycle.
    #[tokio::test]
    async fn a_join_refused_for_collateral_releases_its_nonce() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-1/join"))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "error": {"code": "INSUFFICIENT_COLLATERAL", "message": "no", "status": 422}
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "join_refused");
        client.join_agreement("AGR-1").await.unwrap_err();
        assert_eq!(client.current_nonce(), Some(7));
    }

    /// The detail endpoint carries this node's row whatever its status — the
    /// node-filtered listings only show memberships still `valid`.
    #[tokio::test]
    async fn get_agreement_reads_one_agreement_with_every_membership_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-1"))
            .and(header_exists("Authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agreement_id": "AGR-1",
                "user_id": "user_1",
                "file_id": "FILE-1",
                "filename": "test.bin",
                "mime_type": "application/octet-stream",
                "original_size": 123,
                "nodes": [
                    {"node_id": "NODE-test", "status": "left"},
                    {"node_id": "NODE-other", "status": "valid"}
                ],
                "transaction_id": null,
                "status": "confirmed",
                "created_at": "2024-01-01T00:00:00Z",
                "required_collateral": "12.5"
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "get_agreement");
        let agreement = client.get_agreement("AGR-1").await.unwrap();
        assert_eq!(agreement.status, "confirmed");
        assert_eq!(agreement.nodes[0].node_id, "NODE-test");
        assert_eq!(agreement.nodes[0].status, "left");
        assert_eq!(agreement.required_collateral.as_deref(), Some("12.5"));

        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-gone"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "AGREEMENT_NOT_FOUND", "message": "no", "status": 404}
            })))
            .mount(&mock_server)
            .await;
        assert!(client.get_agreement("AGR-gone").await.is_err());
    }

    #[tokio::test]
    async fn a_created_join_reports_the_nonce_it_was_signed_with() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-1/join"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "node_id": "NODE-test",
                "created": true,
                "nonce": 999
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "join_nonce");
        let response = client.join_agreement("AGR-1").await.unwrap();
        assert_eq!(
            response.nonce,
            Some(7),
            "what was signed, not what was echoed"
        );
    }

    /// A Portal predating staking sends none of the signer stake fields
    /// (Portal `docs/node-portal-contract.md` §3); one that is current sends
    /// all of them. Both must deserialize, and the new fields stay strings so a
    /// strange value cannot break the nonce resync.
    #[test]
    fn registry_entry_reads_with_and_without_the_stake_fields() {
        let old: RegistryEntry = serde_json::from_value(json!({
            "signer_id": 42,
            "x_only_pubkey": "ab",
            "bls_pubkey": null,
            "next_nonce": 3,
            "kor_balance": "10"
        }))
        .unwrap();
        assert_eq!(old.stake, None);
        assert_eq!(old.bond_cleanup_pending, None);

        let new: RegistryEntry = serde_json::from_value(json!({
            "signer_id": 42,
            "x_only_pubkey": "ab",
            "bls_pubkey": null,
            "next_nonce": 3,
            "kor_balance": "5",
            "stake": "995",
            "stake_reserved": "30.5",
            "stake_available": "964.5",
            "stake_withdrawal_height": null,
            "bond_cleanup_pending": false,
            "reward_balance": "not-a-number"
        }))
        .unwrap();
        assert_eq!(new.stake.as_deref(), Some("995"));
        assert_eq!(new.stake_reserved.as_deref(), Some("30.5"));
        assert_eq!(new.stake_available.as_deref(), Some("964.5"));
        assert_eq!(new.stake_withdrawal_height, None);
        assert_eq!(new.bond_cleanup_pending, Some(false));
        assert_eq!(new.reward_balance.as_deref(), Some("not-a-number"));
    }

    #[tokio::test]
    async fn agreements_carry_the_collateral_they_require() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agreements"))
            .and(query_param("status", "ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 2,
                "agreements": [
                    {
                        "agreement_id": "AGR-known", "user_id": "u", "file_id": "F1",
                        "filename": "a", "mime_type": "x", "original_size": 1,
                        "nodes": [], "transaction_id": null, "status": "ready",
                        "created_at": "2024-01-01T00:00:00Z",
                        "required_collateral": "12.5", "storage_weight": "1"
                    },
                    {
                        "agreement_id": "AGR-legacy", "user_id": "u", "file_id": "F2",
                        "filename": "b", "mime_type": "x", "original_size": 1,
                        "nodes": [], "transaction_id": null, "status": "ready",
                        "created_at": "2024-01-01T00:00:00Z"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::new(mock_server.uri(), storage_dir("collateral"));
        let agreements = client.get_new_agreements().await.unwrap();
        assert_eq!(agreements[0].required_collateral.as_deref(), Some("12.5"));
        assert_eq!(agreements[0].storage_weight.as_deref(), Some("1"));
        assert_eq!(agreements[1].required_collateral, None);
    }

    #[tokio::test]
    async fn leave_agreement_names_the_agreement_and_signs_the_filestorage_call() {
        let mock_server = MockServer::start().await;
        mount_ops_accepting(&mock_server, "leave_agreement").await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), Arc::clone(&keypair), "leave");
        client
            .submit_node_op(&NodeOp::LeaveAgreement("agr_1".into()))
            .await
            .unwrap();

        let body = sent_body(&mock_server).await;
        assert_eq!(body["op"], "leave_agreement");
        assert_eq!(body["agreement_id"], "agr_1");
        assert!(body.get("amount").is_none(), "{body}");
        assert_eq!(
            body["bls_signature"],
            expected_signature(
                &keypair,
                DEFAULT_FILESTORAGE_CONTRACT,
                "leave-agreement(\"agr_1\")",
                7
            )
        );
    }

    /// `409 CONFLICT` is the one 4xx after which the Portal holds something:
    /// another op of this node already has that nonce. Releasing it would sign
    /// the next op at the same, taken, nonce.
    #[tokio::test]
    async fn a_conflict_keeps_the_nonce_consumed() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {"code": "CONFLICT", "message": "nonce 7 is taken", "status": 409}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/agreements/AGR-1/join"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {"code": "CONFLICT", "message": "taken", "status": 409}
            })))
            .mount(&mock_server)
            .await;

        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = node_op_client(&mock_server.uri(), keypair, "conflict");

        let err = client
            .submit_node_op(&NodeOp::ClaimRewards)
            .await
            .unwrap_err();
        assert_eq!(
            crate::clients::http_helpers::status_and_code(&err),
            Some((409, Some("CONFLICT".to_string())))
        );
        assert_eq!(client.current_nonce(), Some(8), "409: the nonce is taken");

        client.join_agreement("AGR-1").await.unwrap_err();
        assert_eq!(client.current_nonce(), Some(9), "same rule for a join");
    }
}
