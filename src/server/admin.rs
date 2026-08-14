//! Password-gated operator UI at `/admin`.
//!
//! # Why it exists
//!
//! When the Kontor signet is reset, every agreement and challenge this node
//! holds refers to a chain that no longer exists, and the files on disk belong
//! to agreements nobody will ever challenge. Short of deleting the `SQLite`
//! file by hand on a machine the operator may not have shell access to, there
//! was no way back. This module is that way back, and mirrors the Horizon
//! Portal's own `/admin` page so an operator moves between the two without
//! relearning anything.
//!
//! # Security model
//!
//! The rest of the server is public by design (see [`crate::server::routes`]).
//! These routes are not, so they carry their own guard rather than relying on a
//! reverse proxy:
//!
//! - A password is exchanged at `POST /api/admin/login` for a session token
//!   that expires after 8 hours. On a node nobody has claimed there is no
//!   password yet: `POST /api/admin/claim` trades the setup token for one, and
//!   until it does, login answers 409. `ADMIN_PASSWORD` overrides whatever is
//!   stored and is the recovery path; `ADMIN_UI_DISABLED` turns the UI off
//!   outright, which is the only state that answers 503. See [`credentials`].
//! - The token is signed with a key generated at startup and never persisted,
//!   so sessions do not survive a restart and there is no long-lived secret on
//!   disk to leak. It is held in `sessionStorage` and sent as a bearer — no
//!   cookie, so no CSRF surface.
//! - Failed attempts are counted per peer IP and every rejection costs a delay.
//!   `X-Forwarded-For` is deliberately not trusted: behind a proxy all clients
//!   collapse into one bucket, whereas a spoofable header would hand an attacker
//!   unlimited buckets. Login and claim are counted separately, and a lockout is
//!   only ever applied to a bucket that belongs to one client — see
//!   `session::penalty` for the two gates that must never close, and what a
//!   shared bucket pays instead.
//! - The admin routes are merged *after* the permissive `CorsLayer`, so they
//!   carry no `Access-Control-Allow-Origin` and a browser refuses to let
//!   another origin read their responses.
//! - Every secret that crosses these routes — the seed phrase at setup, a seal
//!   passphrase, the seal key handed back — is sealed end to end by
//!   [`envelope`], in whichever direction it travels. TLS covers the wire; it
//!   does not cover an edge that logs bodies.

pub mod credentials;
pub mod envelope;
pub mod register;
pub mod reset;
pub mod seal;
pub mod session;
pub mod setup;
pub mod status;
pub mod ui;
pub mod whitelist;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tracing::{debug, error, info};

#[cfg(test)]
use crate::app::config::AdminPassword;
use crate::app::lifecycle::NodeRuntime;
use crate::app::restart::RestartHandle;
use crate::clients::PortalClient;
use crate::crypto::{BlsKeyPair, PublicIdentity};
use crate::server::state::DownloadServerState;
use credentials::AdminCredential;
use session::AdminSession;

/// The node's Portal identity, as the operator UI needs to see it.
///
/// Held by [`AdminState`] rather than read off the daemon's client because the
/// registration endpoint has to work on a node that has no daemon: an
/// unregistered node starts the server and nothing else.
#[derive(Clone)]
pub struct NodeIdentity {
    /// The key being registered, and the key that signs the registration op.
    /// This is the only copy on an unregistered node — the daemon's
    /// authenticated client, which normally owns it, was never built.
    keypair: Arc<BlsKeyPair>,
    /// Unauthenticated Portal client. Registration precedes the JWT by
    /// definition, so the signed-request client would be no use here.
    client: PortalClient,
    /// What the Portal knows about this key, `None` when it knows nothing.
    registered: Option<RegisteredNode>,
    /// The Taproot account this node speaks for, when it knows one. Its
    /// address is what an unregistered node is waiting on, so the page can name
    /// it instead of sending the operator to the logs.
    public: Option<PublicIdentity>,
}

/// The Portal-side identity of a registered node.
#[derive(Clone, Debug)]
pub struct RegisteredNode {
    pub node_id: String,
    pub signer_id: u64,
}

impl NodeIdentity {
    #[must_use]
    pub fn new(
        keypair: Arc<BlsKeyPair>,
        client: PortalClient,
        registered: Option<RegisteredNode>,
        public: Option<PublicIdentity>,
    ) -> Self {
        Self {
            keypair,
            client,
            registered,
            public,
        }
    }

    pub(crate) fn keypair(&self) -> &BlsKeyPair {
        &self.keypair
    }

    pub(crate) fn client(&self) -> &PortalClient {
        &self.client
    }

    pub(crate) fn registered(&self) -> Option<&RegisteredNode> {
        self.registered.as_ref()
    }

    pub(crate) fn public(&self) -> Option<&PublicIdentity> {
        self.public.as_ref()
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("registered", &self.registered)
            .field("public", &self.public)
            .field("keypair", &"<BlsKeyPair>")
            .finish_non_exhaustive()
    }
}

/// Credentials and session-signing material for the operator UI.
///
/// Cloned into every request via [`DownloadServerState`], hence the `Arc`.
#[derive(Clone)]
pub struct AdminState {
    inner: Arc<Inner>,
}

struct Inner {
    /// What guards the UI. Behind a lock because claiming a node replaces it
    /// while the server is already answering requests — that is the whole point
    /// of a node configured through its own UI.
    credential: RwLock<AdminCredential>,
    /// Where `admin.json`, `.setup-token` and the keystore live.
    app_dir: PathBuf,
    /// The live sealed-channel envelope, if one has been issued.
    ///
    /// One slot, not a map. A node is administered by one operator in one
    /// browser; a second `GET` invalidating the first is the correct behaviour,
    /// and it is also what keeps a stale key from lingering after an abandoned
    /// attempt.
    envelope: Mutex<Option<envelope::EnvelopeSession>>,
    /// Serialises every read-modify-write of `keystore.json`.
    ///
    /// The seal endpoints each load the file, change one slot and write it back.
    /// [`crate::crypto::aead::write_secret_file`] makes that write atomic, which
    /// rules out a torn file and nothing else: two requests that both read
    /// before either wrote would still end with one slot silently missing.
    /// Provisioning takes it too, so the phase check that guards it cannot be
    /// raced either.
    ///
    /// `tokio`'s mutex rather than `std`'s because the guard is held across the
    /// `await` on reading the file back.
    keystore: tokio::sync::Mutex<()>,
    /// HMAC key for session tokens. Generated per process and never written
    /// anywhere: a node runs as a single process, so there is nothing to share
    /// a persisted secret with, and an ephemeral key means a leaked token dies
    /// with the next restart.
    session_key: [u8; 32],
    /// Lets a reset ask the run loop to exit so the supervisor restarts the
    /// node. It lives behind the admin gate because the operator UI is the only
    /// thing that ever asks.
    restart: RestartHandle,
    /// The node's live state. The identity lives here rather than in this
    /// struct because it appears *after* the server starts on every path that
    /// matters now — a node provisioned through the wizard has no key when its
    /// `/admin` first answers.
    runtime: NodeRuntime,
}

impl AdminState {
    /// Builds the admin state, generating a fresh session-signing key.
    #[must_use]
    pub fn new(
        credential: AdminCredential,
        app_dir: PathBuf,
        restart: RestartHandle,
        runtime: NodeRuntime,
    ) -> Self {
        use rand::RngCore;

        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);
        Self {
            inner: Arc::new(Inner {
                credential: RwLock::new(credential),
                app_dir,
                envelope: Mutex::new(None),
                keystore: tokio::sync::Mutex::new(()),
                session_key,
                restart,
                runtime,
            }),
        }
    }

    /// The admin UI turned off: `/admin` still renders, but nothing behind it
    /// can be unlocked. Production builds this from the configured password;
    /// only tests need to ask for the disabled state directly.
    #[cfg(test)]
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(
            AdminCredential::Disabled,
            PathBuf::new(),
            RestartHandle::new(),
            NodeRuntime::for_tests(None, None),
        )
    }

    /// Test-only: no password, but a live restart switch, for the reset paths
    /// that assert on it.
    #[cfg(test)]
    #[must_use]
    pub fn with_restart(restart: RestartHandle) -> Self {
        Self::new(
            AdminCredential::Disabled,
            PathBuf::new(),
            restart,
            NodeRuntime::for_tests(None, None),
        )
    }

    /// Test-only: an unlockable UI on a node that refuses restarts, for the
    /// session and routing tests that only care about the password.
    #[cfg(test)]
    #[must_use]
    pub fn with_password(password: AdminPassword) -> Self {
        Self::new(
            AdminCredential::Env(password),
            PathBuf::new(),
            RestartHandle::new(),
            NodeRuntime::for_tests(None, None),
        )
    }

    /// Test-only: a node whose key and Portal client the registration tests
    /// need, with a restart switch they can assert on.
    #[cfg(test)]
    #[must_use]
    pub fn with_identity(identity: NodeIdentity, restart: RestartHandle) -> Self {
        Self::new(
            AdminCredential::Disabled,
            PathBuf::new(),
            restart,
            NodeRuntime::for_tests(None, Some(identity)),
        )
    }

    /// True when there is a password to check, i.e. the UI can be unlocked.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.credential().is_enabled()
    }

    /// True when this node is still waiting to be claimed.
    #[must_use]
    pub fn is_unclaimed(&self) -> bool {
        self.credential().is_unclaimed()
    }

    /// True when the operator turned the UI off outright, as opposed to a node
    /// that simply has no password yet.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.credential().is_disabled()
    }

    /// What a `/admin` page needs to know before it has a session: which pane to
    /// render, and — on an unclaimed node — which token is live.
    #[must_use]
    pub fn bootstrap(&self) -> (bool, Option<String>) {
        let credential = self.credential();
        (credential.is_unclaimed(), credential.token_fingerprint())
    }

    /// Trade a setup token for a password, replacing the live credential.
    ///
    /// The write guard is held across the whole exchange, including the Argon2
    /// hash and the write to `admin.json`. Taking a read guard, releasing it and
    /// then taking a write guard would leave a window two claims could both pass
    /// — `RwLock` cannot promote one into the other — and both would answer with
    /// a session while only the later password survived on disk. It is the same
    /// window [`crate::server::admin::setup::provision`] closes by entering its
    /// phase before dropping its guard. The cost is that other admin requests
    /// wait out one password hash, once in a node's life.
    ///
    /// # Errors
    /// See [`credentials::ClaimError`]. The variants are kept apart all the way
    /// out to the status code: a node whose volume will not take a write must
    /// not tell the operator their token was wrong.
    pub fn claim(&self, token: &str, password: &str) -> Result<(), credentials::ClaimError> {
        let mut current = self.credential_mut();
        *current = credentials::claim(&self.inner.app_dir, &current, token, password)?;
        Ok(())
    }

    fn credential(&self) -> RwLockReadGuard<'_, AdminCredential> {
        self.inner
            .credential
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn credential_mut(&self) -> RwLockWriteGuard<'_, AdminCredential> {
        self.inner
            .credential
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a submitted password is this node's.
    #[must_use]
    pub(crate) fn verify_password(&self, submitted: &str) -> bool {
        self.credential().verify(submitted)
    }

    /// The process-restart switch. See [`RestartHandle`].
    pub(crate) fn restart(&self) -> &RestartHandle {
        &self.inner.restart
    }

    /// The node's key and Portal client, when it has them.
    ///
    /// Owned so a handler can hold it across an await — `register` does exactly
    /// that — without keeping the state lock for a Portal round trip.
    pub(crate) fn identity(&self) -> Option<Arc<NodeIdentity>> {
        self.inner.runtime.identity()
    }

    /// Where this node keeps its keystore and credentials.
    pub(crate) fn app_dir(&self) -> &std::path::Path {
        &self.inner.app_dir
    }

    /// Hold a freshly issued envelope, replacing any previous one.
    pub(crate) fn store_envelope(&self, session: envelope::EnvelopeSession) {
        *self
            .inner
            .envelope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session);
    }

    /// Consume the live envelope, but only if it is the one being asked for.
    ///
    /// An envelope is good for one attempt, whether or not that attempt
    /// succeeds — so a request that names it takes it. A request that names
    /// *something else* leaves it alone: a stale tab replaying an old body
    /// must not be able to invalidate the envelope the operator is in the
    /// middle of using. An expired one is dropped either way; nothing is
    /// gained by keeping a key nobody may spend.
    pub(crate) fn take_envelope(&self, session_id: &str) -> Option<envelope::EnvelopeSession> {
        let mut held = self
            .inner
            .envelope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match held.as_ref() {
            Some(session) if session.is_expired() => {
                *held = None;
                None
            }
            Some(session) if session.id_hex() == session_id => held.take(),
            _ => None,
        }
    }

    /// Take the right to rewrite `keystore.json`. See [`Inner::keystore`].
    pub(crate) async fn lock_keystore(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.keystore.lock().await
    }

    fn session_key(&self) -> &[u8; 32] {
        &self.inner.session_key
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("enabled", &self.is_enabled())
            .field("unclaimed", &self.is_unclaimed())
            .field("runtime", &self.inner.runtime)
            .finish_non_exhaustive()
    }
}

/// Machine-readable error codes returned by the admin API.
///
/// The page keys its behaviour off these rather than off message text.
pub mod error_codes {
    /// The admin UI is turned off outright.
    pub const ADMIN_UI_DISABLED: &str = "ADMIN_UI_DISABLED";
    /// Nobody has claimed this node yet, so there is no password to check.
    pub const ADMIN_NOT_CLAIMED: &str = "ADMIN_NOT_CLAIMED";
    /// The submitted setup token did not match.
    pub const INVALID_SETUP_TOKEN: &str = "INVALID_SETUP_TOKEN";
    /// A claim arrived for a node that already has a password.
    pub const ALREADY_CLAIMED: &str = "ALREADY_CLAIMED";
    /// The password offered at claim time was too short.
    pub const WEAK_PASSWORD: &str = "WEAK_PASSWORD";
    /// The submitted password did not match.
    pub const INVALID_PASSWORD: &str = "INVALID_PASSWORD";
    /// Too many failed logins from this client; retry later.
    pub const TOO_MANY_ATTEMPTS: &str = "TOO_MANY_ATTEMPTS";
    /// No usable admin session on a route that requires one.
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    /// A destructive action was requested without its confirmation phrase.
    pub const CONFIRMATION_REQUIRED: &str = "CONFIRMATION_REQUIRED";
    /// A restart was asked for on a node that could not come back unattended.
    pub const RESTART_UNAVAILABLE: &str = "RESTART_UNAVAILABLE";
    /// Registration was attempted on a node with no BLS key loaded.
    pub const REGISTRATION_UNAVAILABLE: &str = "REGISTRATION_UNAVAILABLE";
    /// The wallet-supplied registration fields were malformed or named the
    /// wrong BLS key.
    pub const INVALID_REGISTRATION: &str = "INVALID_REGISTRATION";
    /// A whitelist request was made on a node that cannot build one — no BLS
    /// key, or no source for the proof of possession.
    pub const WHITELIST_UNAVAILABLE: &str = "WHITELIST_UNAVAILABLE";
    /// A whitelist request carried fields the Portal would refuse.
    pub const INVALID_WHITELIST_REQUEST: &str = "INVALID_WHITELIST_REQUEST";
    /// The Portal refused the registration, or could not be reached.
    pub const PORTAL_ERROR: &str = "PORTAL_ERROR";
    /// A database read or write failed.
    pub const DATABASE_ERROR: &str = "DATABASE_ERROR";
    /// The session could not be issued (signing failure).
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    /// Setup was asked for on a node that already has a key.
    pub const SETUP_UNAVAILABLE: &str = "SETUP_UNAVAILABLE";
    /// The setup envelope is unknown, expired, or its payload did not
    /// authenticate.
    pub const INVALID_ENVELOPE: &str = "INVALID_ENVELOPE";
    /// The decrypted setup payload was not a usable seed phrase.
    pub const INVALID_SETUP: &str = "INVALID_SETUP";
    /// A seal change was asked for that this node is not in a position to make.
    pub const SEAL_UNAVAILABLE: &str = "SEAL_UNAVAILABLE";
}

/// An error rendered as `{"error": {"code": ..., "message": ...}}`.
///
/// The admin page is the only consumer, and it reads `code` to decide whether
/// to show the message, fall back to the login screen, or keep polling.
///
/// `message` is public — it reaches a browser. Anything that names internal
/// machinery (a `DbErr`, a signing failure) belongs in `detail`, which is
/// logged and never serialized.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Logged next to the response, never rendered into it.
    detail: Option<String>,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    #[must_use]
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// Attaches the internal cause. It is logged with the response and stays
    /// out of the body.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// A 500 whose detail is logged but not echoed: the session behind it is an
    /// operator's, but the login screen in front of it is public, and an error
    /// string is the cheapest way to hand out the shape of what is running.
    #[must_use]
    pub fn server_error(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::INTERNAL_ERROR,
            "Internal error",
        )
        .with_detail(detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // The log line carries the cause; the body carries only `message`.
        let logged = self.detail.as_deref().unwrap_or(&self.message);

        // Level matched to severity: 5xx is operator-actionable, 401/403 is an
        // auditable denial, everything else is routine validation noise.
        if self.status.is_server_error() {
            error!(status = self.status.as_u16(), code = self.code, detail = %logged, "Admin API error");
        } else if matches!(
            self.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            info!(status = self.status.as_u16(), code = self.code, detail = %logged, "Admin API auth denial");
        } else {
            debug!(status = self.status.as_u16(), code = self.code, detail = %logged, "Admin API rejection");
        }

        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

/// Routes for the operator UI.
///
/// Merged into the public router *after* its CORS layer so none of these
/// responses become cross-origin readable.
pub fn router() -> Router<DownloadServerState> {
    Router::new()
        // Both spellings: an operator typing the path by hand adds the slash
        // as often as not, and axum does not treat them as the same route.
        .route("/admin", get(ui::admin_page))
        .route("/admin/", get(ui::admin_page))
        .route("/api/admin/bootstrap", get(bootstrap_handler))
        .route("/api/admin/claim", post(claim_handler))
        .route("/api/admin/login", post(login_handler))
        .route("/api/admin/status", get(status_handler))
        .route("/api/admin/reset-database", post(reset_handler))
        .route("/api/admin/register-node", post(register_handler))
        .route(
            "/api/admin/whitelist-request",
            get(whitelist_status_handler).post(whitelist_submit_handler),
        )
        .route("/api/admin/envelope", get(envelope_handler))
        .route("/api/admin/setup/provision", post(provision_handler))
        .route("/api/admin/seal", get(seal_handler))
        .route("/api/admin/seal/env-slot", post(add_env_slot_handler))
        .route(
            "/api/admin/seal/drop-file-slot",
            post(drop_file_slot_handler),
        )
        .route(
            "/api/admin/seal/passphrase",
            post(add_passphrase_slot_handler),
        )
        .route("/api/admin/unseal", post(unseal_handler))
}

/// `POST /api/admin/login`
///
/// `ConnectInfo` is optional because the server is also driven directly by
/// `oneshot()` in tests, where no peer address exists.
async fn login_handler(
    State(state): State<DownloadServerState>,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(request): Json<session::AdminLoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let client = client.map(|ConnectInfo(addr)| addr.ip());
    session::login(&request, client, &state.admin)
        .await
        .map(Json)
}

/// `GET /api/admin/claim`'s sibling: what the page needs before it has a session.
///
/// Unauthenticated, and it has to be: the whole question it answers is which
/// screen to render for someone who cannot yet log in. It gives away nothing
/// `POST /api/admin/login` does not already give away through its status code —
/// whether the node is claimed, and what phase it is in — and saying so out loud
/// here is cheaper than an argument at review time.
///
/// The setup token is *not* included, only its fingerprint. An operator who has
/// the token can confirm they have the right one; an operator who does not
/// learns nothing.
async fn bootstrap_handler(State(state): State<DownloadServerState>) -> Json<Value> {
    let (unclaimed, fingerprint) = state.admin.bootstrap();
    Json(json!({
        "phase": state.runtime.phase().as_str(),
        "claimed": !unclaimed,
        "enabled": state.admin.is_enabled(),
        "setup_token_fingerprint": fingerprint,
    }))
}

/// `POST /api/admin/claim`
async fn claim_handler(
    State(state): State<DownloadServerState>,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(request): Json<session::AdminClaimRequest>,
) -> Result<Json<Value>, ApiError> {
    let client = client.map(|ConnectInfo(addr)| addr.ip());
    session::claim(&request, client, &state.admin)
        .await
        .map(Json)
}

/// `GET /api/admin/envelope`
async fn envelope_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
) -> Json<Value> {
    Json(envelope::issue(&state))
}

/// `POST /api/admin/setup/provision`
async fn provision_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<envelope::SealedRequest>,
) -> Result<Json<Value>, ApiError> {
    setup::provision(&request, &state).await.map(Json)
}

/// `GET /api/admin/seal`
async fn seal_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
) -> Json<Value> {
    Json(seal::status(&state))
}

/// `POST /api/admin/seal/env-slot`
///
/// Carries an envelope even though it sends nothing secret *up*: the key it
/// hands back is sealed to the browser, and opening the request first is what
/// proves the browser derived the same keys before the node commits a slot to
/// them.
async fn add_env_slot_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<envelope::SealedRequest>,
) -> Result<Json<Value>, ApiError> {
    seal::add_env_slot(&request, &state).await.map(Json)
}

/// `POST /api/admin/seal/drop-file-slot`
async fn drop_file_slot_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<seal::SealRequest>,
) -> Result<Json<Value>, ApiError> {
    seal::drop_file_slot(&request, &state).await.map(Json)
}

/// `POST /api/admin/seal/passphrase`
async fn add_passphrase_slot_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<envelope::SealedRequest>,
) -> Result<Json<Value>, ApiError> {
    seal::add_passphrase_slot(&request, &state).await.map(Json)
}

/// `POST /api/admin/unseal`
async fn unseal_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<envelope::SealedRequest>,
) -> Result<Json<Value>, ApiError> {
    seal::unseal(&request, &state).await.map(Json)
}

/// `GET /api/admin/status`
async fn status_handler(
    session: AdminSession,
    State(state): State<DownloadServerState>,
) -> Result<Json<Value>, ApiError> {
    status::node_status(&state, session.expires_at)
        .await
        .map(Json)
}

/// `POST /api/admin/reset-database`
async fn reset_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<reset::ResetDatabaseRequest>,
) -> Result<Json<Value>, ApiError> {
    reset::reset_database(&request, &state).await.map(Json)
}

/// `POST /api/admin/register-node`
async fn register_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<register::RegisterNodeRequest>,
) -> Result<Json<Value>, ApiError> {
    register::register_node(&request, &state).await.map(Json)
}

/// `POST /api/admin/whitelist-request`
async fn whitelist_submit_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    Json(request): Json<whitelist::SubmitWhitelistRequest>,
) -> Result<Json<Value>, ApiError> {
    whitelist::submit(&request, &state).await.map(Json)
}

/// `GET /api/admin/whitelist-request`
async fn whitelist_status_handler(
    _session: AdminSession,
    State(state): State<DownloadServerState>,
    axum::extract::Query(query): axum::extract::Query<whitelist::WhitelistStatusQuery>,
) -> Result<Json<Value>, ApiError> {
    whitelist::status(&query, &state).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_reports_whether_a_password_is_configured() {
        assert!(!AdminState::disabled().is_enabled());
        assert!(
            AdminState::with_password(AdminPassword::new(Some("correct horse battery")))
                .is_enabled()
        );
    }

    /// Two processes must not share a session key, or a token minted by one
    /// would unlock the other.
    #[test]
    fn each_state_gets_its_own_session_key() {
        let first = AdminState::disabled();
        let second = AdminState::disabled();
        assert_ne!(first.session_key(), second.session_key());
    }

    #[test]
    fn debug_output_reveals_neither_password_nor_key() {
        let state = AdminState::with_password(AdminPassword::new(Some("correct horse battery")));
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("correct horse battery"), "{rendered}");
        assert!(rendered.contains("enabled: true"), "{rendered}");
    }

    /// The identity is the one thing reachable from this state that carries a
    /// secret, and it is printed as part of the admin state — so its `Debug`
    /// has to redact for the same reason [`BlsKeyPair`]'s does.
    #[test]
    fn debug_output_names_the_registration_without_the_key() {
        use crate::testutils::tempdir;

        let dir = tempdir();
        let identity = NodeIdentity::new(
            Arc::new(BlsKeyPair::generate().unwrap()),
            PortalClient::try_new("http://portal.invalid", dir.path()).unwrap(),
            Some(RegisteredNode {
                node_id: "node-debug".to_string(),
                signer_id: 7,
            }),
            None,
        );
        let rendered = format!(
            "{:?}",
            AdminState::with_identity(identity, RestartHandle::new())
        );

        assert!(rendered.contains("node-debug"), "{rendered}");
        assert!(rendered.contains("<BlsKeyPair>"), "{rendered}");
    }

    #[tokio::test]
    async fn api_error_renders_code_and_message() {
        let response =
            ApiError::bad_request(error_codes::CONFIRMATION_REQUIRED, "nope").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], error_codes::CONFIRMATION_REQUIRED);
        assert_eq!(payload["error"]["message"], "nope");
    }

    /// The detail is the reason `server_error` exists: it goes to the log and
    /// stops there. A `DbErr` or a signing failure names internal machinery,
    /// and the page that would display it sits behind a public login screen.
    #[tokio::test]
    async fn an_internal_cause_is_logged_and_never_rendered() {
        let error = ApiError::server_error("sqlx: no such table: agreements");
        assert_eq!(error.code, error_codes::INTERNAL_ERROR);

        let body = axum::body::to_bytes(error.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            !rendered.contains("no such table"),
            "the cause must not reach the response: {rendered}"
        );
        let payload: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(payload["error"]["message"], "Internal error");
    }

    /// Same guarantee for a hand-built error that attaches a cause: only
    /// `message` is public.
    #[tokio::test]
    async fn with_detail_keeps_the_cause_out_of_the_body() {
        let error = ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::DATABASE_ERROR,
            "failed to reset database",
        )
        .with_detail("reset rolled back: no such table: challenges");

        let body = axum::body::to_bytes(error.into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["error"]["code"], error_codes::DATABASE_ERROR);
        assert_eq!(payload["error"]["message"], "failed to reset database");
        assert!(
            !String::from_utf8_lossy(&body).contains("no such table"),
            "the cause must not reach the response"
        );
    }

    /// The three logging arms of `into_response` — server error, auth denial,
    /// routine rejection — must all still produce the same body shape.
    #[tokio::test]
    async fn every_error_class_renders_the_same_shape() {
        let cases = [
            ApiError::server_error("signing failed"),
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                error_codes::UNAUTHORIZED,
                "Authentication required",
            ),
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                error_codes::ADMIN_UI_DISABLED,
                "disabled",
            ),
        ];

        for error in cases {
            let (status, code) = (error.status, error.code);
            let response = error.into_response();
            assert_eq!(response.status(), status);

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let payload: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["error"]["code"], code);
            assert!(payload["error"]["message"].is_string());
        }
    }

    /// End-to-end over the real router: the routes, the guard and the CORS
    /// boundary, as a browser on `/admin` would meet them.
    mod routes {
        use super::*;
        use crate::app::tasks::downloadagreements::StorageBackend;
        use crate::entities::prelude::Agreements;
        use crate::server::router;
        use crate::testutils::{setup_in_memory_db, tempdir, AgreementFixture};
        use axum::body::Body;
        use axum::http::{header, Request};
        use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait};
        use tower::ServiceExt;

        const PASSWORD: &str = "correct horse battery";

        async fn state_with_password(
            password: Option<&str>,
        ) -> (DownloadServerState, tempfile::TempDir) {
            let db = setup_in_memory_db().await;
            AgreementFixture {
                downloaded: true,
                ..AgreementFixture::new("AGR-1", "FILE-1")
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();

            let dir = tempdir();
            let state = DownloadServerState {
                db,
                storage_dir: dir.path().to_path_buf(),
                storage_backend: StorageBackend::local(),
                runtime: crate::app::lifecycle::NodeRuntime::for_tests(Some("NODE-admin"), None),
                admin: AdminState::with_password(AdminPassword::new(password)),
            };
            (state, dir)
        }

        async fn call(state: &DownloadServerState, request: Request<Body>) -> (StatusCode, Value) {
            let response = router(state.clone()).oneshot(request).await.unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let payload = serde_json::from_slice(&body).unwrap_or(Value::Null);
            (status, payload)
        }

        fn post(uri: &str, body: Value) -> Request<Body> {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }

        fn authorized(
            request: axum::http::request::Builder,
            token: &str,
        ) -> axum::http::request::Builder {
            request.header(header::AUTHORIZATION, format!("Bearer {token}"))
        }

        async fn sign_in(state: &DownloadServerState) -> String {
            session::reset_throttle_for_tests(None);
            let (status, payload) = call(
                state,
                post("/api/admin/login", json!({"password": PASSWORD})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{payload}");
            payload["token"].as_str().unwrap().to_string()
        }

        /// State for a node nobody has claimed, over a real application
        /// directory so the claim actually writes a credential.
        ///
        /// Every test built on this is `#[serial]`, and has to be:
        /// [`credentials::AdminCredential::load_or_bootstrap`] consults
        /// `KONTOR_SETUP_TOKEN`, which is process-global, and the tests in
        /// [`credentials`] set and clear it. A node bootstrapped while one of
        /// those holds the variable takes the token from the environment and
        /// writes no file — leaving this helper reading one that was never
        /// created, on a schedule nothing here controls.
        async fn unclaimed_state() -> (DownloadServerState, tempfile::TempDir, String) {
            let (mut state, _dir) = state_with_password(None).await;
            let app_dir = tempfile::tempdir().unwrap();

            let credential = credentials::AdminCredential::load_or_bootstrap(
                app_dir.path(),
                &AdminPassword::new(None),
            )
            .await
            .unwrap();
            let token = std::fs::read_to_string(app_dir.path().join(credentials::SETUP_TOKEN_FILE))
                .unwrap()
                .trim()
                .to_string();

            state.admin = AdminState::new(
                credential,
                app_dir.path().to_path_buf(),
                RestartHandle::new(),
                crate::app::lifecycle::NodeRuntime::for_tests(None, None),
            );
            (state, app_dir, token)
        }

        /// The bootstrap endpoint is what a browser with no session asks first,
        /// so it has to answer without one.
        #[tokio::test]
        #[serial_test::serial]
        async fn bootstrap_is_public_and_says_whether_the_node_is_claimed() {
            let (state, _app_dir, _token) = unclaimed_state().await;

            let (status, payload) = call(
                &state,
                Request::builder()
                    .uri("/api/admin/bootstrap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;

            assert_eq!(status, StatusCode::OK);
            assert_eq!(payload["claimed"], false);
            assert_eq!(payload["enabled"], false);
            // The fingerprint, never the token.
            assert!(payload["setup_token_fingerprint"].is_string());
        }

        /// Unclaimed and disabled are different answers, and the page renders a
        /// different screen for each.
        #[tokio::test]
        #[serial_test::serial]
        async fn login_on_an_unclaimed_node_says_so_rather_than_unavailable() {
            let (state, _app_dir, _token) = unclaimed_state().await;
            session::reset_throttle_for_tests(None);

            let (status, payload) = call(
                &state,
                post("/api/admin/login", json!({"password": PASSWORD})),
            )
            .await;

            assert_eq!(status, StatusCode::CONFLICT, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::ADMIN_NOT_CLAIMED);
        }

        /// The whole zero-configuration entry point: a token off the logs
        /// becomes a password and a session, in one request.
        #[tokio::test]
        #[serial_test::serial]
        async fn claiming_sets_a_password_and_signs_the_operator_in() {
            let (state, app_dir, token) = unclaimed_state().await;
            session::reset_throttle_for_tests(None);

            let (status, payload) = call(
                &state,
                post(
                    "/api/admin/claim",
                    json!({"token": token, "password": PASSWORD}),
                ),
            )
            .await;

            assert_eq!(status, StatusCode::OK, "{payload}");
            assert!(payload["token"].is_string());
            assert!(app_dir.path().join(credentials::ADMIN_FILE).exists());
            assert!(!app_dir.path().join(credentials::SETUP_TOKEN_FILE).exists());

            // And the password now works.
            session::reset_throttle_for_tests(None);
            let (status, payload) = call(
                &state,
                post("/api/admin/login", json!({"password": PASSWORD})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{payload}");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_claim_with_the_wrong_token_is_rejected_and_changes_nothing() {
            let (state, app_dir, _token) = unclaimed_state().await;
            session::reset_throttle_for_tests(None);

            let (status, payload) = call(
                &state,
                post(
                    "/api/admin/claim",
                    json!({"token": "f".repeat(64), "password": PASSWORD}),
                ),
            )
            .await;

            assert_eq!(status, StatusCode::UNAUTHORIZED, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::INVALID_SETUP_TOKEN);
            assert!(!app_dir.path().join(credentials::ADMIN_FILE).exists());
        }

        /// The password floor is checked before the token, so someone who typed
        /// a short password is told that rather than sent to re-check a token
        /// that was fine.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_claim_with_a_short_password_says_which_rule_it_broke() {
            let (state, _app_dir, token) = unclaimed_state().await;
            session::reset_throttle_for_tests(None);

            let (status, payload) = call(
                &state,
                post(
                    "/api/admin/claim",
                    json!({"token": token, "password": "short"}),
                ),
            )
            .await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::WEAK_PASSWORD);
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_claimed_node_refuses_a_second_claim() {
            let (state, _app_dir, token) = unclaimed_state().await;
            session::reset_throttle_for_tests(None);
            call(
                &state,
                post(
                    "/api/admin/claim",
                    json!({"token": token.clone(), "password": PASSWORD}),
                ),
            )
            .await;

            session::reset_throttle_for_tests(None);
            let (status, payload) = call(
                &state,
                post(
                    "/api/admin/claim",
                    json!({"token": token, "password": PASSWORD}),
                ),
            )
            .await;

            assert_eq!(status, StatusCode::CONFLICT, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::ALREADY_CLAIMED);
        }

        /// Setup is only ever available on a node with no key. A node that is
        /// merely sealed must be refused too: provisioning over a keystore
        /// nobody can currently open would replace an identity that is only
        /// temporarily out of reach.
        #[tokio::test]
        async fn setup_is_refused_on_a_node_that_already_has_a_key() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;
            let token = sign_in(&state).await;

            for phase in [
                crate::app::lifecycle::Phase::Running,
                crate::app::lifecycle::Phase::Sealed,
                crate::app::lifecycle::Phase::Unregistered,
            ] {
                state.runtime.enter(phase);

                // The phase is read before the envelope is opened, so a body
                // that would never decrypt still gets the answer that matters.
                let (status, payload) = call(
                    &state,
                    authorized(
                        Request::builder()
                            .method("POST")
                            .uri("/api/admin/setup/provision")
                            .header(header::CONTENT_TYPE, "application/json"),
                        &token,
                    )
                    .body(Body::from("{}"))
                    .unwrap(),
                )
                .await;

                assert_eq!(status, StatusCode::CONFLICT, "{phase}: {payload}");
                assert_eq!(payload["error"]["code"], error_codes::SETUP_UNAVAILABLE);
            }
        }

        /// An envelope is good for exactly one attempt. A second request must
        /// find nothing to open with, whether or not the first succeeded.
        #[tokio::test]
        async fn a_setup_envelope_is_consumed_by_the_first_attempt() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;
            state
                .runtime
                .enter(crate::app::lifecycle::Phase::Uninitialized);
            let token = sign_in(&state).await;

            let (status, envelope) = call(
                &state,
                authorized(Request::builder().uri("/api/admin/envelope"), &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{envelope}");

            let attempt = json!({
                "session_id": envelope["session_id"],
                "client_pubkey": "00",
                "nonce": "00",
                "ciphertext": "00",
            });

            // The first attempt fails on the payload, not on the envelope.
            let (status, payload) = call(
                &state,
                authorized(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/setup/provision")
                        .header(header::CONTENT_TYPE, "application/json"),
                    &token,
                )
                .body(Body::from(attempt.to_string()))
                .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::INVALID_ENVELOPE);

            // The second finds the envelope already spent.
            let (status, payload) = call(
                &state,
                authorized(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/setup/provision")
                        .header(header::CONTENT_TYPE, "application/json"),
                    &token,
                )
                .body(Body::from(attempt.to_string()))
                .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
            assert_eq!(payload["error"]["code"], error_codes::INVALID_ENVELOPE);
        }

        /// Every setup and seal route is behind a session. The one exception is
        /// `bootstrap`, which is covered above and has to be public.
        #[tokio::test]
        async fn the_setup_and_seal_routes_require_a_session() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;

            for (method, uri) in [
                ("GET", "/api/admin/envelope"),
                ("POST", "/api/admin/setup/provision"),
                ("GET", "/api/admin/seal"),
                ("POST", "/api/admin/seal/env-slot"),
                ("POST", "/api/admin/seal/drop-file-slot"),
                ("POST", "/api/admin/seal/passphrase"),
                ("POST", "/api/admin/unseal"),
                // The whitelist pair reaches the Portal with a body the node
                // signs, so like registration it sits behind the session even
                // though the Portal end takes no credential.
                ("GET", "/api/admin/whitelist-request"),
                ("POST", "/api/admin/whitelist-request"),
            ] {
                let (status, payload) = call(
                    &state,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await;

                assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {payload}");
            }
        }

        /// The page is the login screen, so gating it would make the node
        /// unadministrable. Both spellings of the path resolve.
        #[tokio::test]
        async fn admin_page_is_public_html() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;

            for uri in ["/admin", "/admin/"] {
                let response = router(state.clone())
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{uri}");
                assert_eq!(
                    response.headers().get(header::CONTENT_TYPE).unwrap(),
                    "text/html; charset=utf-8"
                );
            }
        }

        #[tokio::test]
        async fn status_and_reset_require_a_session() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;

            let (status, payload) = call(
                &state,
                Request::builder()
                    .uri("/api/admin/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(payload["error"]["code"], error_codes::UNAUTHORIZED);

            let (status, _) = call(
                &state,
                post("/api/admin/reset-database", json!({"confirm": "RESET"})),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                Agreements::find().count(&state.db).await.unwrap(),
                1,
                "an unauthenticated reset must not delete anything"
            );
        }

        /// The registration route reaches the Portal with a body the node
        /// signs, so an unauthenticated caller must not get that far — the
        /// Portal itself takes the request without any credential.
        #[tokio::test]
        async fn registering_requires_a_session() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;

            let (status, payload) = call(
                &state,
                post("/api/admin/register-node", json!({"xpubkey": "x"})),
            )
            .await;

            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(payload["error"]["code"], error_codes::UNAUTHORIZED);
        }

        /// A token signed by some other key is not a session, however
        /// well-formed it looks.
        #[tokio::test]
        async fn a_foreign_token_is_not_a_session() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;
            let (other, _other_dir) = state_with_password(Some(PASSWORD)).await;
            let token = sign_in(&other).await;

            let (status, _) = call(
                &state,
                authorized(Request::builder().uri("/api/admin/status"), &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn signing_in_opens_status_and_reset() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;
            let token = sign_in(&state).await;

            let (status, payload) = call(
                &state,
                authorized(Request::builder().uri("/api/admin/status"), &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(payload["node_id"], "NODE-admin");
            assert_eq!(payload["agreements"]["total"], 1);

            let request = authorized(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/reset-database")
                    .header(header::CONTENT_TYPE, "application/json"),
                &token,
            )
            .body(Body::from(json!({"confirm": "RESET"}).to_string()))
            .unwrap();

            let (status, payload) = call(&state, request).await;
            assert_eq!(status, StatusCode::OK, "{payload}");
            assert_eq!(payload["total_rows_deleted"], 1);
            assert_eq!(Agreements::find().count(&state.db).await.unwrap(), 0);
        }

        /// Without a password there is nothing to sign in to, and saying so is
        /// more useful than a 401 the operator cannot act on.
        #[tokio::test]
        async fn a_node_without_a_password_answers_service_unavailable() {
            let (state, _dir) = state_with_password(None).await;

            let (status, payload) = call(
                &state,
                post("/api/admin/login", json!({"password": PASSWORD})),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(payload["error"]["code"], error_codes::ADMIN_UI_DISABLED);

            let (status, _) = call(
                &state,
                Request::builder()
                    .uri("/api/admin/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }

        /// The public API is `Allow-Origin: *`; the admin API must not be, or a
        /// page on any origin could read a session's responses.
        #[tokio::test]
        async fn admin_routes_are_outside_the_permissive_cors_layer() {
            let (state, _dir) = state_with_password(Some(PASSWORD)).await;

            let public = router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri("/api/info")
                        .header(header::ORIGIN, "https://elsewhere.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(public
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));

            let admin = router(state)
                .oneshot(
                    Request::builder()
                        .uri("/admin")
                        .header(header::ORIGIN, "https://elsewhere.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!admin
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        }
    }
}
