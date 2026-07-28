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
//! - `ADMIN_PASSWORD` is exchanged at `POST /api/admin/login` for a session
//!   token that expires after 8 hours. Leaving the variable unset disables the
//!   UI entirely (login answers 503), which is the default.
//! - The token is signed with a key generated at startup and never persisted,
//!   so sessions do not survive a restart and there is no long-lived secret on
//!   disk to leak. It is held in `sessionStorage` and sent as a bearer — no
//!   cookie, so no CSRF surface.
//! - Failed attempts are counted per peer IP (10 per 15 minutes) and every
//!   rejection costs a fixed 250 ms. `X-Forwarded-For` is deliberately not
//!   trusted: behind a proxy all clients collapse into one bucket, which fails
//!   closed, whereas a spoofable header would hand an attacker unlimited
//!   buckets.
//! - The admin routes are merged *after* the permissive `CorsLayer`, so they
//!   carry no `Access-Control-Allow-Origin` and a browser refuses to let
//!   another origin read their responses.

pub mod reset;
pub mod session;
pub mod status;
pub mod ui;

use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tracing::{debug, error, info};

use crate::app::config::AdminPassword;
use crate::app::restart::RestartHandle;
use crate::server::state::DownloadServerState;
use session::AdminSession;

/// Credentials and session-signing material for the operator UI.
///
/// Cloned into every request via [`DownloadServerState`], hence the `Arc`.
#[derive(Clone)]
pub struct AdminState {
    inner: Arc<Inner>,
}

struct Inner {
    /// Empty means "no admin UI".
    password: AdminPassword,
    /// HMAC key for session tokens. Generated per process and never written
    /// anywhere: a node runs as a single process, so there is nothing to share
    /// a persisted secret with, and an ephemeral key means a leaked token dies
    /// with the next restart.
    session_key: [u8; 32],
    /// Lets a reset ask the run loop to exit so the supervisor restarts the
    /// node. It lives behind the admin gate because the operator UI is the only
    /// thing that ever asks.
    restart: RestartHandle,
}

impl AdminState {
    /// Builds the admin state, generating a fresh session-signing key.
    #[must_use]
    pub fn new(password: AdminPassword, restart: RestartHandle) -> Self {
        use rand::RngCore;

        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);
        Self {
            inner: Arc::new(Inner {
                password,
                session_key,
                restart,
            }),
        }
    }

    /// The admin UI turned off: `/admin` still renders, but nothing behind it
    /// can be unlocked. Production builds this from the configured password;
    /// only tests need to ask for the disabled state directly.
    #[cfg(test)]
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(AdminPassword::new(None), RestartHandle::unavailable())
    }

    /// Test-only: no password, but a live restart switch, for the reset paths
    /// that assert on it.
    #[cfg(test)]
    #[must_use]
    pub fn with_restart(restart: RestartHandle) -> Self {
        Self::new(AdminPassword::new(None), restart)
    }

    /// Test-only: an unlockable UI on a node that refuses restarts, for the
    /// session and routing tests that only care about the password.
    #[cfg(test)]
    #[must_use]
    pub fn with_password(password: AdminPassword) -> Self {
        Self::new(password, RestartHandle::unavailable())
    }

    /// True when a password is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.inner.password.is_empty()
    }

    /// The process-restart switch. See [`RestartHandle`].
    pub(crate) fn restart(&self) -> &RestartHandle {
        &self.inner.restart
    }

    fn password(&self) -> &AdminPassword {
        &self.inner.password
    }

    fn session_key(&self) -> &[u8; 32] {
        &self.inner.session_key
    }
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("enabled", &self.is_enabled())
            .finish_non_exhaustive()
    }
}

/// Machine-readable error codes returned by the admin API.
///
/// The page keys its behaviour off these rather than off message text.
pub mod error_codes {
    /// `ADMIN_PASSWORD` is unset, so the admin UI is turned off.
    pub const ADMIN_UI_DISABLED: &str = "ADMIN_UI_DISABLED";
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
    /// A database read or write failed.
    pub const DATABASE_ERROR: &str = "DATABASE_ERROR";
    /// The session could not be issued (signing failure).
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
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
        .route("/api/admin/login", post(login_handler))
        .route("/api/admin/status", get(status_handler))
        .route("/api/admin/reset-database", post(reset_handler))
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
                node_id: "NODE-admin".to_string(),
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
