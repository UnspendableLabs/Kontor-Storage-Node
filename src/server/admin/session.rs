//! `POST /api/admin/login` — password → short-lived admin session.
//!
//! The session is a JWT signed with the per-process key held in
//! [`AdminState`]. Nothing about it is persisted: restarting the node ends
//! every session, which is the correct trade for a credential a browser holds.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::server::admin::{error_codes, AdminState, ApiError};
use crate::server::state::DownloadServerState;

/// How long an admin session stays valid. Long enough for a maintenance
/// window, short enough that a forgotten browser tab is not a standing key.
pub const ADMIN_SESSION_EXPIRY_SECS: i64 = 8 * 3600;

/// Failed logins allowed per client inside [`THROTTLE_WINDOW`].
const MAX_ATTEMPTS: u32 = 10;

/// Window over which failures accumulate.
const THROTTLE_WINDOW: Duration = Duration::from_secs(900);

/// Artificial delay applied to every rejected attempt. Caps the online guessing
/// rate without being noticeable to a human typing their password correctly.
const FAILED_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Upper bound on tracked client buckets, so an attacker rotating source
/// addresses cannot grow the map without limit.
const THROTTLE_MAX_ENTRIES: usize = 4096;

/// Failed-attempt count and the instant the current window opened.
type Attempts = (u32, Instant);

/// Request body for `POST /api/admin/login`.
#[derive(Debug, Deserialize)]
pub struct AdminLoginRequest {
    pub password: String,
}

/// Claims carried by an admin session token.
#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    sub: String,
    role: String,
    exp: i64,
}

/// An authenticated admin session, extracted from the `Authorization` header.
#[derive(Debug)]
pub struct AdminSession {
    /// Unix timestamp at which this session stops being accepted.
    pub expires_at: i64,
}

/// Failed-attempt counters keyed by client IP.
///
/// `None` (no `ConnectInfo`, which is the case under `oneshot()` in tests, and
/// for any deployment that terminates connections in a proxy) collapses into a
/// single shared bucket rather than bypassing the throttle.
fn login_throttle() -> &'static Mutex<HashMap<Option<IpAddr>, Attempts>> {
    static THROTTLE: OnceLock<Mutex<HashMap<Option<IpAddr>, Attempts>>> = OnceLock::new();
    THROTTLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `true` when this client has burned through its attempt budget
/// inside the current window. Expired windows reset the counter in place.
fn is_throttled(client: Option<IpAddr>) -> bool {
    let Ok(mut throttle) = login_throttle().lock() else {
        // A poisoned mutex must not turn into an open door, but it also must
        // not lock the operator out permanently: fail open here and rely on the
        // constant-time comparison plus the delay below.
        return false;
    };
    match throttle.get(&client) {
        Some((attempts, first_seen)) if first_seen.elapsed() < THROTTLE_WINDOW => {
            *attempts >= MAX_ATTEMPTS
        }
        Some(_) => {
            throttle.remove(&client);
            false
        }
        None => false,
    }
}

fn record_failure(client: Option<IpAddr>) {
    let Ok(mut throttle) = login_throttle().lock() else {
        return;
    };

    // Evict the oldest quarter once the cap is reached.
    if throttle.len() >= THROTTLE_MAX_ENTRIES && !throttle.contains_key(&client) {
        let mut entries: Vec<(Option<IpAddr>, Instant)> = throttle
            .iter()
            .map(|(key, (_, first_seen))| (*key, *first_seen))
            .collect();
        entries.sort_by_key(|(_, first_seen)| *first_seen);
        for (key, _) in entries.into_iter().take(THROTTLE_MAX_ENTRIES / 4) {
            throttle.remove(&key);
        }
    }

    let entry = throttle
        .entry(client)
        .or_insert_with(|| (0, Instant::now()));
    if entry.1.elapsed() >= THROTTLE_WINDOW {
        *entry = (0, Instant::now());
    }
    entry.0 = entry.0.saturating_add(1);
}

fn clear_failures(client: Option<IpAddr>) {
    if let Ok(mut throttle) = login_throttle().lock() {
        throttle.remove(&client);
    }
}

/// Drops the failed-attempt counter for a single client. Test-only.
///
/// Scoped to one key on purpose. The throttle is a process-global static and
/// `cargo test` runs cases in parallel in one process, so clearing the whole
/// map would be a race rather than isolation: it would wipe the counter another
/// test is still accumulating. Tests isolate by using distinct client
/// addresses; this only clears what a previous run of *this* case left behind.
#[cfg(test)]
pub(crate) fn reset_throttle_for_tests(client: Option<IpAddr>) {
    if let Ok(mut throttle) = login_throttle().lock() {
        throttle.remove(&client);
    }
}

/// Verifies the password and issues a session token.
///
/// # Errors
/// - `503 ADMIN_UI_DISABLED` when the UI is turned off outright.
/// - `409 ADMIN_NOT_CLAIMED` when nobody has set a password yet.
/// - `429 TOO_MANY_ATTEMPTS` once the per-client failure budget is exhausted.
/// - `401 INVALID_PASSWORD` on mismatch.
/// - `500` when the token cannot be signed.
pub async fn login(
    request: &AdminLoginRequest,
    client: Option<IpAddr>,
    admin: &AdminState,
) -> Result<Value, ApiError> {
    // Unclaimed and disabled are different answers on purpose. The page has to
    // tell "nobody has set this node up yet, here is the token field" from "the
    // operator turned the UI off", and a single 503 for both would send someone
    // hunting for a variable they never set.
    if admin.is_unclaimed() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::ADMIN_NOT_CLAIMED,
            "This node has not been claimed yet. Enter its setup token to choose an admin \
             password.",
        ));
    }
    if !admin.is_enabled() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error_codes::ADMIN_UI_DISABLED,
            "The admin UI is disabled on this node.",
        ));
    }

    if is_throttled(client) {
        warn!(
            ?client,
            "Admin login throttled after {MAX_ATTEMPTS} failed attempts"
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            error_codes::TOO_MANY_ATTEMPTS,
            "Too many failed login attempts. Try again later.",
        ));
    }

    if !admin.verify_password(&request.password) {
        record_failure(client);
        tokio::time::sleep(FAILED_ATTEMPT_DELAY).await;
        warn!(?client, "Rejected admin login attempt");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::INVALID_PASSWORD,
            "Invalid password",
        ));
    }

    clear_failures(client);
    issue_session(client, admin)
}

/// Request body for `POST /api/admin/claim`.
#[derive(Debug, Deserialize)]
pub struct AdminClaimRequest {
    pub token: String,
    pub password: String,
}

/// Trade a setup token for an admin password, and hand back a session.
///
/// Behind the same throttle as [`login`], for the same reason: it is the other
/// endpoint on this node where guessing a secret gets you in, and an unclaimed
/// node is the one with no password to fall back on.
///
/// Signing the operator straight in is deliberate. They have just proved they
/// hold the token and chosen the password; making them type it again buys
/// nothing and is one more chance to get locked out of a node they have
/// configured but not yet finished setting up.
///
/// # Errors
/// - `503 ADMIN_UI_DISABLED` when the UI is turned off outright.
/// - `409 ALREADY_CLAIMED` when a password is already set.
/// - `429 TOO_MANY_ATTEMPTS` once the per-client failure budget is exhausted.
/// - `400 WEAK_PASSWORD` when the chosen password is too short.
/// - `401 INVALID_SETUP_TOKEN` when the token does not match.
pub async fn claim(
    request: &AdminClaimRequest,
    client: Option<IpAddr>,
    admin: &AdminState,
) -> Result<Value, ApiError> {
    if matches!(admin.bootstrap(), (false, _)) && !admin.is_enabled() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            error_codes::ADMIN_UI_DISABLED,
            "The admin UI is disabled on this node.",
        ));
    }
    if !admin.is_unclaimed() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::ALREADY_CLAIMED,
            "This node already has an admin password. Sign in with it, or set \
             ADMIN_PASSWORD to override it.",
        ));
    }

    if is_throttled(client) {
        warn!(
            ?client,
            "Admin claim throttled after {MAX_ATTEMPTS} failed attempts"
        );
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            error_codes::TOO_MANY_ATTEMPTS,
            "Too many failed attempts. Try again later.",
        ));
    }

    // The password floor is checked before the token so an operator who typed a
    // short password is told that, rather than being sent away to re-check a
    // token that was fine. It leaks nothing: the length rule is documented.
    if request.password.chars().count() < crate::app::config::MIN_ADMIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(
            error_codes::WEAK_PASSWORD,
            format!(
                "The admin password must be at least {} characters.",
                crate::app::config::MIN_ADMIN_PASSWORD_LEN
            ),
        ));
    }

    if let Err(e) = admin.claim(&request.token, &request.password) {
        record_failure(client);
        tokio::time::sleep(FAILED_ATTEMPT_DELAY).await;
        warn!(?client, error = %format!("{e:#}"), "Rejected admin claim");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::INVALID_SETUP_TOKEN,
            "That setup token is not this node's.",
        ));
    }

    clear_failures(client);
    info!(?client, "Node claimed; admin password set");
    issue_session(client, admin)
}

/// Mint a session token for a caller that has just authenticated.
fn issue_session(client: Option<IpAddr>, admin: &AdminState) -> Result<Value, ApiError> {
    let expires_at = chrono::Utc::now().timestamp() + ADMIN_SESSION_EXPIRY_SECS;
    let claims = SessionClaims {
        sub: "admin".to_string(),
        role: "admin".to_string(),
        exp: expires_at,
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(admin.session_key()),
    )
    .map_err(|err| ApiError::server_error(format!("failed to issue admin session: {err}")))?;

    info!(?client, "Admin session issued");

    Ok(json!({
        "token": token,
        "expires_at": expires_at,
        "expires_in": ADMIN_SESSION_EXPIRY_SECS,
    }))
}

/// Verifies a bearer token against the process session key.
fn verify(token: &str, admin: &AdminState) -> Result<AdminSession, ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp"]);

    let decoded = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(admin.session_key()),
        &validation,
    )
    .map_err(|err| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::UNAUTHORIZED,
            format!("Invalid or expired session: {err}"),
        )
    })?;

    if decoded.claims.role != "admin" {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::UNAUTHORIZED,
            "Invalid session",
        ));
    }

    Ok(AdminSession {
        expires_at: decoded.claims.exp,
    })
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

#[async_trait]
impl<S> FromRequestParts<S> for AdminSession
where
    S: Send + Sync,
    DownloadServerState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let admin = DownloadServerState::from_ref(state).admin;

        // A disabled UI has no valid sessions at all. Saying so plainly beats a
        // 401 that sends the operator hunting for a password that was never
        // configured.
        if !admin.is_enabled() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                error_codes::ADMIN_UI_DISABLED,
                "The admin UI is disabled. Set ADMIN_PASSWORD to enable it.",
            ));
        }

        let token = bearer_token(parts).ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                error_codes::UNAUTHORIZED,
                "Authentication required",
            )
        })?;

        verify(token, &admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::AdminPassword;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery";

    fn enabled_state() -> AdminState {
        AdminState::with_password(AdminPassword::new(Some(PASSWORD)))
    }

    /// The `Option` is deliberate: it mirrors the `Option<IpAddr>` `login`
    /// itself takes, so call sites read `client(6)` instead of `Some(client(6))`.
    fn client(last_octet: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn request(password: &str) -> AdminLoginRequest {
        AdminLoginRequest {
            password: password.to_string(),
        }
    }

    #[tokio::test]
    async fn login_rejected_when_password_not_configured() {
        reset_throttle_for_tests(client(1));
        let err = login(&request("whatever"), client(1), &AdminState::disabled())
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.code, error_codes::ADMIN_UI_DISABLED);
    }

    #[tokio::test]
    async fn login_issues_a_session_the_verifier_accepts() {
        reset_throttle_for_tests(client(2));
        let state = enabled_state();

        let value = login(&request(PASSWORD), client(2), &state).await.unwrap();

        let token = value["token"].as_str().expect("token in response");
        let session = verify(token, &state).expect("token verifies");
        assert_eq!(value["expires_in"], ADMIN_SESSION_EXPIRY_SECS);
        assert_eq!(session.expires_at, value["expires_at"].as_i64().unwrap());
        assert!(session.expires_at > chrono::Utc::now().timestamp());
    }

    /// A token from one process must not unlock another: the key is generated
    /// per [`AdminState`], so restarting the node invalidates every session.
    #[tokio::test]
    async fn session_from_another_state_is_rejected() {
        reset_throttle_for_tests(client(3));
        let issuer = enabled_state();
        let value = login(&request(PASSWORD), client(3), &issuer).await.unwrap();
        let token = value["token"].as_str().unwrap();

        let other = enabled_state();
        let err = verify(token, &other).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn expired_and_malformed_sessions_are_rejected() {
        let state = enabled_state();

        let expired = encode(
            &Header::new(Algorithm::HS256),
            &SessionClaims {
                sub: "admin".to_string(),
                role: "admin".to_string(),
                // Beyond the 60 s leeway `Validation` allows by default.
                exp: chrono::Utc::now().timestamp() - 3600,
            },
            &EncodingKey::from_secret(state.session_key()),
        )
        .unwrap();
        assert_eq!(
            verify(&expired, &state).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );

        assert!(verify("not-a-token", &state).is_err());
    }

    /// A well-signed token that never went through the login path (some other
    /// role) must not be treated as an admin session.
    #[test]
    fn session_with_a_non_admin_role_is_rejected() {
        let state = enabled_state();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &SessionClaims {
                sub: "admin".to_string(),
                role: "node".to_string(),
                exp: chrono::Utc::now().timestamp() + 600,
            },
            &EncodingKey::from_secret(state.session_key()),
        )
        .unwrap();

        assert_eq!(
            verify(&token, &state).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        reset_throttle_for_tests(client(4));
        let err = login(&request("wrong"), client(4), &enabled_state())
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, error_codes::INVALID_PASSWORD);
    }

    /// A same-length wrong password takes the `ct_eq` path rather than the
    /// length short-circuit; it must be rejected just the same.
    #[tokio::test]
    async fn login_rejects_same_length_wrong_password() {
        reset_throttle_for_tests(client(5));
        let state = AdminState::with_password(AdminPassword::new(Some("abcdefghijklmnop")));

        let err = login(&request("ponmlkjihgfedcba"), client(5), &state)
            .await
            .unwrap_err();

        assert_eq!(err.code, error_codes::INVALID_PASSWORD);
    }

    #[tokio::test]
    async fn login_throttles_after_max_attempts() {
        reset_throttle_for_tests(client(6));
        let state = enabled_state();
        let attacker = client(6);

        for _ in 0..MAX_ATTEMPTS {
            let err = login(&request("nope"), attacker, &state).await.unwrap_err();
            assert_eq!(err.code, error_codes::INVALID_PASSWORD);
        }

        let err = login(&request("nope"), attacker, &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.code, error_codes::TOO_MANY_ATTEMPTS);

        // Even the *correct* password is refused while throttled — otherwise
        // the budget would only slow down an attacker who already lost.
        let err = login(&request(PASSWORD), attacker, &state)
            .await
            .unwrap_err();
        assert_eq!(err.code, error_codes::TOO_MANY_ATTEMPTS);
    }

    /// The throttle is per client, so one attacker must not lock out the
    /// operator coming from a different address.
    #[tokio::test]
    async fn login_throttle_is_per_client() {
        reset_throttle_for_tests(client(7));
        reset_throttle_for_tests(client(8));
        let state = enabled_state();

        for _ in 0..MAX_ATTEMPTS {
            let _ = login(&request("nope"), client(7), &state).await;
        }

        let value = login(&request(PASSWORD), client(8), &state)
            .await
            .expect("a different client is unaffected");
        assert!(value["token"].as_str().is_some());
    }

    /// A few typos followed by the right password must not leave the budget
    /// half-spent.
    #[tokio::test]
    async fn successful_login_resets_failure_count() {
        reset_throttle_for_tests(client(9));
        let state = enabled_state();
        let operator = client(9);

        for _ in 0..(MAX_ATTEMPTS - 1) {
            let _ = login(&request("typo"), operator, &state).await;
        }
        login(&request(PASSWORD), operator, &state)
            .await
            .expect("correct password still accepted");

        for _ in 0..(MAX_ATTEMPTS - 1) {
            let err = login(&request("typo"), operator, &state).await.unwrap_err();
            assert_eq!(err.code, error_codes::INVALID_PASSWORD);
        }
    }

    #[test]
    fn bearer_token_reads_only_well_formed_headers() {
        let build = |value: &str| {
            let mut request = axum::http::Request::builder();
            if !value.is_empty() {
                request = request.header(header::AUTHORIZATION, value);
            }
            let (parts, ()) = request.body(()).unwrap().into_parts();
            parts
        };

        assert_eq!(bearer_token(&build("Bearer abc")), Some("abc"));
        assert_eq!(bearer_token(&build("Bearer  abc ")), Some("abc"));
        assert_eq!(bearer_token(&build("Basic abc")), None);
        assert_eq!(bearer_token(&build("Bearer ")), None);
        assert_eq!(bearer_token(&build("")), None);
    }
}
