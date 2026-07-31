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

/// Ceiling on the escalating delay [`claim`] uses in place of a lockout. High
/// enough to make grinding pointless, low enough that a few of them cannot pin
/// connections open indefinitely.
const MAX_CLAIM_DELAY: Duration = Duration::from_secs(2);

/// Upper bound on tracked client buckets, so an attacker rotating source
/// addresses cannot grow the map without limit.
const THROTTLE_MAX_ENTRIES: usize = 4096;

/// Which door a failed attempt was against.
///
/// The two are counted separately, and that is not tidiness. They fail in
/// opposite directions: exhausting the login budget must lock the door, because
/// a password can be weak; exhausting the claim budget must **not**, because on
/// an unclaimed node `/admin` is the only way to configure the node at all and a
/// lockout there is an attacker deciding the node never comes up. Sharing one
/// counter would let failures against either close both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Gate {
    Login,
    Claim,
}

/// Failed-attempt count and the instant the current window opened.
type Attempts = (u32, Instant);

/// One counter per gate per client. `None` is every client behind a proxy.
type Bucket = (Gate, Option<IpAddr>);

/// The whole throttle.
type Counters = Mutex<HashMap<Bucket, Attempts>>;

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

/// Failed-attempt counters keyed by gate and client IP.
///
/// `None` (no `ConnectInfo`, which is the case under `oneshot()` in tests, and
/// for any deployment that terminates connections in a proxy) collapses into a
/// single shared bucket rather than bypassing the throttle.
fn attempt_counters() -> &'static Counters {
    static THROTTLE: OnceLock<Counters> = OnceLock::new();
    THROTTLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many failures this client has against this gate inside the current
/// window. Expired windows reset the counter in place.
fn failures(gate: Gate, client: Option<IpAddr>) -> u32 {
    let Ok(mut throttle) = attempt_counters().lock() else {
        // A poisoned mutex must not turn into an open door, but it also must
        // not lock the operator out permanently: report no failures and rely on
        // the constant-time comparison plus the delay below.
        return 0;
    };
    match throttle.get(&(gate, client)) {
        Some((attempts, first_seen)) if first_seen.elapsed() < THROTTLE_WINDOW => *attempts,
        Some(_) => {
            throttle.remove(&(gate, client));
            0
        }
        None => 0,
    }
}

fn record_failure(gate: Gate, client: Option<IpAddr>) {
    let Ok(mut throttle) = attempt_counters().lock() else {
        return;
    };

    let key = (gate, client);

    // Evict the oldest quarter once the cap is reached.
    if throttle.len() >= THROTTLE_MAX_ENTRIES && !throttle.contains_key(&key) {
        let mut entries: Vec<(Bucket, Instant)> = throttle
            .iter()
            .map(|(key, (_, first_seen))| (*key, *first_seen))
            .collect();
        entries.sort_by_key(|(_, first_seen)| *first_seen);
        for (key, _) in entries.into_iter().take(THROTTLE_MAX_ENTRIES / 4) {
            throttle.remove(&key);
        }
    }

    let entry = throttle.entry(key).or_insert_with(|| (0, Instant::now()));
    if entry.1.elapsed() >= THROTTLE_WINDOW {
        *entry = (0, Instant::now());
    }
    entry.0 = entry.0.saturating_add(1);
}

fn clear_failures(gate: Gate, client: Option<IpAddr>) {
    if let Ok(mut throttle) = attempt_counters().lock() {
        throttle.remove(&(gate, client));
    }
}

/// The penalty a rejected claim pays, doubling with each failure up to
/// [`MAX_CLAIM_DELAY`].
///
/// A delay rather than the lockout [`login`] uses, because the two gates protect
/// different things. A setup token is 32 bytes of entropy, or — when supplied
/// through `KONTOR_SETUP_TOKEN` — at least 32 characters, so grinding one is not
/// a threat a lockout is needed for. What *is* a threat is anyone who can reach
/// an unclaimed node spending ten guesses to keep its operator from ever
/// claiming it, on the only endpoint that can configure the node.
fn claim_penalty(failures: u32) -> Duration {
    FAILED_ATTEMPT_DELAY
        .saturating_mul(1u32 << failures.min(3))
        .min(MAX_CLAIM_DELAY)
}

/// Drops the failed-attempt counters for a single client. Test-only.
///
/// Scoped to one client on purpose. The throttle is a process-global static and
/// `cargo test` runs cases in parallel in one process, so clearing the whole
/// map would be a race rather than isolation: it would wipe the counter another
/// test is still accumulating. Tests isolate by using distinct client
/// addresses; this only clears what a previous run of *this* case left behind.
#[cfg(test)]
pub(crate) fn reset_throttle_for_tests(client: Option<IpAddr>) {
    if let Ok(mut throttle) = attempt_counters().lock() {
        throttle.remove(&(Gate::Login, client));
        throttle.remove(&(Gate::Claim, client));
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

    if failures(Gate::Login, client) >= MAX_ATTEMPTS {
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

    if !verify_password(admin, &request.password).await {
        record_failure(Gate::Login, client);
        tokio::time::sleep(FAILED_ATTEMPT_DELAY).await;
        warn!(?client, "Rejected admin login attempt");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::INVALID_PASSWORD,
            "Invalid password",
        ));
    }

    clear_failures(Gate::Login, client);
    issue_session(client, admin)
}

/// Check a password without parking a `tokio` worker on Argon2.
///
/// A stored credential is verified with Argon2id at
/// [`crate::crypto::aead::Kdf::LOGIN`] — 19 MiB and two passes, by design, since
/// the whole value of the hash is that it is slow. Doing that inline blocks one
/// executor thread for tens of milliseconds per attempt and, with a handful of
/// clients each spending their budget, blocks all of them. It is CPU-bound work
/// of exactly the shape `spawn_blocking` exists for.
///
/// A join failure answers "no", which is the direction a panicking hasher should
/// fail in.
async fn verify_password(admin: &AdminState, password: &str) -> bool {
    let admin = admin.clone();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || admin.verify_password(&password))
        .await
        .unwrap_or(false)
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
/// Repeated failures cost an escalating delay rather than a lockout — see
/// [`claim_penalty`] for why this gate must never close.
///
/// # Errors
/// - `503 ADMIN_UI_DISABLED` when the UI is turned off outright.
/// - `409 ALREADY_CLAIMED` when a password is already set.
/// - `400 WEAK_PASSWORD` when the chosen password is too short.
/// - `401 INVALID_SETUP_TOKEN` when the token does not match.
pub async fn claim(
    request: &AdminClaimRequest,
    client: Option<IpAddr>,
    admin: &AdminState,
) -> Result<Value, ApiError> {
    if admin.is_disabled() {
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

    if let Err(e) = claim_blocking(admin, &request.token, &request.password).await {
        let failures = failures(Gate::Claim, client);
        record_failure(Gate::Claim, client);
        tokio::time::sleep(claim_penalty(failures)).await;
        warn!(?client, error = %format!("{e:#}"), "Rejected admin claim");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::INVALID_SETUP_TOKEN,
            "That setup token is not this node's.",
        ));
    }

    clear_failures(Gate::Claim, client);
    info!(?client, "Node claimed; admin password set");
    issue_session(client, admin)
}

/// Trade the token for a password off the executor.
///
/// Hashing the new password is the same Argon2id cost [`verify_password`]
/// avoids running inline, and this one also writes `admin.json` and fsyncs it.
async fn claim_blocking(
    admin: &AdminState,
    token: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let admin = admin.clone();
    let token = token.to_string();
    let password = password.to_string();

    tokio::task::spawn_blocking(move || admin.claim(&token, &password))
        .await
        .map_err(|e| anyhow::anyhow!("the claim task failed: {e}"))?
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

    /// The two gates must not share a counter. An attacker who cannot reach a
    /// node's password can still reach its claim form, and burning that budget
    /// must not be a way to lock the operator out of logging in — nor the
    /// reverse.
    #[tokio::test]
    async fn a_spent_claim_budget_does_not_close_the_login_door() {
        reset_throttle_for_tests(client(20));
        let state = enabled_state();
        let attacker = client(20);

        for _ in 0..(MAX_ATTEMPTS * 2) {
            record_failure(Gate::Claim, attacker);
        }

        assert!(
            failures(Gate::Login, attacker) < MAX_ATTEMPTS,
            "claim failures must not count against login"
        );
        login(&request(PASSWORD), attacker, &state)
            .await
            .expect("the login gate is untouched by claim failures");

        // And the reverse: a locked-out login leaves the claim gate open.
        reset_throttle_for_tests(client(21));
        for _ in 0..(MAX_ATTEMPTS * 2) {
            record_failure(Gate::Login, client(21));
        }
        assert_eq!(failures(Gate::Claim, client(21)), 0);
    }

    /// The claim gate must never hand an attacker a way to stop a node being
    /// configured at all. Guesses cost an escalating delay, capped, and the
    /// answer stays "wrong token" rather than becoming "come back later".
    #[test]
    fn the_claim_penalty_escalates_but_never_locks_out() {
        assert_eq!(claim_penalty(0), FAILED_ATTEMPT_DELAY);
        assert!(claim_penalty(1) > claim_penalty(0));
        assert!(claim_penalty(3) > claim_penalty(1));

        // Bounded, so a handful of them cannot pin connections open.
        assert_eq!(claim_penalty(3), MAX_CLAIM_DELAY);
        assert_eq!(claim_penalty(u32::MAX), MAX_CLAIM_DELAY);
    }

    /// Failures beyond the login budget still answer 401 on the claim gate, not
    /// 429: the operator with the right token must always get in.
    ///
    /// The counter is filled directly rather than by making the guesses. Each
    /// rejection sleeps for its penalty by design, and paying fifteen of them
    /// would buy this case nothing the arithmetic above does not already pin.
    #[tokio::test]
    async fn a_ground_down_claim_gate_still_accepts_the_right_token() {
        use crate::server::admin::credentials::AdminCredential;
        use crate::testutils::tempdir;

        let dir = tempdir();
        let attacker = client(22);
        reset_throttle_for_tests(attacker);

        let credential = AdminCredential::load_or_bootstrap(dir.path(), &AdminPassword::new(None))
            .await
            .unwrap();
        let token = credential
            .startup_notice()
            .and_then(|notice| {
                notice
                    .split_whitespace()
                    .find(|word| word.len() == 64 && word.chars().all(|c| c.is_ascii_hexdigit()))
                    .map(str::to_string)
            })
            .expect("a generated token is printed in full");

        let state = AdminState::new(
            credential,
            dir.path().to_path_buf(),
            crate::app::restart::RestartHandle::unavailable(),
            crate::app::lifecycle::NodeRuntime::for_tests(None, None),
        );

        for _ in 0..(MAX_ATTEMPTS + 5) {
            record_failure(Gate::Claim, attacker);
        }
        assert!(failures(Gate::Claim, attacker) > MAX_ATTEMPTS);

        // Well past what would lock the login gate, and the answer is still
        // "wrong token" rather than "come back later".
        let err = claim(
            &AdminClaimRequest {
                token: "an entirely wrong token that is long enough".to_string(),
                password: PASSWORD.to_string(),
            },
            attacker,
            &state,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code,
            error_codes::INVALID_SETUP_TOKEN,
            "the claim gate must never close"
        );

        let value = claim(
            &AdminClaimRequest {
                token,
                password: PASSWORD.to_string(),
            },
            attacker,
            &state,
        )
        .await
        .expect("the right token still claims the node");
        assert!(value["token"].as_str().is_some());
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
