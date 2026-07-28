//! `GET /admin` — serves the single-page operator UI.
//!
//! The page is embedded with `include_str!`, so the node keeps shipping as one
//! binary with no build step and no runtime dependency on an asset directory —
//! unlike the public dashboard, which pulls its CSS and JS from `/static`. It
//! talks to the JSON API described in [`super`].

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The operator UI, compiled into the binary.
const ADMIN_HTML: &str = include_str!("index.html");

/// Locks the page down to its own origin.
///
/// The markup carries one inline `<script>` and one inline `<style>`, hence
/// `'unsafe-inline'`; everything else — no external scripts, no remote fonts,
/// no third-party XHR — is denied outright, so an injected string cannot call
/// home. `connect-src 'self'` keeps the session token from being posted
/// elsewhere.
const CSP: &str = "default-src 'self'; \
                   script-src 'self' 'unsafe-inline'; \
                   style-src 'self' 'unsafe-inline'; \
                   img-src 'self' data:; \
                   connect-src 'self'; \
                   base-uri 'none'; \
                   form-action 'none'; \
                   frame-ancestors 'none'";

/// Returns the operator UI.
///
/// Public by necessity — it *is* the login screen. It contains no secrets: the
/// password is typed in by the operator and every API call it makes is
/// authenticated separately.
#[must_use]
pub async fn admin_page() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(CSP),
            ),
            (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        ADMIN_HTML,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page must not embed anything that would only work with a laxer CSP
    /// — the public dashboard's Tailwind CDN tag, most of all — and must not
    /// accidentally ship a credential.
    #[test]
    fn admin_html_is_self_contained() {
        assert!(ADMIN_HTML.contains("<title>"));
        assert!(
            !ADMIN_HTML.contains("http://") && !ADMIN_HTML.contains("https://"),
            "the page must not reference external origins (CSP forbids them)"
        );
        assert!(
            !ADMIN_HTML.contains("ADMIN_PASSWORD="),
            "no credential should be echoed into the page"
        );
    }

    /// The restart control and the API have to agree on their spellings: the
    /// field the page posts, and the two flags it reads back. A rename on
    /// either side would otherwise leave the operator a checkbox that silently
    /// does nothing.
    #[test]
    fn admin_html_speaks_the_same_restart_api_as_the_server() {
        for key in ["restart_available", "result.restarting", "reset-restart"] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }
    }

    /// The registration card is the whole point of the page on a node that
    /// never onboarded, and it is driven entirely by these names: the status
    /// block it keys off, the route it posts to, and the three wallet fields it
    /// forwards. A rename on either side leaves an operator with a button that
    /// does nothing on the one node that needs it.
    #[test]
    fn admin_html_speaks_the_same_registration_api_as_the_server() {
        for key in [
            "registration.supported",
            "registration.registered",
            "registration.bls_pubkey",
            "/api/admin/register-node",
            "result.restarting",
            "pop.xpubkey",
            "pop.blsPubkey",
            "pop.schnorrSig",
        ] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }
    }

    /// The wallet is reached through the extension's injected global, and only
    /// these two calls. `signMessageBLS` in particular must not come back: the
    /// node signs the op itself, which is what keeps this to one prompt.
    #[test]
    fn admin_html_asks_the_wallet_only_for_the_proof_of_possession() {
        assert!(ADMIN_HTML.contains("window.HorizonWalletProvider"));
        assert!(ADMIN_HTML.contains("getBLSPoP"));
        assert!(ADMIN_HTML.contains("getAddresses"));
        assert!(
            !ADMIN_HTML.contains("signMessageBLS"),
            "the node signs the registration op with its own BLS key"
        );
    }

    /// The ledger block is the only place a stopped prover shows up: the row
    /// counts look healthy either way. A rename on the server side must not
    /// leave the page quietly reading `undefined`.
    #[test]
    fn admin_html_reads_the_ledger_fields_the_status_endpoint_sends() {
        for key in [
            "data.ledger",
            "rebuild_blocked",
            "awaiting_ledger_index",
            "ledger.placed",
            "ledger.highest_slot",
        ] {
            assert!(ADMIN_HTML.contains(key), "the page must still read {key}");
        }
    }

    #[tokio::test]
    async fn admin_page_sets_security_headers() {
        let response = admin_page().await;
        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert!(headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
    }
}
