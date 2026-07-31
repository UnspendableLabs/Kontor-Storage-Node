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
    ///
    /// No `result.restarting` here any more, and its absence is the point: a
    /// registration is carried out in the running process, so the page has no
    /// exit to announce and nothing to sign back into.
    #[test]
    fn admin_html_speaks_the_same_registration_api_as_the_server() {
        for key in [
            "registration.supported",
            "registration.registered",
            "registration.bls_pubkey",
            "/api/admin/register-node",
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

    /// The setup wizard is the whole of zero-configuration on the browser side,
    /// and it is driven entirely by these names: the endpoints it calls, the
    /// bootstrap fields it switches panes on, and the four sealed-envelope
    /// fields it posts. A rename on either side leaves an operator with a form
    /// that cannot set their node up — on the one node that has no other way in.
    #[test]
    fn admin_html_speaks_the_same_setup_api_as_the_server() {
        for key in [
            "/api/admin/bootstrap",
            "/api/admin/claim",
            "/api/admin/envelope",
            "/api/admin/setup/provision",
            "/api/admin/unseal",
            "/api/admin/seal",
            "/api/admin/seal/env-slot",
            "/api/admin/seal/drop-file-slot",
            "info.claimed",
            "setup_token_fingerprint",
            "envelope.session_id",
            "envelope.node_pubkey",
            "client_pubkey",
            "ciphertext",
            // The reply direction: the seal key arrives under `sealed`.
            "result.sealed",
        ] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }
    }

    /// The envelope is only as good as the primitives on both sides agreeing.
    /// These are the exact WebCrypto names that have to match
    /// [`crate::server::admin::envelope`]: P-256 ECDH, HKDF-SHA256 salted with
    /// the session id, AES-GCM with that same id as additional authenticated
    /// data.
    #[test]
    fn admin_html_seals_with_the_agreed_primitives() {
        for key in [
            "P-256",
            "ECDH",
            "HKDF",
            "SHA-256",
            "AES-GCM",
            "deriveBits",
            "additionalData",
            "KONTOR_ADMIN_ENVELOPE_V1",
        ] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }
    }

    /// Both directions, expanded from one HKDF call. 512 bits is the number
    /// that has to match [`crate::server::admin::envelope`]: expand to 256 and
    /// the page would derive one key where the node derives two, and every
    /// sealed reply would fail to open with nothing saying why.
    #[test]
    fn admin_html_derives_a_key_for_each_direction() {
        assert!(
            ADMIN_HTML.contains("ikm, 512"),
            "the page must expand HKDF to two keys"
        );
        for key in ["openEnvelope", "sealRequest", "openResponse"] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }
        // One encrypt key and one decrypt key, not a single reversible one.
        assert!(ADMIN_HTML.contains(r#"["encrypt"]"#));
        assert!(ADMIN_HTML.contains(r#"["decrypt"]"#));
    }

    /// The account is the one field on this page a typo cannot be recovered
    /// from: an off-by-one derives a different node entirely, registers it, and
    /// leaves the original's agreements behind. `0` is refused by name rather
    /// than read as the first account — see [`crate::crypto::mnemonic`] — and
    /// that refusal only reaches the operator if the page sends what they typed
    /// instead of coercing it.
    #[test]
    fn admin_html_sends_the_account_as_typed() {
        assert!(
            !ADMIN_HTML.contains("|| 1"),
            "a falsy default would turn a typed 0 into account 1, silently"
        );
        assert!(ADMIN_HTML.contains("account: account"));
    }

    /// The one thing this page must never do. Neither of the two secrets it
    /// sends may appear in a request body outside the sealed envelope: a seed
    /// phrase cannot be rotated after a leak, and a seal passphrase opens the
    /// keystore. Both are read into the object that gets sealed and nowhere
    /// else.
    #[test]
    fn admin_html_never_posts_a_bare_secret() {
        assert!(ADMIN_HTML.contains("mnemonic: phrase"));
        assert!(ADMIN_HTML.contains("passphrase: passphrase"));
        // And the phrase is cleared as soon as it has been sent.
        assert!(ADMIN_HTML.contains(r#"$("setup-mnemonic").value = "";"#));

        for bare in ["body: { mnemonic", "body: { passphrase"] {
            assert!(
                !ADMIN_HTML.contains(bare),
                "{bare}: a secret must never be posted outside the sealed envelope"
            );
        }
    }

    /// Every lifecycle card ships `hidden` and is revealed by the phase alone.
    /// A card with no `renderPhase` branch is a card an operator can never
    /// reach — and on a fresh node the setup wizard is the only way in, so that
    /// failure is a node nobody can configure.
    #[test]
    fn admin_html_reveals_each_lifecycle_card_from_the_phase() {
        assert!(ADMIN_HTML.contains("function renderPhase"));
        assert!(
            ADMIN_HTML.contains("renderPhase(data)"),
            "the status poll must drive the phase, or the cards never move"
        );

        for branch in [
            r#"$("setup").hidden = phase !== "uninitialized""#,
            r#"$("unseal").hidden = phase !== "sealed""#,
        ] {
            assert!(
                ADMIN_HTML.contains(branch),
                "the page must still use {branch}"
            );
        }
        // The seal card is the exception: it is loaded rather than toggled,
        // because its contents come from an endpoint.
        assert!(ADMIN_HTML.contains("loadSeal()"));
        assert!(ADMIN_HTML.contains("phase-notice"));
    }

    /// The passphrase slot is the only recovery from a lost seal key, and it
    /// can only be added while the node still holds what opened its keystore.
    /// A page that did not offer it would leave the unseal card — which it does
    /// have — permanently unreachable in practice.
    #[test]
    fn admin_html_offers_the_passphrase_slot_the_seal_api_describes() {
        for key in [
            "/api/admin/seal/passphrase",
            "seal.can_add_passphrase_slot",
            "seal.has_passphrase_slot",
            "seal.min_passphrase_len",
            "seal-passphrase-submit",
            "function addPassphraseSlot",
        ] {
            assert!(ADMIN_HTML.contains(key), "the page must still use {key}");
        }

        // Sealed on the way up like the seed phrase, and cleared once sent.
        assert!(ADMIN_HTML.contains(r#"field.value = "";"#));
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
