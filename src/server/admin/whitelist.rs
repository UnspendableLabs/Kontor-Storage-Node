//! `/api/admin/whitelist-request` — ask the Portal to whitelist this node.
//!
//! # Why the node carries the form
//!
//! Registration is gated on the node's Taproot address being whitelisted, and
//! until the Portal grew its request queue the only way onto that list was to
//! find a Portal admin out of band. The queue's public endpoints take a proof
//! of possession — the same one a registration carries — plus the operator's
//! contact details, and the node already holds or can produce every signed
//! field. So the operator types four contact fields here and nothing else,
//! and the node signs and submits the rest.
//!
//! Nothing new waits on the outcome: the supervisor already replays the
//! registration every 30 seconds for as long as the node is unregistered, so
//! the moment an admin approves the request, the next replay goes through and
//! the node starts on its own. The `GET` half exists purely so the page can
//! say where the request stands — pending, or rejected and why — instead of
//! leaving the operator to infer it from a node that never comes up.

use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::info;

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::portal::WhitelistRequestView;
use crate::node::registration::{
    build_whitelist_from_public, build_whitelist_request, WhitelistContact,
};
use crate::server::admin::register::portal_error;
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Request body for `POST /api/admin/whitelist-request`.
///
/// The contact fields are the operator's. The three key fields are only for
/// the wallet flow — a node that imported a bare BLS key has no record of its
/// Taproot account, so the browser fetches the proof of possession from
/// Horizon Wallet exactly as it does to register. A mnemonic node leaves them
/// empty and its recorded identity is used instead.
#[derive(Debug, Default, Deserialize)]
pub struct SubmitWhitelistRequest {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub xpubkey: String,
    #[serde(default)]
    pub bls_pubkey: String,
    #[serde(default)]
    pub schnorr_sig: String,
}

/// Query for `GET /api/admin/whitelist-request`.
///
/// The address is optional because a mnemonic node knows its own; the wallet
/// flow passes the one the Portal answered its submission with.
#[derive(Debug, Default, Deserialize)]
pub struct WhitelistStatusQuery {
    #[serde(default)]
    pub bitcoin_address: Option<String>,
}

/// Submit a whitelist request for this node's Taproot address.
///
/// # Errors
/// - `409 WHITELIST_UNAVAILABLE` when no BLS key is loaded, or when neither
///   wallet fields nor a recorded identity can supply the proof.
/// - `400 INVALID_WHITELIST_REQUEST` when a field would not pass the Portal's
///   validation — checked here first, because the Portal charges its per-IP
///   submission quota before validating.
/// - `502 PORTAL_ERROR` when the Portal refuses; its own message is forwarded,
///   since "already whitelisted" and "too many attempts" each tell the
///   operator something different to do.
pub async fn submit(
    request: &SubmitWhitelistRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    let identity = state.admin.identity().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            error_codes::WHITELIST_UNAVAILABLE,
            "This node has no BLS key loaded, so there is nothing to request a whitelist entry for.",
        )
    })?;

    let contact = WhitelistContact {
        first_name: request.first_name.clone(),
        last_name: request.last_name.clone(),
        email: request.email.clone(),
        company: request.company.clone(),
    };

    let wallet_flow = !request.xpubkey.trim().is_empty();
    let body = if wallet_flow {
        build_whitelist_request(
            identity.keypair(),
            &request.xpubkey,
            &request.bls_pubkey,
            &request.schnorr_sig,
            &contact,
        )
    } else if let Some(public) = identity.public() {
        build_whitelist_from_public(identity.keypair(), public, &contact)
    } else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::WHITELIST_UNAVAILABLE,
            "This node has no record of its Taproot account, so the proof of possession \
             has to come from Horizon Wallet — use the wallet button instead.",
        ));
    }
    .map_err(|err| {
        ApiError::bad_request(error_codes::INVALID_WHITELIST_REQUEST, format!("{err:#}"))
    })?;

    info!(
        bls_pubkey = %body.bls_pubkey,
        "Submitting a whitelist request for this node's Taproot address"
    );

    let view = identity
        .client()
        .submit_whitelist_request(&body)
        .await
        .map_err(portal_error)?;

    info!(
        request_id = ?view.request_id,
        bitcoin_address = %view.bitcoin_address,
        status = %view.status,
        "The Portal queued the whitelist request"
    );

    Ok(view_json(&view))
}

/// Where this node's whitelist request stands.
///
/// Answers `status: "none"` — rather than an error — both when the Portal has
/// never seen the address and when no address is known yet, because either way
/// the page's next move is the same: offer the form.
///
/// # Errors
/// - `409 WHITELIST_UNAVAILABLE` when no BLS key is loaded.
/// - `502 PORTAL_ERROR` when the Portal cannot be reached or errors.
pub async fn status(
    query: &WhitelistStatusQuery,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    let identity = state.admin.identity().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            error_codes::WHITELIST_UNAVAILABLE,
            "This node has no BLS key loaded, so it has no whitelist request to report.",
        )
    })?;

    let queried = query
        .bitcoin_address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty());
    let derived = identity
        .public()
        .map(|public| public.taproot_address.clone());
    let Some(address) = queried.map(str::to_string).or(derived) else {
        return Ok(json!({
            "bitcoin_address": Value::Null,
            "status": "none",
            "whitelisted": false,
        }));
    };

    match identity.client().whitelist_request_status(&address).await {
        Ok(view) => Ok(view_json(&view)),
        // The Portal has never seen this address: neither a queued request nor
        // a whitelist entry. Not an error from where the operator stands — it
        // is the state the form exists for.
        Err(err) if is_not_found(&err) => Ok(json!({
            "bitcoin_address": address,
            "status": "none",
            "whitelisted": false,
        })),
        Err(err) => Err(portal_error(err)),
    }
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HttpStatusError>()
        .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND)
}

/// The Portal's view, forwarded field for field.
///
/// `whitelisted` is the one the node acts on; `status` and `review_note` are
/// what the operator reads. Serialized explicitly rather than re-encoding the
/// struct so the page's contract lives in one greppable place.
fn view_json(view: &WhitelistRequestView) -> Value {
    json!({
        "request_id": view.request_id,
        "bitcoin_address": view.bitcoin_address,
        "status": view.status,
        "whitelisted": view.whitelisted,
        "review_note": view.review_note,
        "requested_at": view.requested_at,
        "updated_at": view.updated_at,
        "reviewed_at": view.reviewed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::app::restart::RestartHandle;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::clients::PortalClient;
    use crate::crypto::{BitcoinNetwork, BlsKeyPair, MnemonicIdentity, MnemonicSettings};
    use crate::server::admin::{AdminState, NodeIdentity};
    use crate::testutils::{setup_in_memory_db, tempdir};

    /// BIP32 test vector 1, chain m.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn contact() -> SubmitWhitelistRequest {
        SubmitWhitelistRequest {
            first_name: "Ada".to_string(),
            last_name: "Lovelace".to_string(),
            email: "ada@example.com".to_string(),
            company: None,
            ..SubmitWhitelistRequest::default()
        }
    }

    fn derived_identity() -> MnemonicIdentity {
        MnemonicIdentity::derive(&MnemonicSettings::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
            BitcoinNetwork::Signet,
            2,
        ))
        .unwrap()
    }

    /// A node whose key is loaded, pointed at `portal_uri`. `public` decides
    /// whether it is a mnemonic node or a bare imported key.
    async fn state_with_identity(
        portal_uri: &str,
        keypair: BlsKeyPair,
        public: Option<crate::crypto::PublicIdentity>,
    ) -> (DownloadServerState, tempfile::TempDir) {
        let dir = tempdir();
        let client = PortalClient::try_new(portal_uri, dir.path()).unwrap();
        let identity = NodeIdentity::new(Arc::new(keypair), client, None, public);

        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(None, None),
            admin: AdminState::with_identity(identity, RestartHandle::new()),
        };
        (state, dir)
    }

    fn portal_view(address: &str, status: &str, whitelisted: bool) -> serde_json::Value {
        json!({
            "request_id": 12,
            "bitcoin_address": address,
            "status": status,
            "whitelisted": whitelisted,
            "review_note": null,
            "requested_at": "2026-08-04T00:00:00Z",
            "updated_at": "2026-08-04T00:00:00Z",
            "reviewed_at": null,
        })
    }

    #[tokio::test]
    async fn a_mnemonic_node_submits_from_its_recorded_identity() {
        let server = MockServer::start().await;
        let identity = derived_identity();
        let address = identity.taproot_address.clone();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, Some(public)).await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/whitelist/request"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(portal_view(&address, "pending", false)),
            )
            .mount(&server)
            .await;

        let body = submit(&contact(), &state).await.unwrap();

        assert_eq!(body["status"], "pending");
        assert_eq!(body["request_id"], 12);
        assert_eq!(body["whitelisted"], false);

        // The Portal received the four signed fields and the contact, and no
        // address — it derives that itself.
        let requests = server.received_requests().await.unwrap();
        let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent["xpubkey"], identity.xpubkey);
        assert_eq!(sent["bls_pubkey"], identity.bls_pubkey());
        assert_eq!(sent["schnorr_sig"].as_str().unwrap().len(), 128);
        assert_eq!(sent["bls_sig"].as_str().unwrap().len(), 96);
        assert_eq!(sent["first_name"], "Ada");
        assert_eq!(sent["last_name"], "Lovelace");
        assert_eq!(sent["email"], "ada@example.com");
        assert_eq!(sent.get("bitcoin_address"), None);
        assert_eq!(sent.get("registration_signature"), None);
    }

    #[tokio::test]
    async fn a_wallet_node_submits_with_the_fields_the_wallet_supplied() {
        let server = MockServer::start().await;
        let keypair = BlsKeyPair::generate().unwrap();
        let pubkey = keypair.public_key_hex();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, None).await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/whitelist/request"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(portal_view("bc1pxyz", "pending", false)),
            )
            .mount(&server)
            .await;

        let request = SubmitWhitelistRequest {
            xpubkey: XPUB.to_string(),
            bls_pubkey: pubkey.clone(),
            schnorr_sig: "ab".repeat(64),
            ..contact()
        };
        let body = submit(&request, &state).await.unwrap();

        assert_eq!(body["status"], "pending");
        let requests = server.received_requests().await.unwrap();
        let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent["xpubkey"], XPUB);
        assert_eq!(sent["bls_pubkey"], pubkey);
    }

    /// A bare imported key with no wallet fields has nothing to sign the
    /// Schnorr half with, and the message has to say where that proof comes
    /// from.
    #[tokio::test]
    async fn an_imported_key_without_wallet_fields_is_told_to_use_the_wallet() {
        let server = MockServer::start().await;
        let (state, _dir) =
            state_with_identity(&server.uri(), BlsKeyPair::generate().unwrap(), None).await;

        let err = submit(&contact(), &state).await.unwrap_err();

        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::WHITELIST_UNAVAILABLE);
        assert!(err.message.contains("Horizon Wallet"), "{}", err.message);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The Portal charges its submission quota before validating, so a body
    /// that cannot pass must never reach it.
    #[tokio::test]
    async fn invalid_contact_details_are_refused_before_the_portal_is_called() {
        let server = MockServer::start().await;
        let identity = derived_identity();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, Some(public)).await;

        for (label, request) in [
            (
                "a missing first name",
                SubmitWhitelistRequest {
                    first_name: "  ".to_string(),
                    ..contact()
                },
            ),
            (
                "an email that is not one",
                SubmitWhitelistRequest {
                    email: "not-an-email".to_string(),
                    ..contact()
                },
            ),
        ] {
            let err = submit(&request, &state).await.unwrap_err();
            assert_eq!(err.status, StatusCode::BAD_REQUEST, "{label}");
            assert_eq!(err.code, error_codes::INVALID_WHITELIST_REQUEST, "{label}");
        }
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "an invalid body must not spend a quota attempt"
        );
    }

    #[tokio::test]
    async fn a_node_without_a_key_has_nothing_to_request() {
        let dir = tempdir();
        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(None, None),
            admin: AdminState::disabled(),
        };

        let err = submit(&contact(), &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::WHITELIST_UNAVAILABLE);

        let err = status(&WhitelistStatusQuery::default(), &state)
            .await
            .unwrap_err();
        assert_eq!(err.code, error_codes::WHITELIST_UNAVAILABLE);
    }

    /// The two refusals an operator meets in practice — already whitelisted,
    /// and over quota — arrive in the Portal's own words.
    #[tokio::test]
    async fn portal_refusals_are_forwarded_in_the_portals_own_words() {
        let server = MockServer::start().await;
        let identity = derived_identity();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, Some(public)).await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/whitelist/request"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {
                    "code": "ADDRESS_ALREADY_WHITELISTED",
                    "message": "This address is already whitelisted",
                }
            })))
            .mount(&server)
            .await;

        let err = submit(&contact(), &state).await.unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(err.code, error_codes::PORTAL_ERROR);
        assert_eq!(err.message, "This address is already whitelisted");
    }

    #[tokio::test]
    async fn status_of_a_mnemonic_node_uses_its_own_address() {
        let server = MockServer::start().await;
        let identity = derived_identity();
        let address = identity.taproot_address.clone();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, Some(public)).await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/whitelist/request"))
            .and(query_param("bitcoin_address", address.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "request_id": 12,
                "bitcoin_address": address,
                "status": "rejected",
                "whitelisted": false,
                "review_note": "Capacity is full this quarter",
                "requested_at": "2026-08-04T00:00:00Z",
                "updated_at": "2026-08-04T01:00:00Z",
                "reviewed_at": "2026-08-04T01:00:00Z",
            })))
            .mount(&server)
            .await;

        let body = status(&WhitelistStatusQuery::default(), &state)
            .await
            .unwrap();

        assert_eq!(body["status"], "rejected");
        assert_eq!(body["review_note"], "Capacity is full this quarter");
        assert_eq!(body["bitcoin_address"], address);
    }

    /// An address the Portal has never seen is the form's starting state, not
    /// an error box.
    #[tokio::test]
    async fn an_unknown_address_reads_as_none_rather_than_an_error() {
        let server = MockServer::start().await;
        let identity = derived_identity();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity(&server.uri(), keypair, Some(public)).await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/whitelist/request"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {
                    "code": "WHITELIST_REQUEST_NOT_FOUND",
                    "message": "No whitelist request for this address",
                }
            })))
            .mount(&server)
            .await;

        let body = status(&WhitelistStatusQuery::default(), &state)
            .await
            .unwrap();

        assert_eq!(body["status"], "none");
        assert_eq!(body["whitelisted"], false);
        assert_eq!(body["bitcoin_address"], identity.taproot_address);
    }

    /// A wallet node has no recorded address; the page passes the one the
    /// Portal answered its submission with, and it wins over nothing.
    #[tokio::test]
    async fn status_accepts_an_explicit_address_for_wallet_nodes() {
        let server = MockServer::start().await;
        let (state, _dir) =
            state_with_identity(&server.uri(), BlsKeyPair::generate().unwrap(), None).await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/whitelist/request"))
            .and(query_param("bitcoin_address", "bc1pexplicit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(portal_view(
                "bc1pexplicit",
                "pending",
                false,
            )))
            .mount(&server)
            .await;

        let body = status(
            &WhitelistStatusQuery {
                bitcoin_address: Some("bc1pexplicit".to_string()),
            },
            &state,
        )
        .await
        .unwrap();

        assert_eq!(body["status"], "pending");
        assert_eq!(body["bitcoin_address"], "bc1pexplicit");
    }

    /// No recorded identity and no explicit address: nothing to ask the Portal
    /// about, and the page's next move is the form — so say `none`, not 502.
    #[tokio::test]
    async fn status_with_no_known_address_is_none_without_calling_the_portal() {
        let server = MockServer::start().await;
        let (state, _dir) =
            state_with_identity(&server.uri(), BlsKeyPair::generate().unwrap(), None).await;

        let body = status(&WhitelistStatusQuery::default(), &state)
            .await
            .unwrap();

        assert_eq!(body["status"], "none");
        assert_eq!(body["bitcoin_address"], Value::Null);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A Portal that is down is a 502 with the transport story, same as
    /// registration — not a silent `none` that would offer a form whose
    /// submission cannot work either.
    #[tokio::test]
    async fn a_portal_that_cannot_be_reached_is_a_portal_error() {
        let identity = derived_identity();
        let public = identity.public().unwrap();
        let keypair = BlsKeyPair::from_secret_key_hex(&identity.keypair.secret_key_hex()).unwrap();
        let (state, _dir) = state_with_identity("http://127.0.0.1:1", keypair, Some(public)).await;

        let err = status(&WhitelistStatusQuery::default(), &state)
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(err.code, error_codes::PORTAL_ERROR);
    }
}
