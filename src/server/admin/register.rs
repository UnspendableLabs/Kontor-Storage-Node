//! `POST /api/admin/register-node` — register this node's BLS key on the Portal.
//!
//! # Why the node registers itself
//!
//! A Portal database reset drops every `nodes` row, and the node that comes
//! back finds its BLS key unknown. Re-registering used to mean opening Horizon
//! Market's profile page, which is a second deployment to keep alive for what
//! is really the node's own paperwork. This endpoint moves that work here.
//!
//! # What still needs the wallet
//!
//! One field. The Schnorr half of the proof of possession is signed with the
//! Taproot secret key, which never leaves Horizon Wallet, so the browser has to
//! ask the extension for it. Everything else the node computes from the BLS key
//! it already holds — see [`crate::node::registration`] — which is why the page
//! raises a single wallet prompt where Horizon Market raised two.
//!
//! The Portal's own gate is the Taproot address whitelist, and it survives the
//! Portal's reset. When it does not — a dropped database rather than a reset —
//! only a Portal admin can restore it, so that rejection is passed through
//! word for word rather than flattened into "registration failed".

use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::app::lifecycle::Activation;
use crate::clients::http_helpers::HttpStatusError;
use crate::node::registration::build_registration_request;
use crate::server::admin::{error_codes, ApiError, NodeIdentity};
use crate::server::state::DownloadServerState;

/// Request body for `POST /api/admin/register-node`.
///
/// These are the three fields of Horizon Wallet's `getBLSPoP` response that the
/// node cannot derive: the extended public key, the Schnorr proof of
/// possession, and the BLS key the wallet believes it is binding — carried so
/// the node can refuse a mismatch rather than register a key it cannot sign
/// with.
#[derive(Debug, Default, Deserialize)]
pub struct RegisterNodeRequest {
    #[serde(default)]
    pub xpubkey: String,
    #[serde(default)]
    pub bls_pubkey: String,
    #[serde(default)]
    pub schnorr_sig: String,
}

/// Register the node's BLS key and onboard again to pick it up.
///
/// # Errors
/// - `409 REGISTRATION_UNAVAILABLE` when no BLS key was loaded, so there is
///   nothing to register.
/// - `400 INVALID_REGISTRATION` when the wallet fields are malformed or name a
///   BLS key other than this node's.
/// - `502 PORTAL_ERROR` when the Portal refuses. Its own message is forwarded:
///   an unwhitelisted address needs a Portal admin, and only the Portal knows
///   to say so.
pub async fn register_node(
    request: &RegisterNodeRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    let identity = state.admin.identity().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            error_codes::REGISTRATION_UNAVAILABLE,
            "This node has no BLS key loaded, so there is nothing to register.",
        )
    })?;

    let payload = build_registration_request(
        identity.keypair(),
        &request.xpubkey,
        &request.bls_pubkey,
        &request.schnorr_sig,
    )
    .map_err(|err| ApiError::bad_request(error_codes::INVALID_REGISTRATION, format!("{err:#}")))?;

    info!(
        bls_pubkey = %payload.bls_pubkey,
        "Registering this node's BLS key with the Portal"
    );

    let response = identity
        .client()
        .register_node(&payload)
        .await
        .map_err(portal_error)?;

    // The Portal has the row; the key is not on-chain until its daemon batches
    // the RegisterBlsKey op, which is exactly the state onboarding already
    // knows how to wait out. So the node onboards again rather than growing a
    // second poll loop here.
    reonboard(&identity, state);

    info!(node_id = %response.node_id, "Node registered with the Portal; onboarding again");

    Ok(json!({
        "node_id": response.node_id,
        "bls_pubkey": payload.bls_pubkey,
        "reonboarding": true,
    }))
}

/// Ask the supervisor to onboard again, in this process.
///
/// This used to exit and let the platform's restart policy bring the node back,
/// which meant a registration made from `/admin` could only be finished on a
/// node that was able to restart unattended — and dropped the very page that
/// was reporting the result. The supervisor now re-derives the keys from the
/// keystore it already holds and runs onboarding again in place, so the session
/// survives, the answer arrives, and a node held open by a passphrase is no
/// longer a node that cannot complete its own registration.
fn reonboard(identity: &NodeIdentity, state: &DownloadServerState) {
    // A node that was already registered is being re-registered — the Portal
    // clears `signer_id` on the way through, so it has to onboard again too.
    if identity.registered().is_some() {
        warn!("Re-registering a node that was already registered; it will onboard again");
    }
    state.runtime.request(Activation::Reonboard);
}

/// Forward the Portal's own refusal.
///
/// Its error bodies are `{"error": {"code", "message"}}`; the message is the
/// only part an operator can act on, and flattening it would hide the one case
/// — an address that is not whitelisted — that needs somebody else entirely.
fn portal_error(err: anyhow::Error) -> ApiError {
    let Some(status_error) = err.downcast_ref::<HttpStatusError>() else {
        return ApiError::new(
            StatusCode::BAD_GATEWAY,
            error_codes::PORTAL_ERROR,
            "Could not reach the Portal to register this node.",
        )
        .with_detail(format!("{err:#}"));
    };

    let message = portal_message(&status_error.body).unwrap_or_else(|| {
        format!(
            "The Portal refused the registration (HTTP {}).",
            status_error.status
        )
    });

    ApiError::new(StatusCode::BAD_GATEWAY, error_codes::PORTAL_ERROR, message)
        .with_detail(format!("{err:#}"))
}

/// Pull `error.message` out of a Portal error body.
fn portal_message(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let message = parsed.get("error")?.get("message")?.as_str()?;
    (!message.is_empty()).then(|| message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::app::restart::RestartHandle;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::clients::PortalClient;
    use crate::crypto::BlsKeyPair;
    use crate::server::admin::{AdminState, RegisteredNode};
    use crate::testutils::{setup_in_memory_db, tempdir};

    /// BIP32 test vector 1, chain m.
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn schnorr_sig() -> String {
        "ab".repeat(64)
    }

    /// A node whose key is loaded, pointed at `portal_uri`.
    async fn state_with_identity(
        portal_uri: &str,
        registered: Option<RegisteredNode>,
        restart: RestartHandle,
    ) -> (DownloadServerState, Arc<BlsKeyPair>, tempfile::TempDir) {
        let dir = tempdir();
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let client = PortalClient::try_new(portal_uri, dir.path()).unwrap();
        let identity = NodeIdentity::new(keypair.clone(), client, registered, None);

        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(None, None),
            admin: AdminState::with_identity(identity, restart),
        };
        (state, keypair, dir)
    }

    async fn mock_register(server: &MockServer, node_id: &str, bls_pubkey: &str) {
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "node_id": node_id,
                "x_only_pubkey": "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                "bls_public_key": bls_pubkey,
            })))
            .mount(server)
            .await;
    }

    fn request(bls_pubkey: &str) -> RegisterNodeRequest {
        RegisterNodeRequest {
            xpubkey: XPUB.to_string(),
            bls_pubkey: bls_pubkey.to_string(),
            schnorr_sig: schnorr_sig(),
        }
    }

    /// Whatever the supervisor was asked to do, or `None` if it was asked for
    /// nothing. The pending slot is consumed, so this answers once.
    async fn asked_of_the_supervisor(state: &DownloadServerState) -> Option<Activation> {
        tokio::time::timeout(Duration::from_millis(50), state.runtime.next())
            .await
            .ok()
    }

    #[tokio::test]
    async fn registering_reports_the_node_id_and_onboards_again() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;
        let pubkey = keypair.public_key_hex();
        mock_register(&server, "node-fresh", &pubkey).await;

        let body = register_node(&request(&pubkey), &state).await.unwrap();

        assert_eq!(body["node_id"], "node-fresh");
        assert_eq!(body["bls_pubkey"], pubkey);
        assert_eq!(body["reonboarding"], true);
        assert!(
            matches!(
                asked_of_the_supervisor(&state).await,
                Some(Activation::Reonboard)
            ),
            "onboarding is what turns a registration into a running node"
        );
    }

    /// The point of onboarding in place. Registering used to exit the process,
    /// which meant the one node that could not restart unattended — the one
    /// held open by a passphrase — was also the one that could not finish its
    /// own registration, and the page reporting the result went down with it.
    #[tokio::test]
    async fn a_node_that_could_not_restart_still_finishes_its_registration() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;
        let pubkey = keypair.public_key_hex();
        mock_register(&server, "node-fresh", &pubkey).await;
        // Nothing on this machine could open the keystore again.
        state
            .runtime
            .set_slots(vec![crate::crypto::keystore::SlotKind::Passphrase]);
        assert!(!state.runtime.can_restart());

        let body = register_node(&request(&pubkey), &state).await.unwrap();

        assert_eq!(body["reonboarding"], true);
        assert!(matches!(
            asked_of_the_supervisor(&state).await,
            Some(Activation::Reonboard)
        ));
        assert!(
            !state.admin.restart().is_requested(),
            "the process must stay up: /admin is where the answer is being read"
        );
    }

    /// The Portal is sent exactly what it verifies: the signatures are only
    /// checkable against the key the node holds, so a body that dropped or
    /// renamed a field would fail there rather than here.
    #[tokio::test]
    async fn the_portal_receives_all_five_registration_fields() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;
        let pubkey = keypair.public_key_hex();
        mock_register(&server, "node-fresh", &pubkey).await;

        register_node(&request(&pubkey), &state).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent["xpubkey"], XPUB);
        assert_eq!(sent["bls_pubkey"], pubkey);
        assert_eq!(sent["schnorr_sig"], schnorr_sig());
        assert_eq!(sent["bls_sig"].as_str().unwrap().len(), 96);
        assert_eq!(sent["registration_signature"].as_str().unwrap().len(), 96);
    }

    /// Re-registering clears `signer_id` on the Portal, so an already-running
    /// node has to onboard again to pick the new one up.
    #[tokio::test]
    async fn re_registering_an_already_registered_node_onboards_it_again() {
        let server = MockServer::start().await;
        let registered = Some(RegisteredNode {
            node_id: "node-old".to_string(),
            signer_id: 42,
        });
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), registered, RestartHandle::new()).await;
        let pubkey = keypair.public_key_hex();
        mock_register(&server, "node-old", &pubkey).await;

        let body = register_node(&request(&pubkey), &state).await.unwrap();

        assert_eq!(body["reonboarding"], true);
        assert!(matches!(
            asked_of_the_supervisor(&state).await,
            Some(Activation::Reonboard)
        ));
    }

    /// Registering a key the node cannot sign with produces a Portal row that
    /// the next lookup will not match — the same 404 it started from. It must
    /// not reach the Portal at all.
    #[tokio::test]
    async fn a_wallet_holding_another_key_is_refused_before_the_portal_is_called() {
        let server = MockServer::start().await;
        let (state, _keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;
        let stranger = BlsKeyPair::generate().unwrap().public_key_hex();

        let err = register_node(&request(&stranger), &state)
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, error_codes::INVALID_REGISTRATION);
        assert!(err.message.contains("does not match this node's key"));
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "a mismatch must not be sent to the Portal"
        );
        assert!(asked_of_the_supervisor(&state).await.is_none());
    }

    #[tokio::test]
    async fn a_malformed_xpub_is_refused() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;

        let err = register_node(
            &RegisterNodeRequest {
                xpubkey: "not-an-xpub".to_string(),
                bls_pubkey: keypair.public_key_hex(),
                schnorr_sig: schnorr_sig(),
            },
            &state,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, error_codes::INVALID_REGISTRATION);
        assert!(err.message.contains("extended public key"));
    }

    #[tokio::test]
    async fn an_empty_body_is_refused() {
        let server = MockServer::start().await;
        let (state, _keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;

        let err = register_node(&RegisterNodeRequest::default(), &state)
            .await
            .unwrap_err();

        assert_eq!(err.code, error_codes::INVALID_REGISTRATION);
    }

    /// The one refusal the operator cannot act on alone: only a Portal admin
    /// can whitelist an address, so its wording has to survive the trip.
    #[tokio::test]
    async fn an_unwhitelisted_address_is_reported_in_the_portals_own_words() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {
                    "code": "ADDRESS_NOT_WHITELISTED",
                    "message": "Bitcoin address tb1pxyz is not whitelisted for node registration",
                }
            })))
            .mount(&server)
            .await;

        let err = register_node(&request(&keypair.public_key_hex()), &state)
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(err.code, error_codes::PORTAL_ERROR);
        assert_eq!(
            err.message,
            "Bitcoin address tb1pxyz is not whitelisted for node registration"
        );
        assert!(
            asked_of_the_supervisor(&state).await.is_none(),
            "a refused registration must not send the node round again"
        );
    }

    #[tokio::test]
    async fn a_portal_that_answers_with_junk_reports_the_status() {
        let server = MockServer::start().await;
        let (state, keypair, _dir) =
            state_with_identity(&server.uri(), None, RestartHandle::new()).await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(500).set_body_string("<html>oops</html>"))
            .mount(&server)
            .await;

        let err = register_node(&request(&keypair.public_key_hex()), &state)
            .await
            .unwrap_err();

        assert_eq!(err.code, error_codes::PORTAL_ERROR);
        assert!(err.message.contains("500"), "{}", err.message);
    }

    /// Nothing in the tree builds this state today, but the endpoint is public
    /// enough that it has to answer rather than panic.
    #[tokio::test]
    async fn a_node_without_a_key_has_nothing_to_register() {
        let dir = tempdir();
        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(None, None),
            admin: AdminState::disabled(),
        };

        let err = register_node(&RegisterNodeRequest::default(), &state)
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::REGISTRATION_UNAVAILABLE);
    }

    #[test]
    fn a_portal_error_body_is_unwrapped_to_its_message() {
        let body = json!({
            "error": {
                "code": "ADDRESS_NOT_WHITELISTED",
                "message": "Bitcoin address tb1p… is not whitelisted for node registration",
            }
        })
        .to_string();
        assert_eq!(
            portal_message(&body).unwrap(),
            "Bitcoin address tb1p… is not whitelisted for node registration"
        );
    }

    /// A proxy or a crashed Portal answers with HTML or nothing at all, and the
    /// status line is then the only thing worth showing.
    #[test]
    fn a_body_that_is_not_a_portal_error_yields_nothing() {
        assert!(portal_message("<html>502 Bad Gateway</html>").is_none());
        assert!(portal_message("").is_none());
        assert!(portal_message(r#"{"error": "plain string"}"#).is_none());
        assert!(portal_message(r#"{"error": {"message": ""}}"#).is_none());
    }

    /// A connection that never produced a response has no status to report, so
    /// the generic message stands in.
    #[test]
    fn a_transport_failure_reports_that_the_portal_was_unreachable() {
        let error = portal_error(anyhow::anyhow!("connection refused"));
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert!(error.message.contains("Could not reach the Portal"));
    }

    #[test]
    fn a_status_error_without_a_json_body_reports_the_status() {
        let error = portal_error(anyhow::Error::new(HttpStatusError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: "upstream down".to_string(),
            context: "register node".to_string(),
        }));
        assert!(error.message.contains("503"), "{}", error.message);
    }
}
