//! `POST /api/admin/setup/provision` — give an unconfigured node its identity.
//!
//! # The one thing this endpoint must never do
//!
//! Take a seed phrase in the clear.
//!
//! It does not: the phrase arrives sealed to a one-shot key only this process
//! holds, and what crosses the edge, the proxy and the error reporter is
//! ciphertext. [`crate::server::admin::envelope`] is that channel, and the
//! reasoning for it — along with what it deliberately does not defend against —
//! lives there rather than here.
//!
//! # After decryption
//!
//! The mnemonic exists in this process for as long as it takes to derive a key,
//! inside `Zeroizing` throughout, and is never written anywhere. What persists
//! is the sealed BLS key and the public identity — see
//! [`crate::crypto::identity`] for why that is enough forever.

use anyhow::Result;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app::lifecycle::{Activation, Phase};
use crate::crypto::keystore::{self, Keystore};
use crate::crypto::{BitcoinNetwork, MnemonicIdentity, MnemonicSettings};
use crate::server::admin::envelope::{self, SealedRequest};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// What the browser sealed. Never logged, never echoed.
#[derive(Deserialize)]
struct ProvisionPayload {
    mnemonic: String,
    #[serde(default = "default_account")]
    account: u32,
    #[serde(default)]
    network: Option<String>,
}

fn default_account() -> u32 {
    crate::crypto::mnemonic::FIRST_ACCOUNT
}

/// `POST /api/admin/setup/provision` — derive, seal, and activate.
///
/// # Errors
/// - `409 SETUP_UNAVAILABLE` on a node that already has a keystore.
/// - `400 INVALID_ENVELOPE` when the envelope is unknown, expired, or the
///   payload does not authenticate.
/// - `400 INVALID_SETUP` when what it contained is not a usable seed phrase.
/// - `500` when the keystore cannot be written.
pub async fn provision(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    // Held across the whole of provisioning, and the phase is read *inside* it.
    // Two tabs would otherwise both see `Uninitialized`, both derive, and the
    // second would write its keystore over the first — leaving a node whose
    // identity is whichever request happened to finish last, and a `.seal-key`
    // that opens only one of the two.
    let _guard = state.admin.lock_keystore().await;
    require_uninitialized(state)?;

    let (_session, payload) = envelope::open_as::<ProvisionPayload>(request, state)?;

    // From here on the phrase lives in `Zeroizing` and nothing else. It is not
    // logged, not echoed in the response, and not written to disk in any form.
    let phrase = Zeroizing::new(payload.mnemonic);
    let identity = derive(&phrase, payload.account, payload.network.as_deref())
        .map_err(|e| ApiError::bad_request(error_codes::INVALID_SETUP, format!("{e:#}")))?;
    drop(phrase);

    let public = identity
        .public()
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;
    let secret = identity.keypair.secret_key_hex();
    drop(identity);

    let app_dir = state.admin.app_dir();
    let (seal_key, source) = keystore::resolve_seal_key(app_dir, true)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?
        .ok_or_else(|| ApiError::server_error("no seal key could be resolved or generated"))?;

    let keystore = Keystore::provision(app_dir, &secret, Some(public.clone()), &seal_key)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    tracing::info!(
        node_id = %public.node_id,
        seal_slot = %source.kind(),
        "Node provisioned from /admin; sealing complete"
    );

    let body = json!({
        "node_id": public.node_id,
        "account": public.account,
        "network": public.network.to_string(),
        "taproot_address": public.taproot_address,
        "bls_pubkey": public.bls_pubkey,
        "seal_slot": source.kind().to_string(),
        "seal_fingerprint": seal_key.fingerprint(),
    });

    // Entered here rather than left to the supervisor. The phase *is* the lock
    // this endpoint checks, so publishing it before the guard is dropped is what
    // makes the check above mean anything: a second request that arrives while
    // the supervisor is still waking up now sees a node that already has a key.
    state.runtime.enter(Phase::Activating);
    state.runtime.request(Activation::Open {
        keystore: Box::new(keystore),
        seal_key,
        source,
    });

    Ok(body)
}

/// Derive an identity from what the operator typed, with the account and
/// network they picked.
fn derive(phrase: &str, account: u32, network: Option<&str>) -> Result<MnemonicIdentity> {
    let network = match network {
        Some(name) => BitcoinNetwork::parse(name)?,
        None => BitcoinNetwork::Signet,
    };
    MnemonicIdentity::derive(&MnemonicSettings::for_setup(phrase, network, account)?)
}

/// Refuse to provision a node that already holds a key.
///
/// The check is on the phase rather than on the file, because the phase is what
/// the rest of the process agrees on — and because a node that is merely
/// [`Phase::Sealed`] must be refused too. Provisioning over a keystore nobody
/// can currently open would replace an identity that is only temporarily out of
/// reach.
fn require_uninitialized(state: &DownloadServerState) -> Result<(), ApiError> {
    if state.runtime.phase() == Phase::Uninitialized {
        return Ok(());
    }

    Err(ApiError::new(
        StatusCode::CONFLICT,
        error_codes::SETUP_UNAVAILABLE,
        "This node already has a key. Setup is only available on a node that has none.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::lifecycle::{NodeRuntime, SealStatus};
    use crate::app::restart::RestartHandle;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::server::admin::credentials::AdminCredential;
    use crate::server::admin::envelope::testing::Client;
    use crate::server::admin::AdminState;
    use crate::testutils::{setup_in_memory_db, tempdir};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon about";

    /// A node in the phase the wizard is for, with a real application directory
    /// under it so a provision actually lands on disk.
    async fn uninitialized_node() -> (DownloadServerState, tempfile::TempDir) {
        let dir = tempdir();
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());

        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: runtime.clone(),
            admin: AdminState::new(
                AdminCredential::Disabled,
                dir.path().to_path_buf(),
                RestartHandle::new(),
                runtime,
            ),
        };
        (state, dir)
    }

    /// Fetch an envelope and seal a setup payload against it, as the page does.
    fn sealed_setup(state: &DownloadServerState, account: u32) -> SealedRequest {
        let envelope = envelope::issue(state);
        let session_id = envelope["session_id"].as_str().unwrap();
        let client = Client::greet(envelope["node_pubkey"].as_str().unwrap(), session_id);

        client.seal(
            session_id,
            &serde_json::to_vec(&json!({
                "mnemonic": PHRASE,
                "account": account,
                "network": "signet",
            }))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn a_sealed_phrase_provisions_the_node_it_names() {
        let (state, dir) = uninitialized_node().await;
        let request = sealed_setup(&state, 2);

        let body = provision(&request, &state).await.unwrap();

        assert_eq!(body["account"], 2);
        assert_eq!(body["network"], "signet");
        assert_eq!(body["seal_slot"], "file");

        // The keystore landed, and it holds the identity the response named.
        let keystore = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(keystore.public().unwrap().node_id, body["node_id"]);

        // And the phase moved before the supervisor had a chance to run.
        assert_eq!(state.runtime.phase(), Phase::Activating);
    }

    /// The window the phase change closes. A second tab posting its own
    /// envelope must not be able to write a second identity over the first.
    #[tokio::test]
    async fn a_second_provision_cannot_overwrite_the_first() {
        let (state, dir) = uninitialized_node().await;

        let first = sealed_setup(&state, 1);
        provision(&first, &state).await.unwrap();
        let node_id = Keystore::load(dir.path())
            .await
            .unwrap()
            .unwrap()
            .public()
            .unwrap()
            .node_id
            .clone();

        let second = sealed_setup(&state, 3);
        let err = provision(&second, &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::SETUP_UNAVAILABLE);

        // The identity on disk is still the first one.
        let keystore = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(keystore.public().unwrap().node_id, node_id);
    }

    /// An envelope is good for one attempt, successful or not. Replaying a body
    /// captured off the wire must not provision anything.
    #[tokio::test]
    async fn a_replayed_body_is_refused() {
        let (state, _dir) = uninitialized_node().await;
        let request = sealed_setup(&state, 1);

        // A wrong ciphertext consumes the envelope just as a right one does.
        let spent = SealedRequest {
            session_id: request.session_id.clone(),
            client_pubkey: request.client_pubkey.clone(),
            nonce: request.nonce.clone(),
            ciphertext: format!("ff{}", &request.ciphertext[2..]),
        };
        assert_eq!(
            provision(&spent, &state).await.unwrap_err().code,
            error_codes::INVALID_ENVELOPE
        );

        // And the original body, valid as it is, has nothing left to open it.
        assert_eq!(
            provision(&request, &state).await.unwrap_err().code,
            error_codes::INVALID_ENVELOPE
        );
        assert_eq!(state.runtime.phase(), Phase::Uninitialized);
    }

    /// A phrase that is not one has to come back as the operator's mistake, not
    /// as a 500 — and must leave the node exactly as it was.
    #[tokio::test]
    async fn an_unusable_phrase_leaves_the_node_alone() {
        let (state, dir) = uninitialized_node().await;

        let envelope = envelope::issue(&state);
        let session_id = envelope["session_id"].as_str().unwrap();
        let client = Client::greet(envelope["node_pubkey"].as_str().unwrap(), session_id);
        let request = client.seal(
            session_id,
            &serde_json::to_vec(&json!({ "mnemonic": "not a seed phrase", "account": 1 })).unwrap(),
        );

        let err = provision(&request, &state).await.unwrap_err();
        assert_eq!(err.code, error_codes::INVALID_SETUP);

        assert!(Keystore::load(dir.path()).await.unwrap().is_none());
        assert_eq!(state.runtime.phase(), Phase::Uninitialized);
    }

    /// Setup is for a node with no key. One that is merely sealed must be
    /// refused too: provisioning over a keystore nobody can open right now would
    /// replace an identity that is only temporarily out of reach.
    #[tokio::test]
    async fn a_sealed_node_is_not_offered_the_wizard() {
        let (state, _dir) = uninitialized_node().await;
        let request = sealed_setup(&state, 1);
        state.runtime.enter(Phase::Sealed);

        let err = provision(&request, &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::SETUP_UNAVAILABLE);
    }

    #[test]
    fn derive_picks_the_network_and_account_the_operator_chose() {
        let phrase = PHRASE;

        let signet = derive(phrase, 2, Some("signet")).unwrap();
        assert_eq!(signet.account, 2);
        assert_eq!(signet.network, BitcoinNetwork::Signet);

        let mainnet = derive(phrase, 1, Some("mainnet")).unwrap();
        assert_eq!(mainnet.network, BitcoinNetwork::Mainnet);
        assert_ne!(mainnet.node_id, signet.node_id);

        // Absent means signet, the network a node is most likely being set up on.
        assert_eq!(
            derive(phrase, 1, None).unwrap().network,
            BitcoinNetwork::Signet
        );

        assert!(derive(phrase, 1, Some("dogecoin")).is_err());
        assert!(derive("not a mnemonic", 1, None).is_err());
        assert!(derive("", 1, None).is_err());
    }

    /// `0` is refused by name rather than read as the first account, and the
    /// refusal has to say so: the page sends what the operator typed, so this
    /// message is what they see. Quietly setting up account 1 instead would
    /// leave them a node that is not the one they meant, discoverable only
    /// after it registers.
    #[test]
    fn account_zero_is_refused_in_the_operator_s_own_terms() {
        let refused = derive(PHRASE, 0, None).unwrap_err().to_string();
        assert!(refused.contains("from 1"), "{refused}");
        assert!(refused.contains("got 0"), "{refused}");
    }

    /// The default the payload carries when the page leaves the field blank. It
    /// has to be the wallet's first account, not the derivation path's zero.
    #[test]
    fn a_payload_without_an_account_means_the_first_one() {
        let parsed: ProvisionPayload =
            serde_json::from_value(json!({ "mnemonic": PHRASE })).unwrap();
        assert_eq!(parsed.account, crate::crypto::mnemonic::FIRST_ACCOUNT);
        assert!(parsed.network.is_none());
    }
}
