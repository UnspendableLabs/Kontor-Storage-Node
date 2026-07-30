//! `POST /api/admin/setup/provision` — give an unconfigured node its identity.
//!
//! # The one thing this endpoint must never do
//!
//! Take a seed phrase in the clear.
//!
//! TLS already covers the wire, and on a well-behaved deployment that would be
//! the end of it. Deployments are not well-behaved. The connection terminates at
//! a platform edge that is free to log request bodies; a proxy in between may
//! buffer them; an APM agent may sample them; an error reporter may serialize
//! the whole request when something downstream panics. None of that is an
//! attack, and all of it ends with a wallet's seed phrase in somebody's log
//! store, forever. A mnemonic is not a password that can be rotated after such a
//! leak — it is every key the operator will ever derive.
//!
//! So the browser encrypts it to a key that only this process holds, and what
//! travels is ciphertext that the edge, the proxy and the reporter can all log
//! to their heart's content.
//!
//! # What it is, precisely
//!
//! ECIES over P-256, the shape of an HPKE ciphersuite and using only what
//! WebCrypto offers natively, because [`crate::server::admin::ui`] forbids the
//! page from loading a single external script:
//!
//! 1. The node mints an **ephemeral** P-256 keypair, in memory, for one use.
//! 2. The browser mints its own, does ECDH, and runs the shared secret's
//!    x-coordinate through `HKDF-SHA256` — salted with the session id, with a
//!    fixed `info` string.
//! 3. It seals the payload with `AES-256-GCM`, **with the session id as
//!    additional authenticated data**. That is what binds a ciphertext to the
//!    one envelope it was made for; a captured body cannot be replayed against
//!    the next one.
//!
//! P-256 rather than X25519 for one reason only: WebCrypto's `ECDH` supports it
//! everywhere, and X25519 does not have the same browser floor.
//!
//! # What this does not defend against, stated plainly
//!
//! An attacker who controls the *response* path. The envelope's public key is
//! only as trustworthy as the admin session that fetched it, and that session's
//! bearer token crosses the same proxy in an `Authorization` header — so anyone
//! able to rewrite responses can equally steal the session and hand out an
//! envelope of their own. This is defence against **passive capture**, which is
//! the failure that actually happens, not against an active man in the middle.
//!
//! The one out-of-band check is the fingerprint: the node logs it when the
//! envelope is issued and the page shows it, so an operator who cares can
//! compare the two. That is exactly why it is worth printing.
//!
//! # After decryption
//!
//! The mnemonic exists in this process for as long as it takes to derive a key,
//! inside `Zeroizing` throughout, and is never written anywhere. What persists
//! is the sealed BLS key and the public identity — see
//! [`crate::crypto::identity`] for why that is enough forever.

use std::time::{Duration, Instant};

use aes_gcm::aead::rand_core::RngCore;
use anyhow::{anyhow, Context, Result};
use axum::http::StatusCode;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, PublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::app::lifecycle::{Activation, Phase};
use crate::crypto::aead::{self, KEY_SIZE};
use crate::crypto::keystore::{self, Keystore};
use crate::crypto::{BitcoinNetwork, MnemonicIdentity, MnemonicSettings};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// How long an unused envelope stays valid.
///
/// Long enough to type a seed phrase carefully, short enough that a page left
/// open over lunch does not leave a live decryption key in the process.
pub const ENVELOPE_TTL: Duration = Duration::from_secs(300);

/// Bound to the derivation so a key from this exchange cannot be mistaken for
/// one from any other.
const HKDF_INFO: &[u8] = b"KONTOR_ADMIN_SETUP_V1";

/// Domain separation for the envelope fingerprint.
const FINGERPRINT_DOMAIN: &[u8] = b"KONTOR_ENVELOPE_FP_V1";

const SESSION_ID_BYTES: usize = 16;

/// A one-shot decryption key, alive in memory only.
pub struct EnvelopeSession {
    id: [u8; SESSION_ID_BYTES],
    secret: EphemeralSecret,
    issued: Instant,
}

impl std::fmt::Debug for EnvelopeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeSession")
            .field("id", &hex::encode(self.id))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl EnvelopeSession {
    /// Mint a fresh envelope.
    #[must_use]
    pub fn issue() -> Self {
        let mut id = [0u8; SESSION_ID_BYTES];
        rand::thread_rng().fill_bytes(&mut id);
        Self {
            id,
            secret: EphemeralSecret::random(&mut OsRng),
            issued: Instant::now(),
        }
    }

    #[must_use]
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// The public key the browser encrypts to, as uncompressed SEC1 — the
    /// encoding WebCrypto's `"raw"` export produces, so neither side has to
    /// convert.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(EncodedPoint::from(self.secret.public_key()).as_bytes())
    }

    /// A short identifier for the key in this envelope, so an operator can
    /// compare the browser against the node's own logs.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(EncodedPoint::from(self.secret.public_key()).as_bytes());
        hex::encode(&hasher.finalize()[..4])
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.issued.elapsed() >= ENVELOPE_TTL
    }

    /// Seconds left before this envelope stops working.
    #[must_use]
    pub fn expires_in(&self) -> u64 {
        ENVELOPE_TTL.saturating_sub(self.issued.elapsed()).as_secs()
    }

    /// Open what the browser sealed.
    ///
    /// # Errors
    /// If the client key is malformed, or authentication fails — which covers a
    /// wrong envelope, a tampered body and a replayed session id alike.
    pub fn open(
        &self,
        client_pubkey_hex: &str,
        nonce_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let client_bytes =
            hex::decode(client_pubkey_hex).context("the client public key is not hex")?;
        let client = PublicKey::from_sec1_bytes(&client_bytes)
            .map_err(|e| anyhow!("the client public key is not a P-256 point: {e}"))?;

        let shared = self.secret.diffie_hellman(&client);

        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        Hkdf::<Sha256>::new(Some(&self.id), shared.raw_secret_bytes())
            .expand(HKDF_INFO, key.as_mut())
            .map_err(|e| anyhow!("deriving the envelope key: {e}"))?;

        aead::open(
            &key,
            &self.id,
            &hex::decode(nonce_hex).context("the nonce is not hex")?,
            &hex::decode(ciphertext_hex).context("the ciphertext is not hex")?,
        )
    }
}

/// Request body for `POST /api/admin/setup/provision`.
#[derive(Debug, Default, Deserialize)]
pub struct ProvisionRequest {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub client_pubkey: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub ciphertext: String,
}

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

/// `GET /api/admin/setup/envelope` — mint a key for the browser to seal to.
///
/// # Errors
/// `409 SETUP_UNAVAILABLE` on a node that already has a keystore.
pub fn issue_envelope(state: &DownloadServerState) -> Result<Value, ApiError> {
    require_uninitialized(state)?;

    let session = EnvelopeSession::issue();
    let body = json!({
        "session_id": session.id_hex(),
        "node_pubkey": session.public_key_hex(),
        "fingerprint": session.fingerprint(),
        "expires_in": session.expires_in(),
    });

    // Logged so an operator who wants to check that the page is talking to this
    // process, and not to something in front of it, has something to compare
    // against. It is the only out-of-band check this design offers.
    tracing::info!(
        fingerprint = %session.fingerprint(),
        "Issued a setup envelope; compare this fingerprint with the one shown in /admin"
    );

    state.admin.store_envelope(session);
    Ok(body)
}

/// `POST /api/admin/setup/provision` — derive, seal, and activate.
///
/// # Errors
/// - `409 SETUP_UNAVAILABLE` on a node that already has a keystore.
/// - `400 INVALID_ENVELOPE` when the envelope is unknown, expired, or the
///   payload does not authenticate.
/// - `400 INVALID_SETUP` when what it contained is not a usable seed phrase.
/// - `500` when the keystore cannot be written.
pub fn provision(
    request: &ProvisionRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    require_uninitialized(state)?;

    // Taken, not borrowed: an envelope is good for exactly one attempt, whether
    // or not that attempt succeeds. A failed decryption that left the key alive
    // would turn a one-shot exchange into an oracle.
    let session = state
        .admin
        .take_envelope()
        .filter(|session| session.id_hex() == request.session_id && !session.is_expired())
        .ok_or_else(|| {
            ApiError::bad_request(
                error_codes::INVALID_ENVELOPE,
                "That setup envelope is unknown or has expired. Reload /admin and try again.",
            )
        })?;

    let plaintext = session
        .open(&request.client_pubkey, &request.nonce, &request.ciphertext)
        .map_err(|e| {
            ApiError::bad_request(
                error_codes::INVALID_ENVELOPE,
                "The setup payload did not decrypt. Reload /admin and try again.",
            )
            .with_detail(format!("{e:#}"))
        })?;

    let payload: ProvisionPayload = serde_json::from_slice(&plaintext).map_err(|e| {
        ApiError::bad_request(
            error_codes::INVALID_SETUP,
            "The setup payload was not in the expected form.",
        )
        .with_detail(format!("{e:#}"))
    })?;

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

    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon about";

    /// The browser half of the exchange, in Rust.
    ///
    /// This is what makes the protocol testable at all: the page's WebCrypto
    /// calls cannot run here, but the wire format they produce can be built
    /// exactly, and a server that opens this will open theirs. What stays
    /// unverified by the suite is the shape of the JavaScript calls, and
    /// pretending otherwise would be worse than saying so.
    fn seal_for(
        node_pubkey_hex: &str,
        session_id_hex: &str,
        plaintext: &[u8],
    ) -> (String, String, String) {
        let node_public =
            PublicKey::from_sec1_bytes(&hex::decode(node_pubkey_hex).unwrap()).unwrap();
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let shared = client_secret.diffie_hellman(&node_public);
        let session_id = hex::decode(session_id_hex).unwrap();

        let mut key = [0u8; KEY_SIZE];
        Hkdf::<Sha256>::new(Some(&session_id), shared.raw_secret_bytes())
            .expand(HKDF_INFO, &mut key)
            .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &session_id,
                },
            )
            .unwrap();

        (
            hex::encode(EncodedPoint::from(client_secret.public_key()).as_bytes()),
            hex::encode(nonce_bytes),
            hex::encode(ciphertext),
        )
    }

    fn payload() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "mnemonic": PHRASE,
            "account": 2,
            "network": "signet",
        }))
        .unwrap()
    }

    #[test]
    fn a_payload_sealed_by_the_client_opens_on_the_node() {
        let session = EnvelopeSession::issue();
        let (client_pubkey, nonce, ciphertext) =
            seal_for(&session.public_key_hex(), &session.id_hex(), &payload());

        let opened = session.open(&client_pubkey, &nonce, &ciphertext).unwrap();
        let parsed: ProvisionPayload = serde_json::from_slice(&opened).unwrap();

        assert_eq!(parsed.mnemonic, PHRASE);
        assert_eq!(parsed.account, 2);
    }

    /// The property the AAD buys: a body captured off one envelope is useless
    /// against the next.
    #[test]
    fn a_payload_sealed_for_another_envelope_does_not_open() {
        let first = EnvelopeSession::issue();
        let second = EnvelopeSession::issue();
        let (client_pubkey, nonce, ciphertext) =
            seal_for(&first.public_key_hex(), &first.id_hex(), &payload());

        assert!(second.open(&client_pubkey, &nonce, &ciphertext).is_err());
    }

    /// The same node key, but the session id the ciphertext was bound to has
    /// been swapped. Only the AAD catches this.
    #[test]
    fn a_payload_bound_to_another_session_id_does_not_open() {
        let session = EnvelopeSession::issue();
        let other_id = EnvelopeSession::issue().id_hex();
        let (client_pubkey, nonce, ciphertext) =
            seal_for(&session.public_key_hex(), &other_id, &payload());

        assert!(session.open(&client_pubkey, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_does_not_open() {
        let session = EnvelopeSession::issue();
        let (client_pubkey, nonce, ciphertext) =
            seal_for(&session.public_key_hex(), &session.id_hex(), &payload());

        let flipped = format!(
            "{}{}",
            if ciphertext.starts_with('a') {
                'b'
            } else {
                'a'
            },
            &ciphertext[1..]
        );
        assert!(session.open(&client_pubkey, &nonce, &flipped).is_err());
    }

    #[test]
    fn malformed_client_material_is_refused_rather_than_panicking() {
        let session = EnvelopeSession::issue();
        let (client_pubkey, nonce, ciphertext) =
            seal_for(&session.public_key_hex(), &session.id_hex(), &payload());

        assert!(session.open("not hex", &nonce, &ciphertext).is_err());
        assert!(session
            .open(&hex::encode([1u8; 65]), &nonce, &ciphertext)
            .is_err());
        assert!(session.open(&client_pubkey, "zz", &ciphertext).is_err());
        assert!(session.open(&client_pubkey, &nonce, "zz").is_err());
    }

    #[test]
    fn an_envelope_reports_its_own_shape() {
        let session = EnvelopeSession::issue();

        assert_eq!(session.id_hex().len(), SESSION_ID_BYTES * 2);
        // Uncompressed SEC1 for P-256: 0x04 plus two 32-byte coordinates.
        assert_eq!(session.public_key_hex().len(), 65 * 2);
        assert!(session.public_key_hex().starts_with("04"));
        assert_eq!(session.fingerprint().len(), 8);
        assert!(!session.is_expired());
        assert!(session.expires_in() > 0);

        let rendered = format!("{session:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// Two envelopes must never share a key or an id.
    #[test]
    fn every_envelope_is_its_own() {
        let first = EnvelopeSession::issue();
        let second = EnvelopeSession::issue();

        assert_ne!(first.id_hex(), second.id_hex());
        assert_ne!(first.public_key_hex(), second.public_key_hex());
        assert_ne!(first.fingerprint(), second.fingerprint());
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
        assert!(derive(PHRASE, 0, None).is_err());
    }
}
