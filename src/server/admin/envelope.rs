//! The sealed channel between an operator's browser and this process.
//!
//! # What it is for
//!
//! Three things this node's `/admin` handles are secrets that must not sit in a
//! request or a response body in the clear: the seed phrase at setup, the seal
//! passphrase, and the seal key handed back when an env slot is added.
//!
//! TLS already covers the wire, and on a well-behaved deployment that would be
//! the end of it. Deployments are not well-behaved. The connection terminates at
//! a platform edge that is free to log request bodies; a proxy in between may
//! buffer them; an APM agent may sample them; an error reporter may serialize
//! the whole exchange when something downstream panics. None of that is an
//! attack, and all of it ends with a wallet's seed phrase — or the key that
//! opens this node's keystore — in somebody's log store, forever.
//!
//! So the browser and the node seal to each other, and what travels is
//! ciphertext that the edge, the proxy and the reporter can all log to their
//! heart's content.
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
//!    fixed `info` string — expanding to **64 bytes**.
//! 3. Those 64 bytes are two `AES-256-GCM` keys, not one: the first seals
//!    browser → node, the second node → browser. Splitting them is what stops a
//!    response from being replayed as a request, or the reverse.
//! 4. Every seal carries the **session id as additional authenticated data**,
//!    which binds a ciphertext to the one envelope it was made for; a captured
//!    body cannot be replayed against the next.
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
//! # Why there is no purpose binding
//!
//! One envelope can be spent on any of the endpoints that take one, and nothing
//! in the ciphertext says which. That is deliberate rather than overlooked:
//! every such endpoint sits behind [`crate::server::admin::session::AdminSession`],
//! so anyone in a position to redirect an envelope from one to another already
//! holds a session and can simply call the other endpoint. A purpose field would
//! be a field, not a defence.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, PublicKey};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, KEY_SIZE};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// How long an unused envelope stays valid.
///
/// Long enough to type a seed phrase carefully, short enough that a page left
/// open over lunch does not leave a live decryption key in the process.
pub const ENVELOPE_TTL: Duration = Duration::from_secs(300);

/// Bound to the derivation so a key from this exchange cannot be mistaken for
/// one from any other.
const HKDF_INFO: &[u8] = b"KONTOR_ADMIN_ENVELOPE_V1";

/// Domain separation for the envelope fingerprint.
const FINGERPRINT_DOMAIN: &[u8] = b"KONTOR_ENVELOPE_FP_V1";

const SESSION_ID_BYTES: usize = 16;

/// The two directional keys one envelope derives.
struct Directions {
    /// Seals browser → node.
    to_node: Zeroizing<[u8; KEY_SIZE]>,
    /// Seals node → browser.
    to_client: Zeroizing<[u8; KEY_SIZE]>,
}

/// A one-shot pair of directional keys, alive in memory only.
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
        aead::fingerprint(
            FINGERPRINT_DOMAIN,
            EncodedPoint::from(self.secret.public_key()).as_bytes(),
        )
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

    /// Both directional keys for a given client public key.
    fn directions(&self, client_pubkey_hex: &str) -> Result<Directions> {
        let client_bytes =
            hex::decode(client_pubkey_hex).context("the client public key is not hex")?;
        let client = PublicKey::from_sec1_bytes(&client_bytes)
            .map_err(|e| anyhow!("the client public key is not a P-256 point: {e}"))?;

        let shared = self.secret.diffie_hellman(&client);

        let mut okm = Zeroizing::new([0u8; KEY_SIZE * 2]);
        Hkdf::<Sha256>::new(Some(&self.id), shared.raw_secret_bytes())
            .expand(HKDF_INFO, okm.as_mut())
            .map_err(|e| anyhow!("deriving the envelope keys: {e}"))?;

        let mut to_node = Zeroizing::new([0u8; KEY_SIZE]);
        let mut to_client = Zeroizing::new([0u8; KEY_SIZE]);
        to_node.copy_from_slice(&okm[..KEY_SIZE]);
        to_client.copy_from_slice(&okm[KEY_SIZE..]);

        Ok(Directions { to_node, to_client })
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
        let keys = self.directions(client_pubkey_hex)?;

        aead::open(
            &keys.to_node,
            &self.id,
            &hex::decode(nonce_hex).context("the nonce is not hex")?,
            &hex::decode(ciphertext_hex).context("the ciphertext is not hex")?,
        )
    }

    /// Seal a reply only this browser can read.
    ///
    /// # Errors
    /// If the client key is malformed or the AEAD refuses the input.
    pub fn seal_for_client(&self, client_pubkey_hex: &str, plaintext: &[u8]) -> Result<Value> {
        let keys = self.directions(client_pubkey_hex)?;
        let (nonce, ciphertext) = aead::seal(&keys.to_client, &self.id, plaintext)?;

        Ok(json!({
            "nonce": hex::encode(nonce),
            "ciphertext": hex::encode(ciphertext),
        }))
    }
}

/// The four fields every envelope-carrying request posts.
///
/// One shape for all of them on purpose: an endpoint that took a slightly
/// different set would be one the page could get subtly wrong, and the failure
/// would surface as an operator holding an unreadable answer.
#[derive(Debug, Default, Deserialize)]
pub struct SealedRequest {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub client_pubkey: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub ciphertext: String,
}

/// `GET /api/admin/envelope` — mint a key for the browser to seal to.
///
/// Available in every phase, unlike the endpoints that spend it: a sealed node
/// unlocks with a passphrase and a running one reseals itself, and both need an
/// envelope as much as the setup wizard does.
pub fn issue(state: &DownloadServerState) -> Value {
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
        "Issued an admin envelope; compare this fingerprint with the one shown in /admin"
    );

    state.admin.store_envelope(session);
    body
}

/// Consume the live envelope and open what the browser sealed to it.
///
/// Taken, not borrowed: an envelope is good for exactly one attempt, whether or
/// not that attempt succeeds. A failed decryption that left the key alive would
/// turn a one-shot exchange into an oracle.
///
/// # Errors
/// `400 INVALID_ENVELOPE` when the envelope is unknown, expired, or the payload
/// does not authenticate.
pub fn open(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<(EnvelopeSession, Zeroizing<Vec<u8>>), ApiError> {
    let unknown = || {
        ApiError::bad_request(
            error_codes::INVALID_ENVELOPE,
            "That envelope is unknown or has expired. Reload /admin and try again.",
        )
    };

    let session = state
        .admin
        .take_envelope(&request.session_id)
        .ok_or_else(unknown)?;

    let plaintext = session
        .open(&request.client_pubkey, &request.nonce, &request.ciphertext)
        .map_err(|e| unknown().with_detail(format!("{e:#}")))?;

    Ok((session, plaintext))
}

/// Open a sealed request and parse what it carried.
///
/// # Errors
/// `400 INVALID_ENVELOPE` as [`open`], or `400 INVALID_SETUP` when the plaintext
/// is not the shape this endpoint expects.
pub fn open_as<T: serde::de::DeserializeOwned>(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<(EnvelopeSession, T), ApiError> {
    let (session, plaintext) = open(request, state)?;

    let parsed = serde_json::from_slice(&plaintext).map_err(|e| {
        ApiError::bad_request(
            error_codes::INVALID_SETUP,
            "The sealed payload was not in the expected form.",
        )
        .with_detail(format!("{e:#}"))
    })?;

    Ok((session, parsed))
}

#[cfg(test)]
pub(crate) mod testing {
    //! The browser half of the exchange, in Rust.
    //!
    //! This is what makes the protocol testable at all: the page's WebCrypto
    //! calls cannot run here, but the wire format they produce can be built
    //! exactly, and a server that opens this will open theirs. What stays
    //! unverified by the suite is the shape of the JavaScript calls, and
    //! pretending otherwise would be worse than saying so.

    use super::{Directions, SealedRequest, HKDF_INFO};
    use crate::crypto::aead::{self, KEY_SIZE};
    use hkdf::Hkdf;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::{EncodedPoint, PublicKey};
    use sha2::Sha256;
    use zeroize::Zeroizing;

    /// A client that has done the ECDH and holds both directional keys.
    pub(crate) struct Client {
        pub pubkey_hex: String,
        session_id: Vec<u8>,
        keys: Directions,
    }

    impl Client {
        /// Do what the page does on receiving an envelope.
        pub fn greet(node_pubkey_hex: &str, session_id_hex: &str) -> Self {
            let node_public =
                PublicKey::from_sec1_bytes(&hex::decode(node_pubkey_hex).unwrap()).unwrap();
            let secret = EphemeralSecret::random(&mut OsRng);
            let shared = secret.diffie_hellman(&node_public);
            let session_id = hex::decode(session_id_hex).unwrap();

            let mut okm = Zeroizing::new([0u8; KEY_SIZE * 2]);
            Hkdf::<Sha256>::new(Some(&session_id), shared.raw_secret_bytes())
                .expand(HKDF_INFO, okm.as_mut())
                .unwrap();

            let mut to_node = Zeroizing::new([0u8; KEY_SIZE]);
            let mut to_client = Zeroizing::new([0u8; KEY_SIZE]);
            to_node.copy_from_slice(&okm[..KEY_SIZE]);
            to_client.copy_from_slice(&okm[KEY_SIZE..]);

            Self {
                pubkey_hex: hex::encode(EncodedPoint::from(secret.public_key()).as_bytes()),
                session_id,
                keys: Directions { to_node, to_client },
            }
        }

        /// Seal a payload for the node, as the page's `sealRequest` does.
        pub fn seal(&self, session_id_hex: &str, plaintext: &[u8]) -> SealedRequest {
            let (nonce, ciphertext) =
                aead::seal(&self.keys.to_node, &self.session_id, plaintext).unwrap();

            SealedRequest {
                session_id: session_id_hex.to_string(),
                client_pubkey: self.pubkey_hex.clone(),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            }
        }

        /// Open a sealed reply, as the page's `openResponse` does.
        pub fn open(&self, sealed: &serde_json::Value) -> Zeroizing<Vec<u8>> {
            self.try_open(sealed).expect("the reply opens")
        }

        /// The same, for the cases that are meant to fail.
        pub fn try_open(&self, sealed: &serde_json::Value) -> Option<Zeroizing<Vec<u8>>> {
            aead::open(
                &self.keys.to_client,
                &self.session_id,
                &hex::decode(sealed["nonce"].as_str().unwrap()).unwrap(),
                &hex::decode(sealed["ciphertext"].as_str().unwrap()).unwrap(),
            )
            .ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Client;
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json::to_vec(&json!({ "hello": "world" })).unwrap()
    }

    #[test]
    fn a_payload_sealed_by_the_client_opens_on_the_node() {
        let session = EnvelopeSession::issue();
        let client = Client::greet(&session.public_key_hex(), &session.id_hex());
        let request = client.seal(&session.id_hex(), &payload());

        let opened = session
            .open(&request.client_pubkey, &request.nonce, &request.ciphertext)
            .unwrap();
        assert_eq!(opened.as_slice(), payload());
    }

    /// The reply direction, and the reason it exists: a seal key handed back in
    /// the clear would sit in whatever logs the request body was being kept out
    /// of.
    #[test]
    fn a_reply_sealed_by_the_node_opens_only_in_that_browser() {
        let session = EnvelopeSession::issue();
        let client = Client::greet(&session.public_key_hex(), &session.id_hex());

        let sealed = session
            .seal_for_client(&client.pubkey_hex, b"the seal key")
            .unwrap();
        assert_eq!(client.open(&sealed).as_slice(), b"the seal key");

        // Another browser's keypair derives a different pair of directions, so
        // the ciphertext is inert to it.
        let eavesdropper = Client::greet(&session.public_key_hex(), &session.id_hex());
        assert!(eavesdropper.try_open(&sealed).is_none());
    }

    /// The two directions must not share a key. If they did, a reply could be
    /// replayed to the node as a request.
    #[test]
    fn the_two_directions_use_different_keys() {
        let session = EnvelopeSession::issue();
        let client = Client::greet(&session.public_key_hex(), &session.id_hex());
        let keys = session.directions(&client.pubkey_hex).unwrap();

        assert_ne!(keys.to_node.as_slice(), keys.to_client.as_slice());

        // Concretely: what the node sealed for the browser does not open as a
        // request, even with the right envelope and the right AAD.
        let sealed = session
            .seal_for_client(&client.pubkey_hex, b"a reply")
            .unwrap();
        assert!(session
            .open(
                &client.pubkey_hex,
                sealed["nonce"].as_str().unwrap(),
                sealed["ciphertext"].as_str().unwrap()
            )
            .is_err());
    }

    /// The property the AAD buys: a body captured off one envelope is useless
    /// against the next.
    #[test]
    fn a_payload_sealed_for_another_envelope_does_not_open() {
        let first = EnvelopeSession::issue();
        let second = EnvelopeSession::issue();
        let client = Client::greet(&first.public_key_hex(), &first.id_hex());
        let request = client.seal(&first.id_hex(), &payload());

        assert!(second
            .open(&request.client_pubkey, &request.nonce, &request.ciphertext)
            .is_err());
    }

    /// The same node key, but the session id the ciphertext was bound to has
    /// been swapped. Only the AAD catches this.
    #[test]
    fn a_payload_bound_to_another_session_id_does_not_open() {
        let session = EnvelopeSession::issue();
        let other_id = EnvelopeSession::issue().id_hex();
        let client = Client::greet(&session.public_key_hex(), &other_id);
        let request = client.seal(&other_id, &payload());

        assert!(session
            .open(&request.client_pubkey, &request.nonce, &request.ciphertext)
            .is_err());
    }

    #[test]
    fn a_tampered_ciphertext_does_not_open() {
        let session = EnvelopeSession::issue();
        let client = Client::greet(&session.public_key_hex(), &session.id_hex());
        let request = client.seal(&session.id_hex(), &payload());

        let ct = &request.ciphertext;
        let flipped = format!(
            "{}{}",
            if ct.starts_with('a') { 'b' } else { 'a' },
            &ct[1..]
        );
        assert!(session
            .open(&request.client_pubkey, &request.nonce, &flipped)
            .is_err());
    }

    #[test]
    fn malformed_client_material_is_refused_rather_than_panicking() {
        let session = EnvelopeSession::issue();
        let client = Client::greet(&session.public_key_hex(), &session.id_hex());
        let request = client.seal(&session.id_hex(), &payload());

        assert!(session
            .open("not hex", &request.nonce, &request.ciphertext)
            .is_err());
        assert!(session
            .open(&hex::encode([1u8; 65]), &request.nonce, &request.ciphertext)
            .is_err());
        assert!(session
            .open(&request.client_pubkey, "zz", &request.ciphertext)
            .is_err());
        assert!(session
            .open(&request.client_pubkey, &request.nonce, "zz")
            .is_err());
        assert!(session.seal_for_client("not hex", b"reply").is_err());
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
}
