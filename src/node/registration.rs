//! Building the node's own `RegisterBlsKey` payload.
//!
//! # Why the node can sign most of its own registration
//!
//! The Portal's `POST /api/nodes/register` wants five fields, and only two of
//! them need a wallet:
//!
//! - `xpubkey` and `schnorr_sig` come from Horizon Wallet. The Schnorr half of
//!   the proof of possession is a BIP340 signature over
//!   `sha256("KONTOR_XONLY_TO_BLS_V1" || bls_pubkey)`, which needs the Taproot
//!   secret key. That key never leaves the wallet, so this is the one piece the
//!   node cannot produce for itself.
//! - `bls_pubkey`, `bls_sig` and `registration_signature` are all made with the
//!   BLS key — which the node holds, having imported it at onboarding. It builds
//!   them here.
//!
//! None of the five carry a nonce, a timestamp, or a server-issued challenge:
//! every one is a pure function of the two keys. A registration is therefore
//! replayable, which is what lets a node re-register itself unattended after the
//! Portal's database has been reset.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::clients::kontor_op::{
    build_signing_message, Inst, InstKind, SignerRef, REGISTER_BLS_KEY_GAS_LIMIT,
};
use crate::clients::portal::RegisterNodeRequest;
use crate::clients::PortalClient;
use crate::crypto::mnemonic::{ACCOUNT_INDEX_ENV, REGISTER_NEW_ACCOUNT_ENV};
use crate::crypto::{BitcoinNetwork, BlsKeyPair, MnemonicIdentity};

/// Prefix the Portal signs over to bind a BLS key to a Taproot identity.
///
/// Mirrors `BLS_BINDING_PREFIX` in Horizon Portal's `api/users.rs`.
const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_BLS_TO_XONLY_V1";

/// Hex length of a BLS12-381 min-sig public key (96 bytes, on G2).
const BLS_PUBKEY_HEX_LEN: usize = 192;

/// Hex length of a BIP340 Schnorr signature (64 bytes).
const SCHNORR_SIG_HEX_LEN: usize = 128;

/// Serialized length of a BIP32 extended key: version, depth, parent
/// fingerprint, child number, chain code, key.
const XPUB_PAYLOAD_LEN: usize = 4 + 1 + 4 + 4 + 32 + 33;

/// Offset of the 33-byte compressed public key inside that payload.
const XPUB_KEY_OFFSET: usize = 45;

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Derive the 32-byte x-only public key from an extended public key.
///
/// The Portal does this with `Xpub::from_str(..).public_key.x_only_public_key()`
/// and puts the result inside the message it verifies, so the two derivations
/// have to agree. For a well-formed xpub they do trivially: the serialized key
/// is already a compressed secp256k1 point, and x-only is that point minus its
/// `02`/`03` parity byte. Doing it by hand keeps `bitcoin` and its secp256k1
/// C bindings out of the node's dependency tree.
///
/// The derivation path is deliberately ignored — the account-level key *is* the
/// identity, exactly as the Portal treats it.
///
/// # Errors
/// If `xpub` is not valid base58check, is the wrong length, or does not carry a
/// compressed public key (an `xprv`, say, whose key field starts with `00`).
pub fn x_only_from_xpub(xpub: &str) -> Result<[u8; 32]> {
    let payload = base58check_decode(xpub).context("invalid extended public key")?;

    if payload.len() != XPUB_PAYLOAD_LEN {
        return Err(anyhow!(
            "extended public key must decode to {XPUB_PAYLOAD_LEN} bytes, got {}",
            payload.len()
        ));
    }

    let key = &payload[XPUB_KEY_OFFSET..];
    if key[0] != 0x02 && key[0] != 0x03 {
        return Err(anyhow!(
            "extended key does not hold a compressed public key (prefix {:#04x}); \
             an extended *private* key was probably passed",
            key[0]
        ));
    }

    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&key[1..]);
    Ok(x_only)
}

/// Decode a base58check string, verifying and stripping its 4-byte checksum.
fn base58check_decode(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(anyhow!("empty base58 string"));
    }

    // Big-endian base conversion: each character shifts the accumulator by one
    // base-58 digit. Inputs here are ~111 characters, so the quadratic cost is
    // irrelevant next to the Argon2 hash this runs alongside.
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.bytes() {
        let digit = BASE58_ALPHABET
            .iter()
            .position(|c| *c == ch)
            .ok_or_else(|| anyhow!("invalid base58 character {:?}", ch as char))?;

        let mut carry = digit;
        for byte in bytes.iter_mut().rev() {
            carry += 58 * (*byte as usize);
            *byte = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            bytes.insert(0, (carry % 256) as u8);
            carry /= 256;
        }
    }

    // A leading '1' is a zero digit, which the loop above cannot represent
    // because it carries nothing; base58check encodes each leading zero byte as
    // one such character.
    for _ in input.bytes().take_while(|c| *c == b'1') {
        bytes.insert(0, 0);
    }

    if bytes.len() < 5 {
        return Err(anyhow!("base58check payload is too short"));
    }

    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    let expected = Sha256::digest(Sha256::digest(payload));
    if checksum != &expected[..4] {
        return Err(anyhow!("base58check checksum mismatch"));
    }

    Ok(payload.to_vec())
}

/// The message whose BLS signature proves the BLS key agrees to be bound to
/// `x_only`.
///
/// Mirrors Horizon Portal's `verify_bls_binding`.
fn bls_binding_message(x_only: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + x_only.len());
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(x_only);
    msg
}

/// Build the full `POST /api/nodes/register` body for this node's BLS key.
///
/// `bls_sig` is recomputed rather than taken from the wallet: BLS signing is
/// deterministic, so the value is identical, and producing it here proves the
/// node actually holds the key it is about to register.
///
/// The op is signed with `nonce = 0` and `sponsored = true`, matching what the
/// Portal rebuilds in `verify_registration_signature`. Both are inside the
/// signed bytes — the registration has no account to draw a nonce from or gas
/// from yet, so the Portal publishes it and pays.
///
/// # Errors
/// If the wallet-supplied fields are malformed, if `bls_pubkey` is not this
/// node's own key, or if the op cannot be serialized.
pub fn build_registration_request(
    keypair: &BlsKeyPair,
    xpubkey: &str,
    bls_pubkey: &str,
    schnorr_sig: &str,
) -> Result<RegisterNodeRequest> {
    let bls_pubkey = bls_pubkey.trim().to_ascii_lowercase();
    let schnorr_sig = schnorr_sig.trim().to_ascii_lowercase();
    let xpubkey = xpubkey.trim();

    validate_hex_field(&bls_pubkey, BLS_PUBKEY_HEX_LEN, "bls_pubkey")?;
    validate_hex_field(&schnorr_sig, SCHNORR_SIG_HEX_LEN, "schnorr_sig")?;

    // The wallet account the operator picked must be the one whose BLS key this
    // node imported. Registering any other key would succeed on the Portal and
    // then leave the node looking up a public key it cannot sign for — the same
    // 404 it started from, one restart later.
    let own_pubkey = keypair.public_key_hex();
    if bls_pubkey != own_pubkey {
        return Err(anyhow!(
            "the wallet account's BLS key does not match this node's key.\n  \
             node:   {own_pubkey}\n  \
             wallet: {bls_pubkey}\n  \
             Select the wallet account this node's key was exported from."
        ));
    }

    let x_only = x_only_from_xpub(xpubkey)?;
    let bls_sig = keypair.sign_kontor_op_message(&bls_binding_message(&x_only))?;

    let inst = Inst {
        gas_limit: REGISTER_BLS_KEY_GAS_LIMIT,
        kind: InstKind::RegisterBlsKey {
            bls_pubkey: hex::decode(&bls_pubkey).context("decoding bls_pubkey")?,
            schnorr_sig: hex::decode(&schnorr_sig).context("decoding schnorr_sig")?,
            bls_sig: hex::decode(&bls_sig).context("decoding bls_sig")?,
        },
    };
    let message = build_signing_message(&SignerRef::XOnlyPubkey(x_only), 0, true, &inst)?;
    let registration_signature = keypair.sign_kontor_op_message(&message)?;

    Ok(RegisterNodeRequest {
        xpubkey: xpubkey.to_string(),
        bls_pubkey,
        schnorr_sig,
        bls_sig,
        registration_signature,
    })
}

/// Build the registration for a mnemonic-derived identity.
///
/// The wallet-driven path gets `xpubkey` and `schnorr_sig` from a browser; a
/// node holding the seed phrase signs the Schnorr half itself, and everything
/// downstream is the same code.
///
/// # Errors
/// If the Schnorr signature cannot be produced, or the request cannot be built.
pub fn build_self_registration(identity: &MnemonicIdentity) -> Result<RegisterNodeRequest> {
    // The Portal recovers the x-only key from the xpub and verifies both halves
    // of the proof of possession against it, while the node signs with the key
    // it derived directly. They are the same key by construction — this catches
    // the construction being wrong, here rather than as an opaque 400.
    let from_xpub = x_only_from_xpub(&identity.xpubkey)?;
    if from_xpub != identity.x_only {
        return Err(anyhow!(
            "the derived Taproot key does not match its own extended public key \
             (xpub carries {}, signing with {})",
            hex::encode(from_xpub),
            hex::encode(identity.x_only),
        ));
    }

    let schnorr_sig = identity.schnorr_binding_sig()?;
    build_registration_request(
        &identity.keypair,
        &identity.xpubkey,
        &identity.bls_pubkey(),
        &schnorr_sig,
    )
}

/// How many wallet accounts to probe when the configured one is unknown.
///
/// Only reached on the failure path, and only until something is found. Ten
/// covers every account a wallet realistically hands out before an operator
/// would have noticed something else was wrong.
///
/// Past it the scan finds nothing and the node registers, which is the
/// destructive outcome this whole path exists to avoid — so every message built
/// from a scan says how far it looked rather than implying it looked everywhere.
const ACCOUNT_SCAN_MAX: u32 = 10;

/// How the scan describes its own reach, for the messages that report it.
#[must_use]
pub fn account_scan_range() -> String {
    format!("accounts 0-{ACCOUNT_SCAN_MAX}")
}

/// A node the Portal knows, derived from the same mnemonic as this one.
#[derive(Debug, Clone)]
pub struct RegisteredSibling {
    pub account: u32,
    pub network: BitcoinNetwork,
    pub node_id: String,
    pub taproot_address: String,
}

impl std::fmt::Display for RegisteredSibling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "account {} ({}) -> {} ({})",
            self.account, self.network, self.node_id, self.taproot_address
        )
    }
}

/// Find identities from this mnemonic that the Portal has already registered.
///
/// # Why this runs before registering
///
/// A 404 on the configured account means one of two things: this node is new, or
/// the account index is wrong. Registering is right for the first and quietly
/// destructive for the second — it mints a *second* node while the real one
/// keeps the agreements, and the operator sees a node that works and does
/// nothing. Since every account of a mnemonic is one derivation away, the node
/// can simply go and look, and say which account it should have been.
///
/// Finding a sibling does not settle it, because one mnemonic legitimately backs
/// several nodes, one per account. What the scan produces is a list; whether that
/// list is fatal is [`REGISTER_NEW_ACCOUNT_ENV`]'s decision, and the caller's.
///
/// The configured account's own network is scanned first, then that account on
/// the other coin type: a wrong `KONTOR_STORAGE_NETWORK` produces exactly the
/// same symptom and costs one extra lookup to rule out.
///
/// Errors from individual probes are swallowed. This runs to explain a failure
/// that has already happened; a Portal that answers some lookups and not others
/// should not turn a clear diagnosis into an obscure one.
pub async fn find_registered_siblings(
    client: &PortalClient,
    identity: &MnemonicIdentity,
) -> Vec<RegisteredSibling> {
    let mut candidates: Vec<(u32, BitcoinNetwork)> = (0..=ACCOUNT_SCAN_MAX)
        .filter(|account| *account != identity.account)
        .map(|account| (account, identity.network))
        .collect();
    candidates.push((identity.account, identity.network.counterpart()));

    let mut found = Vec::new();
    for (account, network) in candidates {
        let Ok(sibling) = identity.sibling(account, network) else {
            continue;
        };
        if client.lookup_node(&sibling.bls_pubkey()).await.is_ok() {
            found.push(RegisteredSibling {
                account,
                network,
                node_id: sibling.node_id,
                taproot_address: sibling.taproot_address,
            });
        }
    }
    found
}

/// The error an operator sees when the configured account may not be the
/// registered one.
///
/// Fatal by default, because the two things it can mean are not equally
/// recoverable: a mistyped [`ACCOUNT_INDEX_ENV`] strands a running node's
/// agreements behind a second identity, while a genuine second node is one
/// environment variable away from starting. So the message names both readings
/// and the variable that picks between them.
#[must_use]
pub fn wrong_account_error(
    identity: &MnemonicIdentity,
    siblings: &[RegisteredSibling],
) -> anyhow::Error {
    let listed = siblings
        .iter()
        .map(|sibling| format!("    {sibling}"))
        .collect::<Vec<_>>()
        .join("\n");

    anyhow!(
        "No node is registered for {} = {} ({}).\n  \
           derived BLS key: {}\n  \
           derived address: {}\n\n  \
         This mnemonic does have registered nodes, on other accounts ({} checked):\n{}\n\n  \
         If this node should be one of those, set {} to its account. Registering \
         account {} instead would create a second node and leave that one's \
         agreements behind.\n\n  \
         If this really is a new node alongside them, set {}=1 to say so and it \
         will register account {} on the next start.",
        ACCOUNT_INDEX_ENV,
        identity.account,
        identity.network,
        identity.bls_pubkey(),
        identity.taproot_address,
        account_scan_range(),
        listed,
        ACCOUNT_INDEX_ENV,
        identity.account,
        REGISTER_NEW_ACCOUNT_ENV,
        identity.account,
    )
}

/// What the node prints when it registers a new account next to existing ones.
///
/// The operator has already said this is deliberate, so this is not a warning —
/// but the siblings are listed anyway, because the one thing that would make the
/// decision wrong is a list that does not look like the nodes they think they
/// run.
#[must_use]
pub fn new_account_notice(identity: &MnemonicIdentity, siblings: &[RegisteredSibling]) -> String {
    let listed = siblings
        .iter()
        .map(|sibling| format!("    {sibling}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{REGISTER_NEW_ACCOUNT_ENV} is set, so account {} registers as a new node \
         alongside this mnemonic's existing ones ({} checked):\n{}",
        identity.account,
        account_scan_range(),
        listed,
    )
}

/// Reject a hex field before it reaches the Portal, so a typo reads as a
/// message about the field rather than a 400 from somewhere else.
fn validate_hex_field(value: &str, expected_len: usize, field: &str) -> Result<()> {
    if value.len() != expected_len {
        return Err(anyhow!(
            "{field} must be {expected_len} hex characters, got {}",
            value.len()
        ));
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{field} is not valid hex"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP32 test vector 1, chain m — the canonical xpub, and the x-only key is
    /// its serialized public key with the parity byte dropped.
    const BIP32_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const BIP32_X_ONLY: &str = "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

    fn keypair() -> BlsKeyPair {
        BlsKeyPair::generate().unwrap()
    }

    #[test]
    fn derives_the_x_only_key_the_portal_would_derive() {
        let x_only = x_only_from_xpub(BIP32_XPUB).unwrap();
        assert_eq!(hex::encode(x_only), BIP32_X_ONLY);
    }

    #[test]
    fn surrounding_whitespace_is_not_accepted_by_the_decoder() {
        let err = x_only_from_xpub(&format!(" {BIP32_XPUB}")).unwrap_err();
        assert!(format!("{err:#}").contains("invalid base58 character"));
    }

    #[test]
    fn a_flipped_character_fails_the_checksum() {
        let mut broken = BIP32_XPUB.to_string();
        broken.pop();
        broken.push('9');
        let err = x_only_from_xpub(&broken).unwrap_err();
        assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");
    }

    #[test]
    fn a_character_outside_the_alphabet_is_rejected() {
        let err = x_only_from_xpub("xpub0OIl").unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid base58 character"),
            "{err:#}"
        );
    }

    #[test]
    fn an_empty_string_is_rejected() {
        let err = x_only_from_xpub("").unwrap_err();
        assert!(
            format!("{err:#}").contains("empty base58 string"),
            "{err:#}"
        );
    }

    /// A valid base58check string that simply is not 78 bytes — a Bitcoin
    /// address, here — must not be read as an extended key.
    #[test]
    fn a_short_payload_is_rejected() {
        let err = x_only_from_xpub("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap_err();
        assert!(
            format!("{err:#}").contains("must decode to 78 bytes"),
            "{err:#}"
        );
    }

    /// The xprv counterpart of the vector above: same length, same checksum
    /// rules, but its key field starts with the `00` padding byte.
    #[test]
    fn an_extended_private_key_is_rejected() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let err = x_only_from_xpub(xprv).unwrap_err();
        assert!(
            format!("{err:#}").contains("compressed public key"),
            "{err:#}"
        );
    }

    /// Leading zero bytes are encoded as leading '1' characters and have to
    /// survive the round trip, or the payload comes back short.
    #[test]
    fn leading_zero_bytes_are_preserved() {
        // 0x00 0x00 0x61 plus its checksum, encoded.
        let decoded = base58check_decode("11C33fie4").unwrap();
        assert_eq!(decoded, vec![0x00, 0x00, 0x61]);
    }

    #[test]
    fn the_binding_message_is_the_prefix_then_the_key() {
        let msg = bls_binding_message(&[9u8; 32]);
        assert!(msg.starts_with(BLS_BINDING_PREFIX));
        assert_eq!(&msg[BLS_BINDING_PREFIX.len()..], &[9u8; 32]);
    }

    #[test]
    fn builds_a_request_carrying_the_nodes_own_key() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap();

        assert_eq!(request.xpubkey, BIP32_XPUB);
        assert_eq!(request.bls_pubkey, keypair.public_key_hex());
        assert_eq!(request.schnorr_sig, "ab".repeat(64));
        assert_eq!(request.bls_sig.len(), 96);
        assert_eq!(request.registration_signature.len(), 96);
    }

    fn derived(account: u32) -> MnemonicIdentity {
        MnemonicIdentity::derive(&crate::crypto::MnemonicSettings::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
            BitcoinNetwork::Signet,
            account,
        ))
        .unwrap()
    }

    /// A mnemonic node fills in the two fields the wallet used to supply, and
    /// the result has to be indistinguishable from the wallet-driven one.
    #[test]
    fn a_self_registration_is_shaped_like_a_wallet_one() {
        let identity = derived(2);
        let request = build_self_registration(&identity).unwrap();

        assert_eq!(request.xpubkey, identity.xpubkey);
        assert_eq!(request.bls_pubkey, identity.bls_pubkey());
        assert_eq!(request.schnorr_sig.len(), SCHNORR_SIG_HEX_LEN);
        assert_eq!(request.bls_sig.len(), 96);
        assert_eq!(request.registration_signature.len(), 96);

        // The x-only key the Portal will recover from `xpubkey` is the one the
        // node signed with.
        assert_eq!(x_only_from_xpub(&request.xpubkey).unwrap(), identity.x_only);
    }

    /// Same property the wallet path has: no nonce, no timestamp, so a node can
    /// re-register itself unattended after a Portal reset.
    #[test]
    fn a_self_registration_is_deterministic() {
        let identity = derived(3);
        let first = build_self_registration(&identity).unwrap();
        let second = build_self_registration(&identity).unwrap();

        assert_eq!(first.schnorr_sig, second.schnorr_sig);
        assert_eq!(first.bls_sig, second.bls_sig);
        assert_eq!(first.registration_signature, second.registration_signature);
    }

    fn sibling_of(identity: &MnemonicIdentity) -> RegisteredSibling {
        RegisteredSibling {
            account: identity.account,
            network: identity.network,
            node_id: identity.node_id.clone(),
            taproot_address: identity.taproot_address.clone(),
        }
    }

    /// The message an operator acts on. It has to name the variable, the
    /// account they should have used, and its address.
    #[test]
    fn the_wrong_account_error_names_what_to_change() {
        let identity = derived(1);
        let real = derived(3);
        let siblings = vec![sibling_of(&real)];

        let rendered = wrong_account_error(&identity, &siblings).to_string();

        assert!(rendered.contains(ACCOUNT_INDEX_ENV), "{rendered}");
        assert!(rendered.contains("account 3"), "{rendered}");
        assert!(rendered.contains(&real.taproot_address), "{rendered}");
        assert!(rendered.contains(&identity.taproot_address), "{rendered}");
        assert!(rendered.contains("second node"), "{rendered}");
    }

    /// The same message has to serve the operator whose account index is right
    /// and who is simply adding a node — otherwise the only way out of a correct
    /// refusal is to guess that one exists.
    #[test]
    fn the_wrong_account_error_offers_the_way_out() {
        let rendered = wrong_account_error(&derived(4), &[sibling_of(&derived(2))]).to_string();

        assert!(rendered.contains(REGISTER_NEW_ACCOUNT_ENV), "{rendered}");
        assert!(rendered.contains("really is a new node"), "{rendered}");
    }

    /// Neither message may imply the scan looked everywhere: past account 10 it
    /// finds nothing, and "no siblings" would then read as proof there are none.
    #[test]
    fn both_messages_say_how_far_the_scan_looked() {
        let siblings = [sibling_of(&derived(2))];
        let range = account_scan_range();
        assert_eq!(range, "accounts 0-10");

        assert!(wrong_account_error(&derived(4), &siblings)
            .to_string()
            .contains(&range));
        assert!(new_account_notice(&derived(4), &siblings).contains(&range));
    }

    /// What an opted-in node prints. It is not a warning, but it has to list the
    /// siblings: a list that does not match the nodes the operator thinks they
    /// run is the one signal that the opt-in was a mistake.
    #[test]
    fn the_new_account_notice_lists_what_it_registers_alongside() {
        let existing = derived(2);
        let rendered = new_account_notice(&derived(4), &[sibling_of(&existing)]);

        assert!(rendered.contains(REGISTER_NEW_ACCOUNT_ENV), "{rendered}");
        assert!(rendered.contains("account 4"), "{rendered}");
        assert!(rendered.contains(&existing.node_id), "{rendered}");
        assert!(rendered.contains(&existing.taproot_address), "{rendered}");
    }

    /// The two signatures answer different questions — "this BLS key accepts
    /// that Taproot key" and "this BLS key authorizes that op" — so they must
    /// not come out the same.
    #[test]
    fn the_binding_and_the_op_are_signed_separately() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap();
        assert_ne!(request.bls_sig, request.registration_signature);
    }

    /// Same inputs, same bytes: this is what makes a registration replayable
    /// after the Portal's database is wiped.
    #[test]
    fn the_request_is_deterministic() {
        let keypair = keypair();
        let pubkey = keypair.public_key_hex();
        let first =
            build_registration_request(&keypair, BIP32_XPUB, &pubkey, &"ab".repeat(64)).unwrap();
        let second =
            build_registration_request(&keypair, BIP32_XPUB, &pubkey, &"ab".repeat(64)).unwrap();
        assert_eq!(first.bls_sig, second.bls_sig);
        assert_eq!(first.registration_signature, second.registration_signature);
    }

    #[test]
    fn hex_fields_are_normalized_to_lowercase() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex().to_ascii_uppercase(),
            &"AB".repeat(64),
        )
        .unwrap();
        assert_eq!(request.schnorr_sig, "ab".repeat(64));
    }

    #[test]
    fn a_foreign_bls_key_is_refused() {
        let mine = keypair();
        let other = keypair();
        let err = build_registration_request(
            &mine,
            BIP32_XPUB,
            &other.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match this node's key"),
            "{err:#}"
        );
    }

    #[test]
    fn a_wrong_length_schnorr_signature_is_refused() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, &keypair.public_key_hex(), "abcd")
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("schnorr_sig must be 128 hex characters"),
            "{err:#}"
        );
    }

    #[test]
    fn a_non_hex_schnorr_signature_is_refused() {
        let keypair = keypair();
        let err = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"zz".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("schnorr_sig is not valid hex"),
            "{err:#}"
        );
    }

    /// The length check has to come before the identity check, or a malformed
    /// key reads as "wrong wallet account" and sends the operator hunting for
    /// the wrong problem.
    #[test]
    fn a_wrong_length_bls_key_is_refused_as_a_length_problem() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, "abcd", &"ab".repeat(64)).unwrap_err();
        assert!(
            format!("{err:#}").contains("bls_pubkey must be 192 hex characters"),
            "{err:#}"
        );
    }

    #[test]
    fn a_non_hex_bls_key_is_refused() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, &"zz".repeat(96), &"ab".repeat(64))
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("bls_pubkey is not valid hex"),
            "{err:#}"
        );
    }

    #[test]
    fn a_malformed_xpub_is_refused() {
        let keypair = keypair();
        let err = build_registration_request(
            &keypair,
            "not-an-xpub",
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid extended public key"),
            "{err:#}"
        );
    }
}
