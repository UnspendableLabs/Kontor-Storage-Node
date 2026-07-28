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
use crate::crypto::BlsKeyPair;

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
