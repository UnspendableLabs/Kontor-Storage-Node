//! Mirrors of Kontor's operation types and the canonical signing message.
//!
//! Kontor verifies a BLS signature over
//! `KONTOR-OP-V1 || postcard((SignerRef, nonce, sponsored, &Inst))` — its own
//! `Inst::aggregate_signing_message`. The node reproduces those bytes rather
//! than depending on `indexer-types`, which drags in the whole indexer, so the
//! types below have to encode *identically* to the upstream ones.
//!
//! # What "identically" means here
//!
//! postcard writes an enum as the varint index of its variant followed by the
//! variant's fields, so **variant order is part of the wire format**. Every
//! variant Kontor declares is repeated here even when the node never builds it:
//! dropping one would shift the index of everything after it and silently
//! invalidate every signature the node produces. Fields of those unused
//! variants are only shaped closely enough to keep the derive happy — they are
//! never serialized.
//!
//! Checked against Kontor `core/indexer-types/src/lib.rs` at rev `80913826`
//! (the staking upgrade): variant order, the `KONTOR-OP-V1` prefix and the
//! `(SignerRef, nonce, sponsored, &Inst)` tuple are unchanged from `b8e4026`,
//! and `ContractAddress` still displays as `name_height_txindex` (the
//! `contract_address!` macro in `core/macros`).

use anyhow::{Context, Result};
use serde::Serialize;

/// Prefix for Kontor operation signing messages.
pub const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

/// Default gas limit for filestorage contract calls.
pub const DEFAULT_GAS_LIMIT: u64 = 100_000;

/// Gas limit baked into a `RegisterBlsKey` op.
///
/// Mirrors the Portal's `DEFAULT_BLSBULK_GAS_LIMIT`. It is inside the signed
/// bytes and the Portal rebuilds the message with its own constant, so the two
/// must agree exactly or `verify_registration_signature` rejects the op.
pub const REGISTER_BLS_KEY_GAS_LIMIT: u64 = 100_000;

/// Mirror of Kontor's `SignerRef` enum (`indexer-types`).
///
/// Both variants are constructed: `SignerId` once the node has one, and
/// `XOnlyPubkey` for the `RegisterBlsKey` op that *creates* the signer id, when
/// the Taproot key is the only identity the chain knows about.
#[derive(Serialize)]
pub enum SignerRef {
    SignerId(u64), // index 0
    /// Upstream this is a `secp256k1::XOnlyPublicKey`, whose non-human-readable
    /// `Serialize` is a `serialize_tuple(32)` — postcard writes the 32 bytes
    /// raw, with no length prefix. A `Vec<u8>` here would prepend a `0x20` and
    /// produce a message the Portal never reconstructs.
    XOnlyPubkey([u8; 32]), // index 1
}

/// Mirror of Kontor's `InstKind` enum (`indexer-types`).
///
/// `ContractAddress` is serialized via `DisplayFromStr` in Kontor, so `String`
/// here produces an identical postcard encoding; the same holds for the
/// `BuildProvenance` payloads, which are only present to keep the indices
/// aligned and are never constructed.
#[derive(Serialize)]
pub enum InstKind {
    #[allow(dead_code)]
    Publish {
        name: String,
        bytes: Vec<u8>,
        provenance: (),
    }, // index 0
    Call {
        contract: String,
        expr: String,
    }, // index 1
    #[allow(dead_code)]
    UpdateProvenance {
        contract: String,
        provenance: (),
    }, // index 2
    #[allow(dead_code)]
    Issuance, // index 3
    RegisterBlsKey {
        // index 4
        bls_pubkey: Vec<u8>,
        schnorr_sig: Vec<u8>,
        bls_sig: Vec<u8>,
    },
    #[allow(dead_code)]
    Sponsor, // index 5
}

/// Mirror of Kontor's `Inst` struct.
#[derive(Serialize)]
pub struct Inst {
    pub gas_limit: u64,
    pub kind: InstKind,
}

/// Build the canonical aggregate signing message for one op.
///
/// `KONTOR-OP-V1 || postcard((claim, nonce, sponsored, inst))`, byte-for-byte
/// Kontor's `Inst::aggregate_signing_message`. `sponsored` is *inside* the
/// signed bytes, so it has to match the aggregate the op ends up in: the node's
/// own calls are self-paid (`false`), while `RegisterBlsKey` is published by the
/// Portal on the node's behalf (`true`).
///
/// # Errors
/// If the payload cannot be postcard-encoded.
pub fn build_signing_message(
    claim: &SignerRef,
    nonce: u64,
    sponsored: bool,
    inst: &Inst,
) -> Result<Vec<u8>> {
    let op_bytes = postcard::to_allocvec(&(claim, nonce, sponsored, inst))
        .context("failed to serialize signing payload")?;
    let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
    msg.extend_from_slice(KONTOR_OP_PREFIX);
    msg.extend_from_slice(&op_bytes);
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The indices are the wire format. Pinning them here means a variant
    /// reordered while chasing an upstream change fails a test instead of
    /// failing every signature at runtime.
    #[test]
    fn variant_indices_match_kontor() {
        let call = Inst {
            gas_limit: 0,
            kind: InstKind::Call {
                contract: String::new(),
                expr: String::new(),
            },
        };
        // gas_limit 0, variant index, then two empty strings.
        assert_eq!(postcard::to_allocvec(&call).unwrap(), vec![0, 1, 0, 0]);

        let register = Inst {
            gas_limit: 0,
            kind: InstKind::RegisterBlsKey {
                bls_pubkey: vec![],
                schnorr_sig: vec![],
                bls_sig: vec![],
            },
        };
        assert_eq!(
            postcard::to_allocvec(&register).unwrap(),
            vec![0, 4, 0, 0, 0]
        );
    }

    /// The one encoding difference that cannot be caught by reading the enum:
    /// upstream's `XOnlyPublicKey` is a fixed-size tuple, so the 32 bytes go out
    /// raw. A length prefix here would be invisible until the Portal rejected
    /// the signature.
    #[test]
    fn x_only_pubkey_is_written_without_a_length_prefix() {
        let encoded = postcard::to_allocvec(&SignerRef::XOnlyPubkey([7u8; 32])).unwrap();
        assert_eq!(encoded.len(), 33, "variant index + 32 raw bytes");
        assert_eq!(encoded[0], 1, "XOnlyPubkey is variant 1");
        assert_eq!(&encoded[1..], &[7u8; 32]);
    }

    #[test]
    fn signer_id_is_variant_zero() {
        assert_eq!(
            postcard::to_allocvec(&SignerRef::SignerId(3)).unwrap(),
            vec![0, 3]
        );
    }

    #[test]
    fn the_message_starts_with_the_kontor_prefix() {
        let inst = Inst {
            gas_limit: 1,
            kind: InstKind::Issuance,
        };
        let msg = build_signing_message(&SignerRef::SignerId(0), 0, false, &inst).unwrap();
        assert!(msg.starts_with(KONTOR_OP_PREFIX));
        assert_eq!(&msg[KONTOR_OP_PREFIX.len()..], &[0, 0, 0, 0, 1, 3]);
    }

    /// `sponsored` rides inside the signed bytes, so the two flags must produce
    /// different messages — otherwise a self-paid call and a sponsored one
    /// would share a signature.
    #[test]
    fn sponsored_changes_the_message() {
        let inst = Inst {
            gas_limit: 1,
            kind: InstKind::Issuance,
        };
        let claim = SignerRef::SignerId(0);
        let self_paid = build_signing_message(&claim, 0, false, &inst).unwrap();
        let sponsored = build_signing_message(&claim, 0, true, &inst).unwrap();
        assert_ne!(self_paid, sponsored);
    }
}
