//! Deriving this node's whole identity from a BIP-39 mnemonic.
//!
//! # Why
//!
//! Without a mnemonic a node needs Horizon Wallet twice: once to export the BLS
//! key as `BLS_ENCRYPTED_BLOB`, and again — from a browser — to sign the Schnorr
//! half of the proof of possession that `POST /api/nodes/register` demands. A
//! container can do neither, so it can neither bootstrap itself nor recover
//! unattended after the Portal's database is reset.
//!
//! Hand the node the seed phrase and both keys fall out of it: the BLS key that
//! signs Kontor ops, and the Taproot key that owns it. That is every field of a
//! registration, so the node becomes self-sufficient.
//!
//! # The contract with Horizon Wallet
//!
//! Every constant here mirrors the wallet. A node that disagrees on any of them
//! derives a perfectly valid key that the Portal has simply never seen, which is
//! indistinguishable from a wrong account index until someone reads the logs.
//! The upstream sources are `pop_service_web.dart`, `address_service_web.dart`
//! and `Kontor-Portal-Client/src/bls-primitives.ts`; the tests at the bottom pin
//! that crate's own vectors so a dependency bump cannot drift silently.
//!
//! | | |
//! |---|---|
//! | seed | BIP-39, **empty passphrase** — the wallet never passes one |
//! | BLS path | `m/12381/{coin}/{index}/0` — EIP-2333, four levels, unhardened |
//! | Taproot path | `m/86'/{coin}'/{index}'/0/0` — BIP86, hardened |
//! | coin type | `0` mainnet, `1` testnet *and* signet |
//! | `{index}` | `account - 1`: the paths count from 0, the wallet from 1 |
//!
//! Note the account index is hardened in one path and not the other. That is not
//! a typo: EIP-2333 has no hardened/normal distinction at all, so its indices are
//! written bare, while BIP32 needs the tick.
//!
//! # Which account is "account 2"
//!
//! Horizon Wallet lists accounts from 1 while deriving them from 0, so its second
//! account is the one at index 1. Everything here — [`ACCOUNT_INDEX_ENV`], every
//! log line, `/admin`, the identity record — speaks the wallet's numbering, and
//! [`MnemonicSettings::derivation_index`] is the single place the offset is
//! applied. That is the whole reason it exists: an operator reading "Account 2"
//! off the wallet and typing `2` must get the same keys the wallet shows them,
//! and a node that resolved the offset anywhere else would derive a valid key
//! nobody has registered — the failure this module is built to avoid.

use anyhow::{anyhow, Context, Result};
use bip32::{DerivationPath, Prefix, XPrv};
use bip39::Mnemonic;
use blst::min_sig::SecretKey;
use k256::{
    elliptic_curve::{
        ops::MulByGenerator, point::DecompressPoint, sec1::ToEncodedPoint, PrimeField,
    },
    schnorr::SigningKey,
    AffinePoint, ProjectivePoint, Scalar,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::BlsKeyPair;

/// The seed phrase this node derives its identity from.
pub const MNEMONIC_ENV: &str = "KONTOR_STORAGE_MNEMONIC";

/// Which wallet account to derive, numbered as Horizon Wallet numbers it: the
/// first account is `1`, not `0`.
///
/// This is the variable an operator is most likely to get wrong — most live
/// nodes run on something other than the first account — hence the diagnosis in
/// [`crate::node::onboarding`] when the derived key is unknown, and hence the
/// refusal of `0` rather than a silent off-by-one derivation.
pub const ACCOUNT_INDEX_ENV: &str = "KONTOR_STORAGE_ACCOUNT_INDEX";

/// The wallet's first account, and so both the default for
/// [`ACCOUNT_INDEX_ENV`] and the bottom of the sibling scan in
/// [`crate::node::registration`].
pub const FIRST_ACCOUNT: u32 = 1;

/// Which Bitcoin network the wallet derived against.
pub const NETWORK_ENV: &str = "KONTOR_STORAGE_NETWORK";

/// Opt in to registering an account while other accounts of the same mnemonic
/// are already registered.
///
/// One mnemonic can back several nodes, one per account, so "a sibling account
/// is registered" is ambiguous: it is the symptom of a wrong
/// [`ACCOUNT_INDEX_ENV`] *and* what adding a second node legitimately looks
/// like. The node refuses by default because the first case is silently
/// destructive; this variable is how an operator says they meant the second.
pub const REGISTER_NEW_ACCOUNT_ENV: &str = "KONTOR_STORAGE_REGISTER_NEW_ACCOUNT";

/// EIP-2333's purpose level, from EIP-2334. Shared by every BLS key in the
/// Ethereum ecosystem and kept here for the same reason.
const BLS_PURPOSE: u32 = 12381;

/// The Portal binds a BLS key to a Taproot key in both directions. This is the
/// half the Taproot key signs; the other half lives in
/// [`crate::node::registration`].
const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_XONLY_TO_BLS_V1";

/// Tag for the BIP341 key tweak. Key-path-only, so there is no merkle root to
/// commit to — matching the Portal's `Address::p2tr(&secp, x_only, None, ..)`.
const TAP_TWEAK_TAG: &[u8] = b"TapTweak";

/// The network the wallet derived against.
///
/// Every network but mainnet shares a coin type and an extended key prefix, and
/// all but regtest share an address HRP as well — but they are kept apart so the
/// startup banner can echo back what the operator actually configured, and
/// because the Portal computes the whitelist address with *its* own
/// `PORTAL_BITCOIN_NETWORK`. A node whose HRP disagrees derives an address the
/// Portal will never look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    /// BIP44 coin type: `0` for mainnet, `1` for every test network.
    #[must_use]
    pub fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet | Self::Signet | Self::Regtest => 1,
        }
    }

    /// The version bytes an extended public key is serialized with.
    fn xpub_prefix(self) -> Prefix {
        match self {
            Self::Mainnet => Prefix::XPUB,
            // Regtest included: rust-bitcoin serializes it with the testnet
            // version bytes too, and `node_id` hashes this text.
            Self::Testnet | Self::Signet | Self::Regtest => Prefix::TPUB,
        }
    }

    /// The bech32 human-readable part of a segwit address.
    fn hrp(self) -> bech32::Hrp {
        match self {
            Self::Mainnet => bech32::hrp::BC,
            Self::Testnet | Self::Signet => bech32::hrp::TB,
            Self::Regtest => bech32::hrp::BCRT,
        }
    }

    /// The other coin type's network, for the diagnosis that rules out a
    /// misconfigured [`NETWORK_ENV`] before blaming the account index.
    #[must_use]
    pub fn counterpart(self) -> Self {
        match self {
            Self::Mainnet => Self::Signet,
            Self::Testnet | Self::Signet | Self::Regtest => Self::Mainnet,
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" => Ok(Self::Mainnet),
            "testnet" | "testnet4" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            other => Err(anyhow!(
                "{NETWORK_ENV} must be one of mainnet, testnet, signet, regtest (got {other:?})"
            )),
        }
    }
}

impl std::fmt::Display for BitcoinNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        };
        f.write_str(name)
    }
}

/// What the environment says to derive.
#[derive(Clone)]
pub struct MnemonicSettings {
    phrase: Zeroizing<String>,
    pub network: BitcoinNetwork,
    /// The wallet's account number, counting from [`FIRST_ACCOUNT`]. Carried in
    /// the operator's terms rather than the path's so that every message built
    /// from it names the account the wallet shows; the derivation converts once,
    /// in [`Self::derivation_index`].
    pub account: u32,
    /// Whether this node may register itself even though another account of the
    /// same mnemonic already has a node. See [`REGISTER_NEW_ACCOUNT_ENV`].
    pub allow_new_account: bool,
}

// Manual Debug impl: the phrase is the node's entire identity — every key in
// this module comes back from it — so it must never reach a log line.
impl std::fmt::Debug for MnemonicSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicSettings")
            .field("phrase", &"<redacted>")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("allow_new_account", &self.allow_new_account)
            .finish()
    }
}

impl MnemonicSettings {
    /// Build settings from a phrase already in hand.
    ///
    /// Test-only, as [`crate::crypto::BlsKeyPair::generate`] is: production
    /// reads the phrase from the environment and nowhere else, and the tests
    /// that need one would otherwise have to set a process-wide variable and
    /// serialize against every other test that reads it.
    ///
    /// # Panics
    /// If `account` is below [`FIRST_ACCOUNT`], which is not an account any
    /// operator can configure — see [`Self::from_env`].
    #[cfg(test)]
    #[must_use]
    pub fn new(phrase: impl Into<String>, network: BitcoinNetwork, account: u32) -> Self {
        assert!(
            account >= FIRST_ACCOUNT,
            "accounts count from {FIRST_ACCOUNT}, got {account}"
        );
        Self {
            phrase: Zeroizing::new(phrase.into()),
            network,
            account,
            allow_new_account: false,
        }
    }

    /// The same settings, opted in to registering alongside sibling accounts.
    #[cfg(test)]
    #[must_use]
    pub fn allowing_new_account(mut self) -> Self {
        self.allow_new_account = true;
        self
    }

    /// Read the mnemonic configuration, or `None` if this node is not in
    /// mnemonic mode.
    ///
    /// Read straight from the environment rather than declared as a clap field,
    /// exactly as `BLS_PASSWORD` is: a `Cli` field ends up in `--help` and in
    /// the `Debug` output `print_config_info` leans on.
    ///
    /// # Errors
    /// If the mnemonic is set but blank, or if the account index, the network,
    /// or the new-account opt-in is set to something unparseable.
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(raw) = std::env::var(MNEMONIC_ENV) else {
            return Ok(None);
        };

        // Normalize whitespace: a phrase pasted into a `.env` file or a
        // deployment console routinely picks up newlines or double spaces, and
        // BIP-39 hashes the phrase verbatim.
        let phrase = Zeroizing::new(raw.split_whitespace().collect::<Vec<_>>().join(" "));
        if phrase.is_empty() {
            return Err(anyhow!(
                "{MNEMONIC_ENV} is set but empty; unset it entirely to fall back to \
                 BLS_ENCRYPTED_BLOB"
            ));
        }

        let account = match std::env::var(ACCOUNT_INDEX_ENV) {
            Ok(value) => {
                let account = value.trim().parse::<u32>().with_context(|| {
                    format!("{ACCOUNT_INDEX_ENV} must be a positive integer (got {value:?})")
                })?;
                // Refused rather than read as the first account: `0` is what
                // someone types who believes this counts from 0, and the account
                // they meant is then one below every account they have. Deriving
                // *something* would hand them a key the Portal has never seen,
                // which is indistinguishable from a wrong mnemonic.
                if account < FIRST_ACCOUNT {
                    return Err(anyhow!(
                        "{ACCOUNT_INDEX_ENV} counts from {FIRST_ACCOUNT}, like Horizon Wallet: \
                         the first account is {FIRST_ACCOUNT}, not 0. Set it to the account \
                         number the wallet shows."
                    ));
                }
                account
            }
            Err(_) => FIRST_ACCOUNT,
        };

        let network = match std::env::var(NETWORK_ENV) {
            Ok(value) => BitcoinNetwork::parse(&value)?,
            Err(_) => BitcoinNetwork::Signet,
        };

        let allow_new_account = match std::env::var(REGISTER_NEW_ACCOUNT_ENV) {
            Ok(value) => parse_flag(&value, REGISTER_NEW_ACCOUNT_ENV)?,
            Err(_) => false,
        };

        Ok(Some(Self {
            phrase,
            network,
            account,
            allow_new_account,
        }))
    }

    /// The 0-based child index [`Self::account`] names, for the two derivation
    /// paths and nothing else.
    ///
    /// Saturating rather than `- 1`: every constructor refuses account 0, so the
    /// clamp is unreachable, but an underflow here would silently derive account
    /// `4294967295` — a perfectly valid key that no Portal has ever seen, which
    /// is the one failure mode this module cannot diagnose.
    #[must_use]
    pub fn derivation_index(&self) -> u32 {
        self.account.saturating_sub(FIRST_ACCOUNT)
    }

    /// The same mnemonic, pointed at a different account and network.
    ///
    /// Used to probe neighbouring accounts when the configured one turns out to
    /// be unknown to the Portal.
    #[must_use]
    pub fn at(&self, account: u32, network: BitcoinNetwork) -> Self {
        Self {
            phrase: self.phrase.clone(),
            network,
            account,
            allow_new_account: self.allow_new_account,
        }
    }
}

/// Parse a boolean environment variable.
///
/// Written out rather than `parse::<bool>()` because the values operators
/// actually type into a deployment console are `1` and `yes` at least as often
/// as `true`, and silently reading one of those as "off" would disarm the very
/// guard this flag exists to lift.
fn parse_flag(value: &str, name: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(anyhow!(
            "{name} must be one of 1, true, yes, on, 0, false, no, off (got {other:?})"
        )),
    }
}

/// What `/admin` may know about a mnemonic-derived node.
///
/// Carries no key material, so it can be cloned into the server state and
/// serialized to a browser. The Taproot address is the reason it exists: on a
/// node the Portal has not whitelisted yet, that string is the entire remaining
/// task, and reading it off a page beats grepping a container's logs.
#[derive(Clone, Debug)]
pub struct DerivedIdentityInfo {
    pub account: u32,
    pub network: BitcoinNetwork,
    pub taproot_address: String,
    pub node_id: String,
}

/// Every key and identifier this node needs, derived from the seed phrase.
pub struct MnemonicIdentity {
    pub keypair: BlsKeyPair,
    pub account: u32,
    pub network: BitcoinNetwork,
    /// Base58 extended public key of the Taproot leaf, as the wallet's
    /// `neutered().toBase58()` produces it. The Portal derives `node_id` from
    /// this exact string, so its prefix and depth are load-bearing.
    pub xpubkey: String,
    pub x_only: [u8; 32],
    /// The P2TR address a Portal admin has to whitelist.
    pub taproot_address: String,
    /// `node-<sha256(xpubkey)>`, mirroring the Portal's
    /// `derive_node_id_from_xpubkey`. Computed here so the node can ask about
    /// itself before it has any credential to log in with.
    pub node_id: String,
    schnorr: SigningKey,
    /// Kept so the node can derive its neighbours: when the Portal has never
    /// heard of this identity, the likeliest cause is a wrong account index, and
    /// the only way to say so is to go and look.
    settings: MnemonicSettings,
}

// Manual Debug impl: `schnorr` and the BLS secret inside `keypair` are secrets;
// everything else here is public by construction.
impl std::fmt::Debug for MnemonicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicIdentity")
            .field("account", &self.account)
            .field("network", &self.network)
            .field("xpubkey", &self.xpubkey)
            .field("taproot_address", &self.taproot_address)
            .field("node_id", &self.node_id)
            .field("keypair", &self.keypair)
            .finish()
    }
}

impl MnemonicIdentity {
    /// Derive the BLS key, the Taproot key, and everything named after them.
    ///
    /// # Errors
    /// If the phrase is not a valid English BIP-39 mnemonic (wrong word count,
    /// unknown word, or bad checksum), or if any derivation step rejects its
    /// input.
    pub fn derive(settings: &MnemonicSettings) -> Result<Self> {
        // The checksum is the whole reason to go through BIP-39 rather than
        // hashing the phrase directly: it turns a mistyped word into an error
        // here instead of a valid key nobody has ever registered.
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, &settings.phrase)
            .map_err(|e| anyhow!("{MNEMONIC_ENV} is not a valid BIP-39 mnemonic: {e}"))?;
        // Empty passphrase: the wallet calls `bip39.mnemonicToSeed(mnemonic)`
        // with one argument and never offers a 25th word.
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));

        let coin = settings.network.coin_type();
        // The one place the wallet's numbering becomes the path's: both keys of
        // an identity have to come from the same index, or the node registers a
        // BLS key its own Taproot key does not own.
        let index = settings.derivation_index();
        let keypair = derive_bls_keypair(seed.as_slice(), coin, index)?;

        let path: DerivationPath = format!("m/86'/{coin}'/{index}'/0/0")
            .parse()
            .context("building the BIP86 derivation path")?;
        let xprv = XPrv::derive_from_path(seed.as_slice(), &path)
            .map_err(|e| anyhow!("deriving the Taproot key: {e}"))?;

        let xpub = xprv.public_key();
        let xpubkey = xpub.to_string(settings.network.xpub_prefix());

        // x-only is the compressed point minus its parity byte, which is what
        // the Portal recovers from the xpub on its side.
        let compressed = xpub.to_bytes();
        let x_only: [u8; 32] = compressed[1..]
            .try_into()
            .expect("a compressed secp256k1 point is 33 bytes");

        let schnorr = SigningKey::from_bytes(&xprv.to_bytes())
            .map_err(|e| anyhow!("the derived Taproot key is not a valid signing key: {e}"))?;

        let taproot_address = p2tr_address(&x_only, settings.network)?;
        let node_id = derive_node_id(&xpubkey);

        Ok(Self {
            keypair,
            account: settings.account,
            network: settings.network,
            xpubkey,
            x_only,
            taproot_address,
            node_id,
            schnorr,
            settings: settings.clone(),
        })
    }

    /// The public half of this identity: what the operator UI is allowed to
    /// show, and the only part that outlives onboarding.
    #[must_use]
    pub fn info(&self) -> DerivedIdentityInfo {
        DerivedIdentityInfo {
            account: self.account,
            network: self.network,
            taproot_address: self.taproot_address.clone(),
            node_id: self.node_id.clone(),
        }
    }

    /// The same mnemonic's identity at another account, or on the other coin
    /// type.
    ///
    /// # Errors
    /// Only if derivation itself fails, which cannot happen once `self` exists —
    /// the phrase has already been validated.
    pub fn sibling(&self, account: u32, network: BitcoinNetwork) -> Result<Self> {
        Self::derive(&self.settings.at(account, network))
    }

    /// The BLS public key this identity registers under.
    #[must_use]
    pub fn bls_pubkey(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// Whether the operator has said this node is a new node on a mnemonic that
    /// already backs others. See [`REGISTER_NEW_ACCOUNT_ENV`].
    #[must_use]
    pub fn allows_new_account(&self) -> bool {
        self.settings.allow_new_account
    }

    /// The Schnorr half of the proof of possession: the Taproot key signing off
    /// on the BLS key it is about to be bound to.
    ///
    /// BIP340 over `sha256("KONTOR_XONLY_TO_BLS_V1" || bls_pubkey)`, verified by
    /// the Portal's `verify_schnorr_binding`. `sign_prehash` uses zero auxiliary
    /// randomness, so this is byte-identical to what the wallet produces and a
    /// registration stays the pure function of two keys that
    /// [`crate::node::registration`] documents.
    ///
    /// # Errors
    /// If the BLS public key is not valid hex, or BIP340 signing fails.
    pub fn schnorr_binding_sig(&self) -> Result<String> {
        let bls_pubkey = hex::decode(self.bls_pubkey()).context("decoding own BLS public key")?;

        let mut hasher = Sha256::new();
        hasher.update(SCHNORR_BINDING_PREFIX);
        hasher.update(&bls_pubkey);
        let digest: [u8; 32] = hasher.finalize().into();

        let sig =
            k256::schnorr::signature::hazmat::PrehashSigner::sign_prehash(&self.schnorr, &digest)
                .map_err(|e| anyhow!("signing the Schnorr binding: {e}"))?;

        Ok(hex::encode(sig.to_bytes()))
    }
}

/// Derive the BLS secret key at `m/12381/{coin}/{index}/0`.
///
/// `index` is the 0-based child index, not the wallet's account number — see
/// [`MnemonicSettings::derivation_index`].
///
/// `blst` implements EIP-2333 itself, so this is only the path. Note it stops at
/// four levels: EIP-2334's five-level `m/12381/3600/i/0/0` is an Ethereum
/// validator convention that Horizon Wallet does not follow.
fn derive_bls_keypair(seed: &[u8], coin: u32, index: u32) -> Result<BlsKeyPair> {
    let master = SecretKey::derive_master_eip2333(seed)
        .map_err(|e| anyhow!("EIP-2333 master key derivation failed: {e:?}"))?;

    let sk = [BLS_PURPOSE, coin, index, 0]
        .iter()
        .fold(master, |key, index| key.derive_child_eip2333(*index));

    let sk_hex = Zeroizing::new(hex::encode(sk.to_bytes()));
    BlsKeyPair::from_secret_key_hex(&sk_hex)
}

/// The key-path-only P2TR address for an internal key.
///
/// BIP341: tweak by `t = tagged_hash("TapTweak", x_only)` with no script tree,
/// then encode `(P + t·G).x` as a version-1 witness program. The Portal computes
/// the same address to check its whitelist, so an operator whitelisting what
/// this prints is whitelisting what the Portal will look for.
fn p2tr_address(x_only: &[u8; 32], network: BitcoinNetwork) -> Result<String> {
    // `lift_x`: the internal key is the point with this x and an even y.
    let x = k256::FieldBytes::from(*x_only);
    let internal = Option::<AffinePoint>::from(AffinePoint::decompress(&x, 0u8.into()))
        .ok_or_else(|| anyhow!("the derived Taproot key is not a point on secp256k1"))?;

    let tweak_bytes = tagged_hash(TAP_TWEAK_TAG, &[x_only.as_slice()]);
    // A tweak at or above the curve order is invalid rather than reducible.
    // Reaching it takes a ~1-in-2^128 hash collision, so this is a guard, not a
    // branch anyone will take.
    let tweak = Option::<Scalar>::from(Scalar::from_repr(k256::FieldBytes::from(tweak_bytes)))
        .ok_or_else(|| anyhow!("the TapTweak scalar is out of range"))?;

    let output = ProjectivePoint::from(internal) + ProjectivePoint::mul_by_generator(&tweak);
    let encoded = output.to_affine().to_encoded_point(true);
    let program = encoded
        .x()
        .ok_or_else(|| anyhow!("the tweaked Taproot key is the point at infinity"))?;

    bech32::segwit::encode_v1(network.hrp(), program.as_slice())
        .map_err(|e| anyhow!("encoding the Taproot address: {e}"))
}

/// BIP340's `tagged_hash`: `sha256(sha256(tag) || sha256(tag) || msg)`.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `node-<sha256(xpubkey)>`, mirroring the Portal's
/// `derive_node_id_from_xpubkey`. Note it hashes the base58 *text*, not the key
/// bytes, so the extended key's prefix and depth are part of the identifier.
#[must_use]
pub fn derive_node_id(xpubkey: &str) -> String {
    format!("node-{}", hex::encode(Sha256::digest(xpubkey.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// The 24-word phrase behind the `Kontor-Portal-Client` seed vector, so the
    /// BLS expectations below are that crate's own numbers rather than ours.
    /// Its BIP-39 seed is *not* `[0x00..0x3f]` — those tests derive from raw
    /// bytes — so the key vectors are asserted through [`derive_bls_keypair`]
    /// directly, and the phrase only exercises the wiring.
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    /// `[0x00, 0x01, .. 0x3f]`, the IKM every upstream vector starts from.
    fn upstream_seed() -> Vec<u8> {
        (0u8..64).collect()
    }

    fn settings(account: u32, network: BitcoinNetwork) -> MnemonicSettings {
        MnemonicSettings {
            phrase: Zeroizing::new(TEST_PHRASE.to_string()),
            network,
            account,
            allow_new_account: false,
        }
    }

    /// `deriveMasterSK` — `bls-primitives.test.ts`.
    #[test]
    fn master_key_matches_upstream_vector() {
        let master = SecretKey::derive_master_eip2333(&upstream_seed()).unwrap();
        assert_eq!(
            hex::encode(master.to_bytes()),
            "1377f4b2f2479c8f6ea40c3570b7c049cadc4a1cfc8081ebf28e572b80231886"
        );
    }

    /// `deriveBlsKey(seed, coinType, account)` — `bls-primitives.test.ts`. The
    /// `(1, 5)` case is the one that proves the account index reaches the path.
    #[test]
    fn bls_derivation_matches_upstream_vectors() {
        let seed = upstream_seed();
        for (coin, account, expected) in [
            (
                0,
                0,
                "600807b7d8e3d8cc9f980aa1937f55ae84dbe540358f026578b84fd231f95f56",
            ),
            (
                1,
                0,
                "403ec84ec266cc93809d5a4c576f9b60b44260c739202b857f24d4d47358461b",
            ),
            (
                1,
                5,
                "33f336ecc31dab1416993aa03ae859bccc1c18546f95f0ef60e015cf3441f219",
            ),
        ] {
            let master = SecretKey::derive_master_eip2333(&seed).unwrap();
            let sk = [BLS_PURPOSE, coin, account, 0]
                .iter()
                .fold(master, |key, index| key.derive_child_eip2333(*index));
            assert_eq!(
                hex::encode(sk.to_bytes()),
                expected,
                "coin {coin} account {account}"
            );
        }
    }

    /// The public key upstream reports for the mainnet account-0 key, which also
    /// pins the min-sig scheme: 96 bytes on G2, not 48.
    #[test]
    fn bls_public_key_matches_upstream_vector() {
        let keypair = derive_bls_keypair(&upstream_seed(), 0, 0).unwrap();
        let pubkey = keypair.public_key_hex();
        assert_eq!(pubkey.len(), 192);
        assert!(
            pubkey.starts_with("9251e095"),
            "unexpected public key {pubkey}"
        );
    }

    /// BIP32 test vector 1 belongs to this phrase; the Taproot leaf is what the
    /// wallet's `taprootChild.neutered().toBase58()` returns.
    #[test]
    fn taproot_identity_is_stable() {
        let identity = MnemonicIdentity::derive(&settings(1, BitcoinNetwork::Mainnet)).unwrap();

        assert!(
            identity.xpubkey.starts_with("xpub"),
            "mainnet must serialize as xpub, got {}",
            identity.xpubkey
        );
        assert!(
            identity.taproot_address.starts_with("bc1p"),
            "expected a mainnet P2TR address, got {}",
            identity.taproot_address
        );
        assert_eq!(identity.node_id, derive_node_id(&identity.xpubkey));
        assert!(identity.node_id.starts_with("node-"));
        assert_eq!(identity.node_id.len(), "node-".len() + 64);
    }

    /// BIP86's own test vector: this phrase, `m/86'/0'/0'/0/0`, first receive
    /// address. Reached here as the *first* account, which is what pins the
    /// offset at the bottom of the range where an off-by-one hides best.
    #[test]
    fn taproot_address_matches_bip86_vector() {
        let identity =
            MnemonicIdentity::derive(&settings(FIRST_ACCOUNT, BitcoinNetwork::Mainnet)).unwrap();
        assert_eq!(
            identity.taproot_address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            hex::encode(identity.x_only),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
    }

    /// The offset itself, pinned end to end and in both paths at once: the
    /// wallet's account 2 is the key at child index 1.
    ///
    /// Asserted against the paths spelled out here rather than against a stored
    /// vector, because what can silently break is the *conversion* — a node that
    /// applied it to one path and not the other would derive a BLS key its own
    /// Taproot key does not own, and the Portal would reject the binding with
    /// nothing in the message pointing back here.
    #[test]
    fn the_wallets_second_account_is_the_key_at_index_one() {
        let identity = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Mainnet)).unwrap();

        let seed = Mnemonic::parse_in_normalized(bip39::Language::English, TEST_PHRASE)
            .unwrap()
            .to_seed_normalized("");
        let path: DerivationPath = "m/86'/0'/1'/0/0".parse().unwrap();
        let xprv = XPrv::derive_from_path(seed, &path).unwrap();

        assert_eq!(identity.xpubkey, xprv.public_key().to_string(Prefix::XPUB));
        assert_eq!(
            identity.bls_pubkey(),
            derive_bls_keypair(&seed, 0, 1).unwrap().public_key_hex()
        );
        assert_eq!(settings(2, BitcoinNetwork::Mainnet).derivation_index(), 1);
    }

    /// Signet and testnet share a coin type, so they must derive the same keys —
    /// and differ from mainnet.
    #[test]
    fn signet_and_testnet_agree_and_differ_from_mainnet() {
        let signet = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Signet)).unwrap();
        let testnet = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Testnet)).unwrap();
        let mainnet = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Mainnet)).unwrap();

        assert_eq!(signet.bls_pubkey(), testnet.bls_pubkey());
        assert_eq!(signet.xpubkey, testnet.xpubkey);
        assert_ne!(signet.bls_pubkey(), mainnet.bls_pubkey());
        assert!(signet.xpubkey.starts_with("tpub"));
        assert!(signet.taproot_address.starts_with("tb1p"));
    }

    /// Each account is a different node. If this ever stops holding, two nodes
    /// on one mnemonic would fight over a single identity.
    #[test]
    fn accounts_derive_distinct_identities() {
        let two = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Signet)).unwrap();
        let three = MnemonicIdentity::derive(&settings(3, BitcoinNetwork::Signet)).unwrap();

        assert_ne!(two.bls_pubkey(), three.bls_pubkey());
        assert_ne!(two.xpubkey, three.xpubkey);
        assert_ne!(two.taproot_address, three.taproot_address);
        assert_ne!(two.node_id, three.node_id);
    }

    /// Derivation is a pure function of the settings — the node re-derives on
    /// every start and has to land on the same identity each time.
    #[test]
    fn derivation_is_deterministic() {
        let first = MnemonicIdentity::derive(&settings(3, BitcoinNetwork::Signet)).unwrap();
        let second = MnemonicIdentity::derive(&settings(3, BitcoinNetwork::Signet)).unwrap();

        assert_eq!(first.bls_pubkey(), second.bls_pubkey());
        assert_eq!(first.xpubkey, second.xpubkey);
        assert_eq!(
            first.schnorr_binding_sig().unwrap(),
            second.schnorr_binding_sig().unwrap()
        );
    }

    /// The signature the Portal's `verify_schnorr_binding` checks.
    ///
    /// Swept across accounts and both coin types rather than pinned to one
    /// identity, because BIP340 signs with the even-`y` half of the key: half
    /// the derived keys need their scalar negated first, and a single vector
    /// exercises only one of those two paths. Which one it lands on is a
    /// property of the phrase, so a one-identity test can pass while the other
    /// half of every real deployment fails at the Portal.
    #[test]
    fn schnorr_binding_verifies_against_the_x_only_key() {
        use bip32::XPub;
        use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

        let mut parities = std::collections::HashSet::new();

        for network in [BitcoinNetwork::Mainnet, BitcoinNetwork::Signet] {
            for account in FIRST_ACCOUNT..FIRST_ACCOUNT + 6 {
                let identity = MnemonicIdentity::derive(&settings(account, network)).unwrap();
                let sig_hex = identity.schnorr_binding_sig().unwrap();
                assert_eq!(sig_hex.len(), 128);

                let digest = tagged_preimage_digest(&identity);
                let verifying = VerifyingKey::from_bytes(&identity.x_only).unwrap();
                let sig = Signature::try_from(hex::decode(&sig_hex).unwrap().as_slice()).unwrap();

                verifying
                    .verify_prehash(&digest, &sig)
                    .unwrap_or_else(|e| panic!("{network} account {account}: {e}"));

                // The compressed prefix of the derived point: `02` even, `03`
                // odd. Only the odd ones exercise the negation.
                let xpub: XPub = identity.xpubkey.parse().unwrap();
                parities.insert(xpub.to_bytes()[0]);
            }
        }

        assert_eq!(
            parities.len(),
            2,
            "the sweep must land on both key parities, or it says nothing about the negation"
        );
    }

    fn tagged_preimage_digest(identity: &MnemonicIdentity) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SCHNORR_BINDING_PREFIX);
        hasher.update(hex::decode(identity.bls_pubkey()).unwrap());
        hasher.finalize().into()
    }

    #[test]
    fn bad_mnemonic_is_rejected() {
        let mut bad = settings(1, BitcoinNetwork::Signet);
        bad.phrase = Zeroizing::new("abandon abandon abandon".to_string());
        let err = MnemonicIdentity::derive(&bad).unwrap_err().to_string();
        assert!(err.contains("not a valid BIP-39 mnemonic"), "{err}");

        // Right length, wrong checksum: the last word carries it.
        let mut checksum = settings(1, BitcoinNetwork::Signet);
        checksum.phrase = Zeroizing::new(TEST_PHRASE.replace("about", "abandon"));
        let err = MnemonicIdentity::derive(&checksum).unwrap_err().to_string();
        assert!(err.contains("not a valid BIP-39 mnemonic"), "{err}");
    }

    #[test]
    fn network_parsing_accepts_the_documented_names() {
        assert_eq!(
            BitcoinNetwork::parse("mainnet").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            BitcoinNetwork::parse(" SIGNET ").unwrap(),
            BitcoinNetwork::Signet
        );
        assert_eq!(
            BitcoinNetwork::parse("testnet4").unwrap(),
            BitcoinNetwork::Testnet
        );
        assert_eq!(
            BitcoinNetwork::parse("regtest").unwrap(),
            BitcoinNetwork::Regtest
        );
        let err = BitcoinNetwork::parse("mainet").unwrap_err().to_string();
        assert!(err.contains("mainnet, testnet, signet, regtest"), "{err}");
    }

    /// Regtest derives the same keys as signet — same coin type — and differs
    /// only in the address, which is the one field the Portal matches against
    /// its whitelist. Getting that wrong would make a regtest node's
    /// registration unwhitelistable rather than merely wrong.
    #[test]
    fn regtest_shares_signet_keys_and_differs_only_in_the_address() {
        let regtest = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Regtest)).unwrap();
        let signet = MnemonicIdentity::derive(&settings(2, BitcoinNetwork::Signet)).unwrap();

        assert_eq!(regtest.bls_pubkey(), signet.bls_pubkey());
        assert_eq!(regtest.xpubkey, signet.xpubkey);
        assert!(
            regtest.taproot_address.starts_with("bcrt1p"),
            "expected a regtest P2TR address, got {}",
            regtest.taproot_address
        );
        assert_ne!(regtest.taproot_address, signet.taproot_address);
    }

    /// The banner and the `/admin` status both echo this back, and the string
    /// has to be the one the operator typed into `KONTOR_STORAGE_NETWORK`.
    #[test]
    fn networks_display_as_their_configured_names() {
        for (network, name) in [
            (BitcoinNetwork::Mainnet, "mainnet"),
            (BitcoinNetwork::Testnet, "testnet"),
            (BitcoinNetwork::Signet, "signet"),
            (BitcoinNetwork::Regtest, "regtest"),
        ] {
            assert_eq!(network.to_string(), name);
            assert_eq!(BitcoinNetwork::parse(name).unwrap(), network);
        }
    }

    #[test]
    fn counterpart_crosses_the_coin_type() {
        assert_eq!(BitcoinNetwork::Mainnet.counterpart().coin_type(), 1);
        assert_eq!(BitcoinNetwork::Signet.counterpart().coin_type(), 0);
        assert_eq!(BitcoinNetwork::Testnet.counterpart().coin_type(), 0);
        assert_eq!(BitcoinNetwork::Regtest.counterpart().coin_type(), 0);
    }

    #[test]
    fn at_keeps_the_phrase_and_swaps_the_rest() {
        let base = settings(2, BitcoinNetwork::Signet).allowing_new_account();
        let moved = base.at(7, BitcoinNetwork::Mainnet);

        assert_eq!(moved.account, 7);
        assert_eq!(moved.network, BitcoinNetwork::Mainnet);
        // The opt-in belongs to the node, not to the account being probed: a
        // sibling derived for the scan is the same operator's decision.
        assert!(moved.allow_new_account);
        assert_eq!(
            MnemonicIdentity::derive(&moved).unwrap().bls_pubkey(),
            MnemonicIdentity::derive(&settings(7, BitcoinNetwork::Mainnet))
                .unwrap()
                .bls_pubkey()
        );
    }

    /// `MnemonicSettings` and `MnemonicIdentity` both hold secrets and both get
    /// logged on the error paths.
    #[test]
    fn debug_impls_hide_the_secrets() {
        let settings = settings(2, BitcoinNetwork::Signet);
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("abandon"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");

        let identity = MnemonicIdentity::derive(&settings).unwrap();
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains("abandon"), "{rendered}");
        assert!(rendered.contains(&identity.node_id), "{rendered}");
    }

    /// A guard against clearing the wrong variables between the env tests.
    struct EnvGuard;

    impl EnvGuard {
        fn set(vars: &[(&str, &str)]) -> Self {
            Self::clear();
            for (key, value) in vars {
                std::env::set_var(key, value);
            }
            Self
        }

        fn clear() {
            for key in [
                MNEMONIC_ENV,
                ACCOUNT_INDEX_ENV,
                NETWORK_ENV,
                REGISTER_NEW_ACCOUNT_ENV,
            ] {
                std::env::remove_var(key);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            Self::clear();
        }
    }

    #[test]
    #[serial]
    fn from_env_is_none_without_a_mnemonic() {
        let _guard = EnvGuard::set(&[(ACCOUNT_INDEX_ENV, "2")]);
        assert!(MnemonicSettings::from_env().unwrap().is_none());
    }

    #[test]
    #[serial]
    fn from_env_defaults_to_signet_and_the_first_account() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE)]);
        let settings = MnemonicSettings::from_env().unwrap().unwrap();
        assert_eq!(settings.account, FIRST_ACCOUNT);
        assert_eq!(settings.derivation_index(), 0);
        assert_eq!(settings.network, BitcoinNetwork::Signet);
    }

    /// The variable is the wallet's account number, so it must survive the trip
    /// through the environment unshifted: what an operator reads off Horizon
    /// Wallet and types here is what the node reports back and derives from.
    #[test]
    #[serial]
    fn from_env_reads_the_account_in_the_wallets_numbering() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE), (ACCOUNT_INDEX_ENV, "2")]);
        let settings = MnemonicSettings::from_env().unwrap().unwrap();

        assert_eq!(settings.account, 2);
        assert_eq!(settings.derivation_index(), 1);

        let identity = MnemonicIdentity::derive(&settings).unwrap();
        assert_eq!(identity.account, 2);
        assert_eq!(
            identity.bls_pubkey(),
            MnemonicIdentity::derive(&settings.at(2, BitcoinNetwork::Signet))
                .unwrap()
                .bls_pubkey()
        );
        assert_ne!(
            identity.bls_pubkey(),
            MnemonicIdentity::derive(&settings.at(FIRST_ACCOUNT, BitcoinNetwork::Signet))
                .unwrap()
                .bls_pubkey(),
            "the account read from the environment must not collapse onto the first one"
        );
    }

    #[test]
    #[serial]
    fn from_env_normalizes_pasted_whitespace() {
        let messy = format!("  {}  ", TEST_PHRASE.replace(' ', "\n  "));
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, &messy), (ACCOUNT_INDEX_ENV, " 3 ")]);

        let settings = MnemonicSettings::from_env().unwrap().unwrap();
        assert_eq!(settings.phrase.as_str(), TEST_PHRASE);
        assert_eq!(settings.account, 3);
        MnemonicIdentity::derive(&settings).unwrap();
    }

    #[test]
    #[serial]
    fn from_env_rejects_a_blank_mnemonic() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, "   ")]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();
        assert!(err.contains(MNEMONIC_ENV), "{err}");
    }

    #[test]
    #[serial]
    fn from_env_rejects_a_bad_account_index() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE), (ACCOUNT_INDEX_ENV, "two")]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();
        assert!(err.contains(ACCOUNT_INDEX_ENV), "{err}");

        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE), (ACCOUNT_INDEX_ENV, "-1")]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();
        assert!(err.contains(ACCOUNT_INDEX_ENV), "{err}");
    }

    /// `0` is the one wrong value that would otherwise derive something: it is
    /// what an operator types who believes this counts from 0, and reading it as
    /// the first account would shift their whole deployment down by one.
    #[test]
    #[serial]
    fn from_env_rejects_account_zero_rather_than_shifting_it() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE), (ACCOUNT_INDEX_ENV, "0")]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();

        assert!(err.contains(ACCOUNT_INDEX_ENV), "{err}");
        assert!(err.contains("first account is 1"), "{err}");
    }

    /// Defaulting this to `false` is what keeps the sibling guard armed on every
    /// node that has not explicitly asked for a second identity.
    #[test]
    #[serial]
    fn from_env_defaults_to_refusing_a_new_account() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE)]);
        assert!(
            !MnemonicSettings::from_env()
                .unwrap()
                .unwrap()
                .allow_new_account
        );
    }

    /// The values an operator actually types into a deployment console. Reading
    /// any of them as "off" would leave the node refusing to start with no way
    /// out, which is the failure this flag exists to fix.
    #[test]
    #[serial]
    fn from_env_accepts_the_usual_spellings_of_yes() {
        for value in ["1", "true", "TRUE", " yes ", "on"] {
            let _guard = EnvGuard::set(&[
                (MNEMONIC_ENV, TEST_PHRASE),
                (REGISTER_NEW_ACCOUNT_ENV, value),
            ]);
            let settings = MnemonicSettings::from_env().unwrap().unwrap();
            assert!(settings.allow_new_account, "{value:?}");
        }

        for value in ["0", "false", "no", "off", ""] {
            let _guard = EnvGuard::set(&[
                (MNEMONIC_ENV, TEST_PHRASE),
                (REGISTER_NEW_ACCOUNT_ENV, value),
            ]);
            let settings = MnemonicSettings::from_env().unwrap().unwrap();
            assert!(!settings.allow_new_account, "{value:?}");
        }
    }

    /// A typo must not read as "off": that would silently re-arm a guard the
    /// operator believes they lifted, and the node would refuse to start with an
    /// error naming a variable they have already set.
    #[test]
    #[serial]
    fn from_env_rejects_an_unparseable_new_account_flag() {
        let _guard = EnvGuard::set(&[
            (MNEMONIC_ENV, TEST_PHRASE),
            (REGISTER_NEW_ACCOUNT_ENV, "ouiiii"),
        ]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();
        assert!(err.contains(REGISTER_NEW_ACCOUNT_ENV), "{err}");
    }

    #[test]
    #[serial]
    fn from_env_rejects_an_unknown_network() {
        let _guard = EnvGuard::set(&[(MNEMONIC_ENV, TEST_PHRASE), (NETWORK_ENV, "mainet")]);
        let err = MnemonicSettings::from_env().unwrap_err().to_string();
        assert!(err.contains(NETWORK_ENV), "{err}");
    }
}
