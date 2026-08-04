//! The part of a node's identity that is not a secret.
//!
//! # Why this type exists
//!
//! A node needs the seed phrase exactly once: to derive its keys. After that,
//! every ongoing obligation is served by the BLS key alone plus a handful of
//! strings — and those strings are all public. The Portal publishes them, the
//! chain records them, `/admin` displays them.
//!
//! The one that looks like it should be secret is [`PublicIdentity::schnorr_binding_sig`].
//! It is not. It is a BIP340 signature the Taproot key makes over a fixed digest
//! of the BLS public key, and [`crate::node::registration`] documents that a
//! registration carries no nonce, no timestamp and no challenge — the Portal
//! accepts the same bytes forever. Signing it once at setup and writing it down
//! is therefore not a shortcut around holding the key; it is the whole of what
//! holding the key was ever used for here.
//!
//! That is what lets a node throw the mnemonic away and still register itself,
//! re-register after a Portal database reset, and prove which Taproot account it
//! belongs to — with nothing on disk that could move a coin.
//!
//! # What is deliberately absent
//!
//! - **The x-only key.** Recoverable from [`PublicIdentity::xpubkey`] with
//!   [`crate::node::registration::x_only_from_xpub`]. A second copy could drift
//!   from the first, and there would be no way to tell which one was right.
//! - **The seed, the Taproot secret, the BLS secret.** The first two are gone
//!   after setup; the third lives sealed in [`crate::crypto::keystore`].

use serde::{Deserialize, Serialize};

use crate::crypto::mnemonic::BitcoinNetwork;

/// Everything a node needs to speak for its Taproot account without holding the
/// key to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    /// The wallet's account number, as Horizon Wallet displays it (1-based).
    pub account: u32,
    pub network: BitcoinNetwork,
    /// Base58 extended public key of the Taproot leaf. The Portal derives
    /// `node_id` from this exact string, so its prefix and depth are
    /// load-bearing.
    pub xpubkey: String,
    /// The P2TR address a Portal admin has to whitelist.
    pub taproot_address: String,
    /// `node-<sha256(xpubkey)>`, mirroring the Portal's
    /// `derive_node_id_from_xpubkey`.
    pub node_id: String,
    /// The BLS key this identity registers under. Carried so `/admin` and the
    /// Portal lookup work on a node that has not been unsealed, and so
    /// unsealing can check that the key it opened is the one this record
    /// describes.
    pub bls_pubkey: String,
    /// The Schnorr half of the proof of possession, precomputed. See the module
    /// documentation for why storing it is sound.
    pub schnorr_binding_sig: String,
}

impl PublicIdentity {
    /// A one-line summary for logs and the startup banner.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (account {}, {})",
            self.node_id, self.account, self.network
        )
    }
}

/// A syntactically valid identity for tests that need one but do not care what
/// it says. Lives outside `mod tests` so the keystore's tests can reach it.
#[cfg(test)]
#[must_use]
pub(crate) fn sample() -> PublicIdentity {
    PublicIdentity {
        account: 2,
        network: BitcoinNetwork::Signet,
        xpubkey: "tpubDCBWBScQPGv4Xk3JSbhw6wYYpayMjb2eAYyArpbSqQTbLDpphHGAetB6VQgVeftLML8vDSUEWcC2xDi3qJJ3YCDChJDvqVzpgoYSuT52MhJ".to_string(),
        taproot_address: "tb1p8sxwsvwx2wq0kkl4qgm5nqvmvzp2mnzr7ck0aqz5vqc9wr7jsq2q6rvj7x".to_string(),
        node_id: "node-abc123".to_string(),
        bls_pubkey: "aa".repeat(96),
        schnorr_binding_sig: "bb".repeat(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_round_trips_through_json() {
        let identity = sample();
        let encoded = serde_json::to_string(&identity).unwrap();
        let decoded: PublicIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, identity);
    }

    /// The network must land in the file as a name a human can read, not as a
    /// variant index — the record exists to be understood at 3am.
    #[test]
    fn the_network_is_stored_by_name() {
        let encoded = serde_json::to_string(&sample()).unwrap();
        assert!(encoded.contains(r#""network":"signet""#), "{encoded}");
    }

    #[test]
    fn an_unknown_network_is_refused_rather_than_defaulted() {
        let encoded = serde_json::to_string(&sample())
            .unwrap()
            .replace(r#""network":"signet""#, r#""network":"dogecoin""#);

        let err = serde_json::from_str::<PublicIdentity>(&encoded).unwrap_err();
        assert!(err.to_string().contains("dogecoin"), "{err}");
    }

    #[test]
    fn summary_names_the_node_and_its_account() {
        let summary = sample().summary();
        assert!(summary.contains("node-abc123"), "{summary}");
        assert!(summary.contains("account 2"), "{summary}");
        assert!(summary.contains("signet"), "{summary}");
    }
}
