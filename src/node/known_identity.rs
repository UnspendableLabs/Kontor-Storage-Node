//! Remembering which identity this node has already run as.
//!
//! # Why a node has to keep this
//!
//! A 404 from the Portal's lookup means one of three things: this node is new,
//! its account index is wrong, or the Portal forgot it. The first two are told
//! apart by scanning sibling accounts — see
//! [`crate::node::registration::find_registered_siblings`] — but the third is
//! invisible to that scan, and it collides with the second head-on.
//!
//! Two nodes, accounts 2 and 3, one mnemonic. The Portal's database is reset;
//! both take a 404. Whichever restarts first finds no sibling and re-registers.
//! The other then finds its neighbour registered, which is exactly what a
//! mistyped account index looks like, and refuses to start. Unattended recovery
//! — the reason the node derives its own keys at all — would work for the first
//! node of a deployment and no other.
//!
//! Nothing the Portal can be asked settles it, because the distinction is about
//! this node's own past rather than the Portal's present. So the node writes
//! down the identity it onboarded under, and reads it back on the way up: a
//! 404 on an identity we have already run as is a Portal that forgot us, and
//! re-registering is recovery rather than a second node.
//!
//! # Where it lives, and what happens without it
//!
//! In `storage_dir`, alongside the files the node serves — the one directory a
//! node must already keep across restarts to be worth anything. A node whose
//! `storage_dir` is ephemeral gets the old behaviour (refuse and ask), which is
//! the safe direction.
//!
//! The record speaks for exactly one `node_id`. On that one it permits a
//! registration the node would otherwise refuse; on any other it does the
//! opposite and *causes* the refusal, including where the sibling scan comes
//! back empty — a reset plus a mistyped account index erases the Portal-side
//! evidence, leaving the record as the only thing that still knows this node is
//! not new. Either way [`crate::crypto::mnemonic::REGISTER_NEW_ACCOUNT_ENV`]
//! remains the operator's override.
//!
//! It holds nothing secret. Every field is either public on the Portal or
//! derivable from the mnemonic, so a leaked copy tells an attacker what
//! `/admin` already shows.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::crypto::MnemonicIdentity;

/// File name inside `storage_dir`. Dotted, like `.portal-daemon.lock`, since it
/// is bookkeeping rather than served content.
const FILE_NAME: &str = ".node-identity.json";

/// The identity this node last onboarded under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownIdentity {
    /// `node-<sha256(xpubkey)>`. The field that actually decides: it commits to
    /// the whole derivation, so it only matches when every constant — seed,
    /// path, coin type, account — is the one that produced the registered node.
    pub node_id: String,
    pub account: u32,
    /// Stored as its configured name (`signet`, `mainnet`, …) so the file stays
    /// readable by whoever is debugging a node at 3am.
    pub network: String,
    /// Not load-bearing; recorded so a mismatch can be reported in the terms an
    /// operator sees everywhere else.
    pub bls_pubkey: String,
}

impl KnownIdentity {
    fn path(storage_dir: &Path) -> PathBuf {
        storage_dir.join(FILE_NAME)
    }

    /// Read the recorded identity, or `None` if this node has never onboarded
    /// here.
    ///
    /// A corrupt or unreadable file is `None` rather than an error. `None` is
    /// the state every node was in before this file existed, so failing to read
    /// it falls back to the old behaviour — the node loses the automatic
    /// recovery and the extra refusal alike — whereas failing *closed* on a
    /// truncated write would strand a node that is otherwise perfectly fine.
    #[must_use]
    pub async fn load(storage_dir: &Path) -> Option<Self> {
        let path = Self::path(storage_dir);
        let raw = tokio::fs::read(&path).await.ok()?;
        match serde_json::from_slice::<Self>(&raw) {
            Ok(record) => Some(record),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ignoring an unreadable node identity record"
                );
                None
            }
        }
    }

    /// Record the identity this node just onboarded under.
    ///
    /// # Errors
    /// If the file cannot be written. Callers treat that as a warning: a node
    /// that is up and running should not be brought down by bookkeeping, and
    /// the cost of losing it is one refused registration after a Portal reset.
    pub async fn store(storage_dir: &Path, identity: &MnemonicIdentity) -> Result<()> {
        let record = Self {
            node_id: identity.node_id.clone(),
            account: identity.account,
            network: identity.network.to_string(),
            bls_pubkey: identity.bls_pubkey(),
        };

        let path = Self::path(storage_dir);
        let encoded = serde_json::to_vec_pretty(&record).context("encoding the identity record")?;
        tokio::fs::write(&path, encoded)
            .await
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Whether this record names the identity now being derived.
    #[must_use]
    pub fn matches(&self, identity: &MnemonicIdentity) -> bool {
        self.node_id == identity.node_id
    }
}

/// Record the identity, logging rather than failing if it cannot be written.
///
/// Called on the way up from a node that has just onboarded, where the write is
/// the least important thing that happened.
pub async fn remember(storage_dir: &Path, identity: &MnemonicIdentity) {
    if let Err(e) = KnownIdentity::store(storage_dir, identity).await {
        tracing::warn!(
            error = %format!("{e:#}"),
            "could not record this node's identity; a Portal reset will need \
             KONTOR_STORAGE_REGISTER_NEW_ACCOUNT to recover"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{BitcoinNetwork, MnemonicSettings};
    use tempfile::tempdir;

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";

    fn identity(account: u32) -> MnemonicIdentity {
        MnemonicIdentity::derive(&MnemonicSettings::new(
            TEST_PHRASE,
            BitcoinNetwork::Signet,
            account,
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn nothing_is_remembered_before_the_first_onboarding() {
        let dir = tempdir().unwrap();
        assert!(KnownIdentity::load(dir.path()).await.is_none());
    }

    /// The round trip that makes recovery work: what onboarding wrote is what
    /// the next start reads back.
    #[tokio::test]
    async fn a_stored_identity_is_recognised_on_the_next_start() {
        let dir = tempdir().unwrap();
        let identity = identity(2);

        KnownIdentity::store(dir.path(), &identity).await.unwrap();
        let record = KnownIdentity::load(dir.path()).await.unwrap();

        assert!(record.matches(&identity));
        assert_eq!(record.account, 2);
        assert_eq!(record.network, "signet");
        assert_eq!(record.bls_pubkey, identity.bls_pubkey());
    }

    /// The whole point of keying on `node_id`: a different account is a
    /// different node, and the record must not vouch for it.
    #[tokio::test]
    async fn a_record_does_not_vouch_for_another_account() {
        let dir = tempdir().unwrap();
        KnownIdentity::store(dir.path(), &identity(2))
            .await
            .unwrap();

        let record = KnownIdentity::load(dir.path()).await.unwrap();
        assert!(!record.matches(&identity(3)));
    }

    /// Same account, other coin type — the case a wrong `KONTOR_STORAGE_NETWORK`
    /// produces. The xpub differs, so the node id does too.
    #[tokio::test]
    async fn a_record_does_not_vouch_for_another_network() {
        let dir = tempdir().unwrap();
        let signet = identity(2);
        KnownIdentity::store(dir.path(), &signet).await.unwrap();

        let mainnet = MnemonicIdentity::derive(&MnemonicSettings::new(
            TEST_PHRASE,
            BitcoinNetwork::Mainnet,
            2,
        ))
        .unwrap();

        let record = KnownIdentity::load(dir.path()).await.unwrap();
        assert!(!record.matches(&mainnet));
    }

    /// A half-written file must cost the node its recovery, not its start.
    #[tokio::test]
    async fn a_corrupt_record_reads_as_no_record() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join(FILE_NAME), b"{ truncated")
            .await
            .unwrap();

        assert!(KnownIdentity::load(dir.path()).await.is_none());
    }

    /// Re-onboarding on a different account overwrites rather than appends: the
    /// record answers "what is this node now", not "what has it ever been".
    #[tokio::test]
    async fn storing_again_replaces_the_record() {
        let dir = tempdir().unwrap();
        KnownIdentity::store(dir.path(), &identity(2))
            .await
            .unwrap();
        KnownIdentity::store(dir.path(), &identity(3))
            .await
            .unwrap();

        let record = KnownIdentity::load(dir.path()).await.unwrap();
        assert!(record.matches(&identity(3)));
        assert_eq!(record.account, 3);
    }

    /// Bookkeeping must never take a running node down.
    #[tokio::test]
    async fn remembering_into_a_missing_directory_does_not_panic() {
        remember(Path::new("/nonexistent/storage"), &identity(2)).await;
    }
}
