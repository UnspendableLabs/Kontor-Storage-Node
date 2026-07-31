//! What the node is currently doing, and how `/admin` asks it to do something
//! else.
//!
//! # Why this exists
//!
//! A node used to learn everything about itself before its HTTP server existed:
//! keys were loaded, the Portal was asked, and only then was anything served. A
//! node that could not answer those questions could not be talked to either,
//! which is why the one recovery path — registering from a browser — had to be
//! bolted on as a second, daemon-less way of running the server.
//!
//! Zero-configuration inverts that. The server comes up first, always, and the
//! answers arrive afterwards: an operator claims the admin UI, provisions a key,
//! unlocks a sealed one. So the two facts every request handler needs — which
//! node this is, and what key it holds — can no longer be constants fixed at
//! construction. [`NodeRuntime`] is where they live instead.
//!
//! # Why a plain `RwLock`
//!
//! These fields are written perhaps twice in a process's life and read on every
//! request, which sounds like a case for a lock-free cell. It is not worth one.
//! The critical section is a single `Option<Arc<_>>::clone`, so a reader never
//! waits on anything but another clone, and an `arc-swap` dependency would buy
//! nanoseconds on a path already doing HTTP.
//!
//! A `tokio::sync::RwLock` would be the worse choice for a concrete reason:
//! [`crate::server::admin::register`] holds the identity across an `.await` on
//! the Portal, and an async guard held across that await would have to be
//! `Send`, and would hold the lock for the length of a network round trip.
//! Returning an owned `Arc` sidesteps both.
//!
//! Poisoning is recovered from rather than propagated, following
//! [`crate::server::admin::session`]: a panic somewhere else must not be able to
//! lock an operator out of the UI they would use to fix it.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use tokio::sync::Notify;

use crate::crypto::keystore::{self, Keystore, SealKey, SealKeySource, SlotKind};
use crate::server::admin::NodeIdentity;

/// Where the node is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No keystore. The setup wizard has the work.
    Uninitialized,
    /// A keystore exists and nothing on this machine can open it.
    Sealed,
    /// Keys in hand, talking to the Portal.
    Activating,
    /// Onboarding got as far as "the Portal has never heard of this key".
    Unregistered,
    /// Onboarded, daemon running.
    Running,
    /// Activation failed in a way retrying will not fix. The server stays up so
    /// the reason can be read and acted on.
    Failed,
}

impl Phase {
    /// The name `/admin` switches its panes on.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::Sealed => "sealed",
            Self::Activating => "activating",
            Self::Unregistered => "unregistered",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }

    /// Whether the node is serving files and proving storage.
    #[must_use]
    pub fn is_serving(self) -> bool {
        matches!(self, Self::Running)
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How this node's key is sealed, as `/admin` needs to present it.
///
/// `opened_with` is recorded rather than inferred, and that distinction is
/// load-bearing: dropping the `.seal-key` file is only safe once the node has
/// actually come up through the env slot, and "there is an env slot" is not the
/// same claim as "this boot used it".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealStatus {
    pub slots: Vec<SlotKind>,
    pub opened_with: Option<SlotKind>,
    pub source: Option<SealKeySource>,
    pub fingerprint: Option<String>,
}

impl SealStatus {
    /// The status of a node whose keystore was opened this boot.
    ///
    /// The fingerprint is whatever the key is willing to publish, which is
    /// nothing at all for a passphrase — see [`SealKey::fingerprint`].
    #[must_use]
    pub fn opened(keystore: &Keystore, key: &SealKey, source: SealKeySource) -> Self {
        Self {
            slots: keystore.slots(),
            opened_with: Some(source.kind()),
            source: Some(source),
            fingerprint: key.fingerprint(),
        }
    }

    /// The status of a keystore nothing could open.
    #[must_use]
    pub fn locked(keystore: &Keystore) -> Self {
        Self {
            slots: keystore.slots(),
            ..Self::default()
        }
    }

    /// Whether some slot could be supplied by the machine itself at boot.
    ///
    /// The same question [`Keystore::can_boot_unattended`] answers, asked of the
    /// copy `/admin` can see. It is what decides whether a restart is a recovery
    /// or an outage that waits for a human, and it lives here rather than being
    /// captured once at startup because the slots change while the node runs:
    /// a node provisioned through the wizard gains its first machine slot after
    /// the server is already answering requests.
    #[must_use]
    pub fn can_boot_unattended(&self) -> bool {
        keystore::slots_can_boot_unattended(&self.slots)
    }

    /// Whether `/admin` may offer to reseal this node at all.
    ///
    /// Adding or dropping a slot needs the data key, which needs the key this
    /// boot opened the keystore with. A node that never opened one — sealed, or
    /// stopped in [`Phase::Failed`] before it got there — has slots to show and
    /// nothing to change them with.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.opened_with.is_some()
    }

    /// Whether `/admin` may offer to drop the file slot.
    ///
    /// Both halves are required. Without the env slot there would be nothing
    /// left to open the node with; without having *used* it, "it is in the
    /// environment" is a claim nobody has tested, and testing it after deleting
    /// the fallback is the wrong order.
    #[must_use]
    pub fn can_drop_file_slot(&self) -> bool {
        self.opened_with == Some(SlotKind::Env) && self.slots.contains(&SlotKind::File)
    }
}

/// Something an operator asked for that the supervisor has to carry out.
pub enum Activation {
    /// A keystore that has **already been opened** — freshly provisioned by the
    /// wizard, or unlocked by a passphrase.
    ///
    /// The opened key travels with it rather than being derived again on the
    /// other side. That is not a micro-optimisation: a passphrase slot costs
    /// 64 MiB of Argon2id across four lanes, the endpoints run it on
    /// `spawn_blocking` precisely because it must not sit on the executor, and
    /// the supervisor is a plain `tokio` task. Re-deriving here would pay the
    /// whole cost a second time, on the one thread that has no business
    /// blocking.
    Open {
        keystore: Box<Keystore>,
        keypair: Box<crate::crypto::BlsKeyPair>,
        seal_key: SealKey,
        source: SealKeySource,
    },
    /// Onboard again with the keys the supervisor already holds. Sent after a
    /// registration, which is exactly the fact that made the previous attempt
    /// fail.
    Reonboard,
}

impl std::fmt::Debug for Activation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { source, .. } => f
                .debug_struct("Open")
                .field("source", source)
                .finish_non_exhaustive(),
            Self::Reonboard => f.write_str("Reonboard"),
        }
    }
}

struct State {
    phase: Phase,
    node_id: Option<String>,
    identity: Option<Arc<NodeIdentity>>,
    seal: SealStatus,
    /// The key this boot actually opened the keystore with.
    ///
    /// Kept rather than re-resolved. `/admin` changes how the node is sealed by
    /// unwrapping the data key with whatever opened it, and the environment is
    /// not a reliable answer to "what was that": a node unsealed by passphrase
    /// has nothing on the machine to re-derive, and a `KONTOR_SEAL_KEY` pasted
    /// in ahead of the slot it belongs to names a slot that does not exist yet.
    /// Both cases are a working node being told it cannot reseal itself.
    seal_key: Option<SealKey>,
    /// Why the node is where it is, when that needs saying — a failed
    /// activation, a Portal that will not register it, an environment variable
    /// that disagrees with the keystore.
    notice: Option<String>,
    pending: Option<Activation>,
}

struct Inner {
    state: RwLock<State>,
    wake: Notify,
}

/// The node's live state, shared by every request handler and the supervisor.
#[derive(Clone)]
pub struct NodeRuntime {
    inner: Arc<Inner>,
}

impl NodeRuntime {
    #[must_use]
    pub fn new(phase: Phase, seal: SealStatus) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(State {
                    phase,
                    node_id: None,
                    identity: None,
                    seal,
                    seal_key: None,
                    notice: None,
                    pending: None,
                }),
                wake: Notify::new(),
            }),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.read().phase
    }

    #[must_use]
    pub fn node_id(&self) -> Option<String> {
        self.read().node_id.clone()
    }

    /// The node's key and Portal client, when it has them.
    ///
    /// Owned rather than borrowed so the caller can hold it across an await
    /// without holding the lock.
    #[must_use]
    pub fn identity(&self) -> Option<Arc<NodeIdentity>> {
        self.read().identity.clone()
    }

    #[must_use]
    pub fn seal(&self) -> SealStatus {
        self.read().seal.clone()
    }

    /// Whether a restarted process could reach a running node again without a
    /// human at a terminal.
    ///
    /// Answered from the slots rather than remembered from startup, because the
    /// answer changes during a process's life: a node that came up with no
    /// keystore at all says no, and says yes the moment the wizard seals one.
    /// A handle carrying a `bool` fixed at boot would go on refusing the reset's
    /// restart to exactly the nodes this release exists to create.
    #[must_use]
    pub fn can_restart(&self) -> bool {
        self.read().seal.can_boot_unattended()
    }

    /// The key this boot opened the keystore with, when it opened one.
    #[must_use]
    pub fn seal_key(&self) -> Option<SealKey> {
        self.read().seal_key.clone()
    }

    #[must_use]
    pub fn notice(&self) -> Option<String> {
        self.read().notice.clone()
    }

    /// Move to a new phase, logging the transition.
    ///
    /// Every phase change goes through here so a node's whole life is one
    /// greppable sequence of lines rather than something to be reconstructed
    /// from what happened to be logged nearby.
    pub fn enter(&self, phase: Phase) {
        let previous = {
            let mut state = self.write();
            let previous = state.phase;
            state.phase = phase;
            previous
        };

        if previous != phase {
            tracing::info!(from = %previous, to = %phase, "node phase changed");
        }
    }

    /// Record why the node is where it is. `None` clears it.
    pub fn set_notice(&self, notice: Option<String>) {
        self.write().notice = notice;
    }

    /// Record that the keystore was opened, and with what.
    ///
    /// The status and the key are written together and only together. `/admin`
    /// decides what it may offer from the status and then acts with the key, so
    /// the two drifting apart is how an operator gets told a slot can be added
    /// and then handed a 500 when they try.
    pub fn opened(&self, keystore: &Keystore, key: &SealKey, source: SealKeySource) {
        let mut state = self.write();
        state.seal = SealStatus::opened(keystore, key, source);
        state.seal_key = Some(key.clone());
    }

    /// Refresh which slots exist, after `/admin` has added or dropped one.
    ///
    /// Only the list changes: the key this boot came up on is still the key it
    /// came up on, and `opened_with` still names the slot it came through — a
    /// node that has just gained an env slot has not thereby started using it.
    pub fn set_slots(&self, slots: Vec<SlotKind>) {
        self.write().seal.slots = slots;
    }

    /// Publish the identity the rest of the process should work from.
    pub fn set_identity(&self, identity: NodeIdentity) {
        let node_id = identity
            .registered()
            .map(|registered| registered.node_id.clone());
        let mut state = self.write();
        state.identity = Some(Arc::new(identity));
        state.node_id = node_id;
    }

    /// Ask the supervisor to do something.
    ///
    /// One slot, deliberately. Two operators racing to provision the same node
    /// is not a case worth queueing for, and dropping the earlier request is
    /// what stops a stale one from being carried out after the state it assumed
    /// has moved on.
    pub fn request(&self, activation: Activation) {
        self.write().pending = Some(activation);
        self.inner.wake.notify_one();
    }

    /// Wait for the next thing to do.
    ///
    /// The pending slot is checked before waiting: a request that arrived while
    /// the supervisor was busy must not be lost to a notification nobody was
    /// listening for.
    pub async fn next(&self) -> Activation {
        loop {
            if let Some(activation) = self.write().pending.take() {
                return activation;
            }
            self.inner.wake.notified().await;
        }
    }

    /// A runtime with an identity already in place, for handler tests that do
    /// not exercise activation.
    #[cfg(test)]
    #[must_use]
    pub fn for_tests(node_id: Option<&str>, identity: Option<NodeIdentity>) -> Self {
        let runtime = Self::new(Phase::Running, SealStatus::default());
        {
            let mut state = runtime.write();
            state.node_id = node_id.map(ToString::to_string);
            state.identity = identity.map(Arc::new);
        }
        runtime
    }
}

impl std::fmt::Debug for NodeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.read();
        f.debug_struct("NodeRuntime")
            .field("phase", &state.phase)
            .field("node_id", &state.node_id)
            .field("seal", &state.seal)
            // Included rather than skipped: this is what gets printed whenever
            // the admin state is, so `NodeIdentity`'s own redaction has to be
            // on the path an accidental `{:?}` would take.
            .field("identity", &state.identity)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_runtime_knows_nothing() {
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());

        assert_eq!(runtime.phase(), Phase::Uninitialized);
        assert!(runtime.node_id().is_none());
        assert!(runtime.identity().is_none());
        assert!(runtime.notice().is_none());
        assert!(!runtime.phase().is_serving());
    }

    #[test]
    fn phases_render_as_the_names_the_page_switches_on() {
        assert_eq!(Phase::Uninitialized.as_str(), "uninitialized");
        assert_eq!(Phase::Sealed.to_string(), "sealed");
        assert_eq!(Phase::Activating.as_str(), "activating");
        assert_eq!(Phase::Unregistered.as_str(), "unregistered");
        assert_eq!(Phase::Failed.as_str(), "failed");
        assert!(Phase::Running.is_serving());
        assert!(!Phase::Unregistered.is_serving());
    }

    #[test]
    fn entering_a_phase_is_visible_to_every_clone() {
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());
        let clone = runtime.clone();

        clone.enter(Phase::Running);

        assert_eq!(runtime.phase(), Phase::Running);
    }

    #[test]
    fn a_notice_can_be_set_and_cleared() {
        let runtime = NodeRuntime::new(Phase::Failed, SealStatus::default());

        runtime.set_notice(Some("the Portal refused".to_string()));
        assert_eq!(runtime.notice().as_deref(), Some("the Portal refused"));

        runtime.set_notice(None);
        assert!(runtime.notice().is_none());
    }

    /// The rule the hardening flow turns on: an env slot that exists is not an
    /// env slot that has been shown to work.
    #[test]
    fn the_file_slot_is_only_droppable_after_booting_through_the_env_slot() {
        let both = vec![SlotKind::File, SlotKind::Env];

        let via_file = SealStatus {
            slots: both.clone(),
            opened_with: Some(SlotKind::File),
            ..SealStatus::default()
        };
        assert!(!via_file.can_drop_file_slot());

        let via_env = SealStatus {
            slots: both,
            opened_with: Some(SlotKind::Env),
            ..SealStatus::default()
        };
        assert!(via_env.can_drop_file_slot());

        let env_only = SealStatus {
            slots: vec![SlotKind::Env],
            opened_with: Some(SlotKind::Env),
            ..SealStatus::default()
        };
        assert!(!env_only.can_drop_file_slot());
    }

    /// The status and the key are published in one call because `/admin` reads
    /// one and acts with the other: it decides a slot may be added from
    /// `SealStatus`, then unwraps the data key with the key. A runtime that
    /// carried one without the other would offer a change that cannot succeed.
    #[test]
    fn opening_publishes_the_status_and_the_key_together() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let runtime = NodeRuntime::new(Phase::Activating, SealStatus::default());
        runtime.opened(&keystore, &key, SealKeySource::File);

        assert_eq!(runtime.seal().opened_with, Some(SlotKind::File));
        assert_eq!(runtime.seal().fingerprint, key.fingerprint());
        assert_eq!(
            runtime.seal_key().and_then(|held| held.fingerprint()),
            key.fingerprint(),
            "the key that opened it must be the one /admin reseals with"
        );
    }

    /// A node opened by hand publishes no fingerprint, because the only thing
    /// there is to fingerprint is the operator's passphrase. Everything else
    /// about the seal is still reported.
    #[test]
    fn opening_with_a_passphrase_publishes_no_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::passphrase("a passphrase long enough to be accepted");
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let runtime = NodeRuntime::new(Phase::Sealed, SealStatus::default());
        runtime.opened(&keystore, &key, SealKeySource::Passphrase);

        let seal = runtime.seal();
        assert_eq!(seal.opened_with, Some(SlotKind::Passphrase));
        assert!(seal.is_open());
        assert_eq!(seal.fingerprint, None);
        // And a node held open only by a human cannot be restarted into one.
        assert!(!runtime.can_restart());
    }

    /// The restart offer follows the slots, and has to keep following them: a
    /// node with no keystore says no, and says yes as soon as the wizard seals
    /// one — in the same process, without anybody restarting anything.
    #[test]
    fn the_restart_offer_appears_with_the_first_machine_slot() {
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());
        assert!(!runtime.can_restart());

        runtime.set_slots(vec![SlotKind::Passphrase]);
        assert!(
            !runtime.can_restart(),
            "a slot only a human can supply is not a way back from a restart"
        );

        runtime.set_slots(vec![SlotKind::File, SlotKind::Passphrase]);
        assert!(runtime.can_restart());
    }

    /// Nothing hands out a seal key until one has actually opened the keystore.
    /// The supervisor only announces an opening after the unseal succeeds, so a
    /// key that turned out to be wrong never becomes the one `/admin` acts with.
    #[test]
    fn a_runtime_that_never_opened_anything_holds_no_key() {
        let runtime = NodeRuntime::new(Phase::Sealed, SealStatus::default());

        assert!(runtime.seal_key().is_none());
        assert!(runtime.seal().opened_with.is_none());
    }

    /// Gaining a slot is not the same as having booted through it, and only the
    /// second permits dropping the file slot.
    #[test]
    fn refreshing_the_slots_leaves_the_boot_record_alone() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let runtime = NodeRuntime::new(Phase::Running, SealStatus::default());
        runtime.opened(&keystore, &key, SealKeySource::File);
        runtime.set_slots(vec![SlotKind::File, SlotKind::Env]);

        let seal = runtime.seal();
        assert_eq!(seal.slots, vec![SlotKind::File, SlotKind::Env]);
        assert_eq!(seal.opened_with, Some(SlotKind::File));
        assert!(!seal.can_drop_file_slot());
        assert!(
            runtime.seal_key().is_some(),
            "the boot key is still the key"
        );
    }

    #[test]
    fn a_locked_keystore_reports_its_slots_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let locked = SealStatus::locked(&keystore);
        assert_eq!(locked.slots, vec![SlotKind::File]);
        assert!(locked.opened_with.is_none());
        assert!(locked.fingerprint.is_none());
        assert!(!locked.is_open(), "a locked keystore cannot be resealed");
        // It could still come back from a restart on its own — the slot is
        // there, this boot simply had no key for it.
        assert!(locked.can_boot_unattended());

        let opened = SealStatus::opened(&keystore, &key, SealKeySource::Generated);
        assert_eq!(opened.opened_with, Some(SlotKind::File));
        assert_eq!(opened.fingerprint, key.fingerprint());
        assert!(opened.is_open());
    }

    #[tokio::test]
    async fn a_request_made_before_anyone_waits_is_not_lost() {
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());

        runtime.request(Activation::Reonboard);

        let activation = tokio::time::timeout(std::time::Duration::from_secs(1), runtime.next())
            .await
            .expect("the pending slot must be checked before waiting");
        assert!(matches!(activation, Activation::Reonboard));
    }

    #[tokio::test]
    async fn next_waits_until_something_is_asked_for() {
        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), runtime.next())
                .await
                .is_err(),
            "next() must not return anything before a request"
        );

        let waiter = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.next().await })
        };
        tokio::task::yield_now().await;
        runtime.request(Activation::Reonboard);

        let activation = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(activation, Activation::Reonboard));
    }

    /// One slot: a second request supersedes the first rather than queueing
    /// behind it.
    #[tokio::test]
    async fn a_later_request_replaces_an_unclaimed_one() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let runtime = NodeRuntime::new(Phase::Uninitialized, SealStatus::default());
        runtime.request(Activation::Reonboard);
        let keypair = keystore.unseal(&key).unwrap();
        runtime.request(Activation::Open {
            keystore: Box::new(keystore),
            keypair: Box::new(keypair),
            seal_key: key,
            source: SealKeySource::File,
        });

        assert!(matches!(runtime.next().await, Activation::Open { .. }));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), runtime.next())
                .await
                .is_err(),
            "the superseded request must not still be waiting"
        );
    }

    #[test]
    fn the_debug_impl_names_the_phase_without_reaching_for_the_key() {
        let runtime = NodeRuntime::new(Phase::Sealed, SealStatus::default());
        let rendered = format!("{runtime:?}");
        assert!(rendered.contains("Sealed"), "{rendered}");
    }

    #[test]
    fn activation_debug_does_not_reach_for_the_seal_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let keypair = crate::crypto::BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, &key).unwrap();

        let keypair = keystore.unseal(&key).unwrap();
        let rendered = format!(
            "{:?}",
            Activation::Open {
                keystore: Box::new(keystore),
                keypair: Box::new(keypair),
                seal_key: key.clone(),
                source: SealKeySource::Env,
            }
        );
        assert!(rendered.contains("Env"), "{rendered}");
        assert!(
            !rendered.contains(key.encode().unwrap().as_str()),
            "{rendered}"
        );
        assert_eq!(format!("{:?}", Activation::Reonboard), "Reonboard");
    }
}
