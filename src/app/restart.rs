//! Operator-requested process restart.
//!
//! # Why the node exits instead of restarting itself
//!
//! A database reset only wipes chain-derived state. The node's Portal
//! registration — the `signer_id`, the JWT, the announced public URL — is read
//! once by [`crate::node::perform_onboarding`] and then frozen in the
//! `PortalClient` the daemon owns. After a signet reset that registration
//! describes nothing: the announce is a startup-only call, and the nonce
//! resynced at every cycle is resynced against a `signer_id` the new chain
//! never issued. Wiping the tables alone leaves a node that talks to the Portal
//! with a stale identity.
//!
//! Re-onboarding in place would mean swapping the client out from under the
//! running daemon task and handing over its lock file. Exiting and letting the
//! supervisor start us again reaches the same state for the cost of an exit
//! code, and every deployment of this node already has such a supervisor —
//! Railway, a Docker restart policy, systemd.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

use crate::crypto::mnemonic::MNEMONIC_ENV;
use crate::node::onboarding::key_management::BLS_PASSWORD_ENV;

/// Exit code the process uses when an operator asked for a restart.
///
/// `EX_TEMPFAIL` from `sysexits.h`. It has to be non-zero: Railway's default
/// policy and Docker Compose's `restart: on-failure` only bring a container
/// back that exited with a failure, so a clean `0` would leave the node
/// stopped. `always` and `unless-stopped` restart on any code, which makes
/// non-zero strictly the more portable choice.
pub const RESTART_EXIT_CODE: i32 = 75;

/// Why the run loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// SIGINT/SIGTERM, or a subcommand that ran to completion. Exit `0`.
    Shutdown,
    /// An operator asked for a restart from `/admin`. Exit with
    /// [`RESTART_EXIT_CODE`] so the supervisor starts the node again.
    Restart,
}

/// A one-way switch the admin API flips and the run loop waits on.
///
/// Cloned into [`crate::server::admin::AdminState`], hence the `Arc`.
#[derive(Clone)]
pub struct RestartHandle {
    inner: Arc<Inner>,
}

struct Inner {
    /// Whether a restart is offered at all: see [`RestartHandle::is_available`].
    available: bool,
    requested: AtomicBool,
    /// Wakes the run loop. A `Notify` rather than a `oneshot`: the permit
    /// `notify_one` leaves behind means a request that lands before the run
    /// loop starts waiting is not lost.
    notify: Notify,
}

impl RestartHandle {
    #[must_use]
    fn new(available: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                available,
                requested: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Reads the environment to decide whether restarting can be offered.
    ///
    /// Onboarding gets the BLS key on every startup, and only two of the three
    /// ways it can do that come back without a human. `get_password_reader`
    /// takes the key file's password from the environment when `BLS_PASSWORD` is
    /// set and prompts on the terminal otherwise; a node with
    /// `KONTOR_STORAGE_MNEMONIC` re-derives the key and never asks at all. A
    /// container has no terminal to prompt at, so restarting with neither
    /// variable would take the node down and leave it down. Nothing else in
    /// startup blocks on a human: the key file itself always exists by the time
    /// a node is running (onboarding writes it), and the KOR faucet step polls
    /// rather than asks.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(std::env::var(BLS_PASSWORD_ENV).is_ok() || std::env::var(MNEMONIC_ENV).is_ok())
    }

    /// A handle that refuses restarts, for callers that have no run loop to
    /// stop.
    #[cfg(test)]
    #[must_use]
    pub fn unavailable() -> Self {
        Self::new(false)
    }

    /// A handle that accepts restarts, for tests that assert on the switch.
    #[cfg(test)]
    #[must_use]
    pub fn available() -> Self {
        Self::new(true)
    }

    /// True when a restarted process could reach a running node again without
    /// a human at a terminal.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.inner.available
    }

    /// Ask the run loop to shut down so the supervisor restarts the node.
    ///
    /// Returns without waiting: the caller is inside a request handler whose
    /// response the graceful shutdown still has to flush.
    pub fn request(&self) {
        self.inner.requested.store(true, Ordering::Release);
        self.inner.notify.notify_one();
    }

    /// True once [`RestartHandle::request`] has been called.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.inner.requested.load(Ordering::Acquire)
    }

    /// Resolves once a restart has been requested, immediately if it already
    /// was.
    pub async fn requested(&self) {
        while !self.is_requested() {
            self.inner.notify.notified().await;
        }
    }
}

impl std::fmt::Debug for RestartHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestartHandle")
            .field("available", &self.is_available())
            .field("requested", &self.is_requested())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_handle_has_not_been_asked_for_anything() {
        let handle = RestartHandle::available();
        assert!(handle.is_available());
        assert!(!handle.is_requested());

        let unavailable = RestartHandle::unavailable();
        assert!(!unavailable.is_available());
    }

    /// Availability is a statement about the *next* startup, so requesting a
    /// restart on an unavailable handle still flips the switch. The refusal
    /// belongs to the admin API, which never gets that far.
    #[test]
    fn requesting_is_independent_of_availability() {
        let handle = RestartHandle::unavailable();
        handle.request();
        assert!(handle.is_requested());
    }

    /// The clone the admin API holds and the one the run loop waits on are the
    /// same switch.
    #[tokio::test]
    async fn a_clone_observes_the_request() {
        let handle = RestartHandle::available();
        let clone = handle.clone();

        clone.request();

        assert!(handle.is_requested());
        handle.requested().await;
    }

    /// The request arrives from a request handler, which may well run before
    /// the run loop reaches its `select!`. The permit is what keeps that from
    /// hanging forever.
    #[tokio::test]
    async fn a_request_made_before_the_wait_is_not_lost() {
        let handle = RestartHandle::available();
        handle.request();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle.requested())
            .await
            .expect("a request made before the wait must still wake it");
    }

    #[tokio::test]
    async fn waiting_wakes_on_a_later_request() {
        let handle = RestartHandle::available();
        let waiter = handle.clone();
        let task = tokio::spawn(async move { waiter.requested().await });

        // Yield until the task is parked on `notified()`, then request.
        tokio::task::yield_now().await;
        handle.request();

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("request must wake the waiter")
            .unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn availability_follows_the_bls_password_variable() {
        let original = std::env::var(BLS_PASSWORD_ENV).ok();

        std::env::set_var(BLS_PASSWORD_ENV, "testpassword123");
        assert!(
            RestartHandle::from_env().is_available(),
            "a password in the environment means startup needs no terminal"
        );

        std::env::remove_var(BLS_PASSWORD_ENV);
        assert!(
            !RestartHandle::from_env().is_available(),
            "without it a restarted process would stop at the password prompt"
        );

        match original {
            Some(value) => std::env::set_var(BLS_PASSWORD_ENV, value),
            None => std::env::remove_var(BLS_PASSWORD_ENV),
        }
    }

    /// A mnemonic node never reaches a password prompt: it re-derives the key on
    /// the way up. Restarting has to be offered to it even with no
    /// `BLS_PASSWORD`, or the `/admin` reset would be a one-way door on exactly
    /// the nodes that need it most.
    #[test]
    #[serial_test::serial]
    fn a_mnemonic_also_makes_restarting_available() {
        let original_password = std::env::var(BLS_PASSWORD_ENV).ok();
        let original_mnemonic = std::env::var(MNEMONIC_ENV).ok();

        std::env::remove_var(BLS_PASSWORD_ENV);
        std::env::set_var(MNEMONIC_ENV, "abandon abandon about");
        let with_mnemonic = RestartHandle::from_env().is_available();

        std::env::remove_var(MNEMONIC_ENV);
        let without_either = RestartHandle::from_env().is_available();

        match original_password {
            Some(value) => std::env::set_var(BLS_PASSWORD_ENV, value),
            None => std::env::remove_var(BLS_PASSWORD_ENV),
        }
        match original_mnemonic {
            Some(value) => std::env::set_var(MNEMONIC_ENV, value),
            None => std::env::remove_var(MNEMONIC_ENV),
        }

        assert!(
            with_mnemonic,
            "a node that derives its key needs nothing from a terminal"
        );
        assert!(!without_either);
    }

    #[test]
    fn debug_output_names_both_flags() {
        let handle = RestartHandle::available();
        handle.request();
        let rendered = format!("{handle:?}");
        assert!(rendered.contains("available: true"), "{rendered}");
        assert!(rendered.contains("requested: true"), "{rendered}");
    }

    /// An empty `BLS_PASSWORD` is still a password as far as
    /// `get_password_reader` is concerned — it keys off `is_ok`, not off the
    /// value — so availability has to agree, or the two would disagree about
    /// whether startup prompts.
    #[test]
    #[serial_test::serial]
    fn an_empty_password_variable_still_counts_as_set() {
        let original = std::env::var(BLS_PASSWORD_ENV).ok();

        std::env::set_var(BLS_PASSWORD_ENV, "");
        let available = RestartHandle::from_env().is_available();

        match original {
            Some(value) => std::env::set_var(BLS_PASSWORD_ENV, value),
            None => std::env::remove_var(BLS_PASSWORD_ENV),
        }

        assert!(available);
    }
}
