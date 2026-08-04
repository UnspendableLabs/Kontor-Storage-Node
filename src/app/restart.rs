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
///
/// # Why it does not know whether a restart is a good idea
///
/// That question — could a restarted process get back up without a human — is a
/// question about the keystore's slots, and the slots change while the node
/// runs: a node provisioned through the wizard has none when its server starts
/// and a machine slot a moment later. A `bool` captured here at startup would
/// answer for the node that booted rather than the one being asked about, and
/// would go on refusing the reset's restart to exactly the nodes zero
/// configuration creates. [`crate::app::lifecycle::NodeRuntime::can_restart`]
/// owns it instead, where the slots already live.
#[derive(Clone)]
pub struct RestartHandle {
    inner: Arc<Inner>,
}

struct Inner {
    requested: AtomicBool,
    /// Wakes the run loop. A `Notify` rather than a `oneshot`: the permit
    /// `notify_one` leaves behind means a request that lands before the run
    /// loop starts waiting is not lost.
    notify: Notify,
}

impl Default for RestartHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartHandle {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                requested: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
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
            .field("requested", &self.is_requested())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_handle_has_not_been_asked_for_anything() {
        assert!(!RestartHandle::new().is_requested());
        assert!(!RestartHandle::default().is_requested());
    }

    /// The clone the admin API holds and the one the run loop waits on are the
    /// same switch.
    #[tokio::test]
    async fn a_clone_observes_the_request() {
        let handle = RestartHandle::new();
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
        let handle = RestartHandle::new();
        handle.request();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle.requested())
            .await
            .expect("a request made before the wait must still wake it");
    }

    #[tokio::test]
    async fn waiting_wakes_on_a_later_request() {
        let handle = RestartHandle::new();
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
    fn debug_output_names_the_switch() {
        let handle = RestartHandle::new();
        assert!(format!("{handle:?}").contains("requested: false"));
        handle.request();
        assert!(format!("{handle:?}").contains("requested: true"));
    }
}
