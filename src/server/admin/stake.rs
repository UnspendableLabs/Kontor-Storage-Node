//! `POST /api/admin/stake` — start an unstake, or withdraw the bond.
//!
//! The two operator decisions the stake policy never makes on its own. Both
//! are one-way enough to deserve the reset's treatment — a typed confirmation
//! phrase — and neither is signed here. The handler only queues the op on the
//! daemon's [`StakeTracker`](crate::app::tasks::stake::StakeTracker), and the
//! daemon signs it on its next cycle: the daemon is the only thing that holds
//! the authenticated client, and keeping it the only signer means the nonce
//! counter never has two writers racing each other.
//!
//! What each does on Kontor:
//!
//! - `begin_unstake` sets the bond's withdrawal height (2028 blocks out) and
//!   starts the exit: joins stop as soon as it is queued, and once it has
//!   executed the daemon leaves each membership and finally withdraws on its
//!   own (see [`ExitInputs`](crate::app::tasks::stake::ExitInputs)). The
//!   agreements still held have to be proved until they are left, and a
//!   missed proof is still slashed.
//! - `withdraw_stake` tries the withdrawal now, ahead of the daemon's own
//!   estimate of when the delay ends. Kontor refuses it before that height or
//!   while any agreement or open challenge holds part of the bond; the refusal
//!   shows as an op that landed without the stake moving.

use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::lifecycle::Phase;
use crate::clients::portal::NodeOp;
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Phrase that arms `begin_unstake`.
pub const UNSTAKE_PHRASE: &str = "UNSTAKE";
/// Phrase that arms `withdraw_stake`.
pub const WITHDRAW_PHRASE: &str = "WITHDRAW";

/// Request body for `POST /api/admin/stake`.
#[derive(Debug, Default, Deserialize)]
pub struct StakeActionRequest {
    /// `begin_unstake` or `withdraw_stake`.
    #[serde(default)]
    pub action: String,
    /// Must equal the action's phrase.
    #[serde(default)]
    pub confirm: String,
}

/// Queue the requested op for the daemon's next cycle.
///
/// # Errors
/// - `400 CONFIRMATION_REQUIRED` for an unknown action or a wrong phrase.
/// - `409 STAKE_UNAVAILABLE` when no daemon is running to sign it, the bond
///   has not been read yet, the bond's state rules the action out, or another
///   request is already waiting.
pub fn request_stake_action(
    request: &StakeActionRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    let (op, phrase) = match request.action.as_str() {
        "begin_unstake" => (NodeOp::BeginUnstake, UNSTAKE_PHRASE),
        "withdraw_stake" => (NodeOp::WithdrawStake, WITHDRAW_PHRASE),
        other => {
            return Err(ApiError::bad_request(
                error_codes::CONFIRMATION_REQUIRED,
                format!("unknown action {other:?}: expected begin_unstake or withdraw_stake"),
            ))
        }
    };
    if request.confirm != phrase {
        return Err(ApiError::bad_request(
            error_codes::CONFIRMATION_REQUIRED,
            format!("type {phrase} to confirm"),
        ));
    }

    let unavailable = |message: &str| {
        ApiError::new(
            StatusCode::CONFLICT,
            error_codes::STAKE_UNAVAILABLE,
            message,
        )
    };

    if state.runtime.phase() != Phase::Running {
        return Err(unavailable(
            "the node is not running, so there is no daemon to sign the op",
        ));
    }
    let tracker = state.runtime.staking();
    let Some(snapshot) = tracker.snapshot() else {
        return Err(unavailable(
            "the Portal has not reported this node's stake yet; try again after the next cycle",
        ));
    };
    match op {
        NodeOp::BeginUnstake if snapshot.withdrawal_height.is_some() => {
            return Err(unavailable("a withdrawal is already requested"));
        }
        NodeOp::BeginUnstake if snapshot.stake.is_zero() => {
            return Err(unavailable("there is no bonded stake to unstake"));
        }
        NodeOp::WithdrawStake if snapshot.withdrawal_height.is_none() => {
            return Err(unavailable(
                "no withdrawal is requested: begin the unstake first",
            ));
        }
        _ => {}
    }

    let name = op.name();
    tracker.request(op).map_err(unavailable)?;

    Ok(json!({
        "queued": name,
        "message": "queued: the daemon signs it on its next cycle",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::lifecycle::NodeRuntime;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::clients::portal::RegistryEntry;
    use crate::server::admin::AdminState;
    use crate::testutils::{setup_in_memory_db, tempdir};

    async fn state() -> (DownloadServerState, tempfile::TempDir) {
        let dir = tempdir();
        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: NodeRuntime::for_tests(Some("NODE-stake"), None),
            admin: AdminState::disabled(),
        };
        (state, dir)
    }

    fn observe(state: &DownloadServerState, stake: &str, withdrawal_height: Option<u64>) {
        let entry: RegistryEntry = serde_json::from_value(json!({
            "signer_id": 42,
            "x_only_pubkey": "ab",
            "bls_pubkey": null,
            "next_nonce": 1,
            "kor_balance": "5",
            "stake": stake,
            "stake_available": stake,
            "stake_withdrawal_height": withdrawal_height,
            "bond_cleanup_pending": false
        }))
        .unwrap();
        state
            .runtime
            .staking()
            .observe(Some(&entry), std::time::Instant::now());
    }

    fn request(action: &str, confirm: &str) -> StakeActionRequest {
        StakeActionRequest {
            action: action.to_string(),
            confirm: confirm.to_string(),
        }
    }

    #[tokio::test]
    async fn an_unstake_is_queued_for_the_daemon_not_signed_here() {
        let (state, _dir) = state().await;
        observe(&state, "100", None);

        let value = request_stake_action(&request("begin_unstake", "UNSTAKE"), &state).unwrap();
        assert_eq!(value["queued"], "begin_unstake");
        assert_eq!(
            state.runtime.staking().status()["operator_request"],
            "begin_unstake"
        );
        assert_eq!(
            state
                .runtime
                .staking()
                .plan(std::time::Instant::now(), None),
            Some(NodeOp::BeginUnstake),
            "the daemon's next cycle picks it up"
        );
    }

    #[tokio::test]
    async fn each_action_needs_its_own_phrase() {
        let (state, _dir) = state().await;
        observe(&state, "100", None);
        for (action, confirm) in [
            ("begin_unstake", ""),
            ("begin_unstake", "WITHDRAW"),
            ("begin_unstake", "unstake"),
            ("withdraw_stake", "UNSTAKE"),
            ("add_stake", "UNSTAKE"),
        ] {
            let err = request_stake_action(&request(action, confirm), &state).unwrap_err();
            assert_eq!(
                err.code,
                error_codes::CONFIRMATION_REQUIRED,
                "{action}/{confirm}"
            );
        }
        assert_eq!(
            state.runtime.staking().status()["operator_request"],
            Value::Null
        );
    }

    /// Asking for what Kontor would refuse is turned down here, with the
    /// reason, rather than spending a nonce and gas to learn it.
    #[tokio::test]
    async fn the_bond_state_rules_out_what_kontor_would_refuse() {
        let (state, _dir) = state().await;
        let conflict = |action: &str, confirm: &str| {
            request_stake_action(&request(action, confirm), &state)
                .unwrap_err()
                .code
        };

        assert_eq!(
            conflict("begin_unstake", "UNSTAKE"),
            error_codes::STAKE_UNAVAILABLE,
            "nothing read yet"
        );

        observe(&state, "0", None);
        assert_eq!(
            conflict("begin_unstake", "UNSTAKE"),
            error_codes::STAKE_UNAVAILABLE
        );
        assert_eq!(
            conflict("withdraw_stake", "WITHDRAW"),
            error_codes::STAKE_UNAVAILABLE
        );

        observe(&state, "100", Some(5000));
        assert_eq!(
            conflict("begin_unstake", "UNSTAKE"),
            error_codes::STAKE_UNAVAILABLE
        );
        request_stake_action(&request("withdraw_stake", "WITHDRAW"), &state).unwrap();
        assert_eq!(
            conflict("withdraw_stake", "WITHDRAW"),
            error_codes::STAKE_UNAVAILABLE,
            "one request at a time"
        );
    }

    #[tokio::test]
    async fn a_node_that_is_not_running_has_nobody_to_sign() {
        let (mut state, _dir) = state().await;
        state.runtime = NodeRuntime::new(Phase::Sealed, Default::default());
        let err = request_stake_action(&request("begin_unstake", "UNSTAKE"), &state).unwrap_err();
        assert_eq!(err.code, error_codes::STAKE_UNAVAILABLE);
    }
}
