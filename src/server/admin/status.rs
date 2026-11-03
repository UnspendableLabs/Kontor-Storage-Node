//! `GET /api/admin/status` — what a reset would erase.
//!
//! Deliberately small: the public dashboard at `/` already lists the files, so
//! this only answers the question the danger zone raises — how much state is
//! there, and where does it live.
//!
//! Plus the bond, under `staking`: since the staking upgrade a node with no
//! unreserved stake silently stops taking on agreements, and one that misses a
//! challenge loses 30× its collateral. Neither shows up in the counts, so the
//! daemon's own view of the stake is echoed here — admin-only, unlike the
//! public `/api/info`, because it is the operator's money.

use axum::http::StatusCode;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, PaginatorTrait, QueryFilter, QuerySelect};
use serde_json::{json, Value};
use tracing::error;

use crate::app::config::StorageMethod;
use crate::app::tasks::downloadagreements::MAX_LEDGER_INDEX_SPARSITY_GAP;
use crate::entities::agreements;
use crate::entities::prelude::{Agreements, Challenges};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Counts of everything the reset would delete.
///
/// `session_expires_at` is echoed back so the page can show when the operator
/// will be signed out instead of finding out mid-reset. `restart_available`
/// answers the same question ahead of time for the restart checkbox: the page
/// disables it rather than letting the operator meet a `RESTART_UNAVAILABLE`
/// only once they have typed the confirmation phrase. It is read from the live
/// seal status on every poll, so a node that gains its first machine slot part
/// way through a session — which is what the setup wizard does — sees the
/// checkbox come alive without a reload.
///
/// # Errors
/// `500 DATABASE_ERROR` if any of the counts cannot be read.
pub async fn node_status(
    state: &DownloadServerState,
    session_expires_at: i64,
) -> Result<Value, ApiError> {
    let agreements_total = Agreements::find()
        .count(&state.db)
        .await
        .map_err(|err| database_error("count agreements", &err))?;

    let agreements_downloaded = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .count(&state.db)
        .await
        .map_err(|err| database_error("count downloaded agreements", &err))?;

    let challenges_total = Challenges::find()
        .count(&state.db)
        .await
        .map_err(|err| database_error("count challenges", &err))?;

    let stored_bytes = stored_bytes(state).await?;
    let ledger = ledger_status(state).await?;

    // The directory is meaningless for a GCS node, and the bucket name is
    // configuration the admin session has no business echoing back.
    let directory = match state.storage_backend.method {
        StorageMethod::Local => json!(state.storage_dir.display().to_string()),
        StorageMethod::Gcs => Value::Null,
    };

    Ok(json!({
        "node_id": state.runtime.node_id(),
        "phase": state.runtime.phase().as_str(),
        "serving": state.runtime.phase().is_serving(),
        // Why the node is where it is, when that needs saying. The one thing an
        // operator cannot infer from the counters below.
        "notice": state.runtime.notice(),
        "registration": registration_status(state),
        "storage": {
            "method": state.storage_backend.method.to_string(),
            "directory": directory,
        },
        "agreements": {
            "total": agreements_total,
            "downloaded": agreements_downloaded,
            "stored_bytes": stored_bytes,
        },
        "challenges": {
            "total": challenges_total,
        },
        "ledger": ledger,
        "staking": state.runtime.staking().status(),
        "restart_available": state.runtime.can_restart(),
        "session_expires_at": session_expires_at,
    }))
}

/// Whether the Portal knows this node's BLS key.
///
/// This is the one status block that matters on a node which never finished
/// onboarding: `registered: false` is what makes the page offer the wallet
/// flow at all. The public key is safe to publish — it is the lookup key, and
/// the node prints it on startup either way — while `supported` says whether
/// a key was loaded at all, which is the difference between "register it" and
/// "there is nothing here to register".
///
/// A node that knows its Taproot account adds `derived`. It needs no wallet
/// flow at all — it registers itself at startup — so what an operator wants from
/// this page is the address to whitelist, and which account it came from.
fn registration_status(state: &DownloadServerState) -> Value {
    let Some(identity) = state.admin.identity() else {
        return json!({ "supported": false, "registered": false });
    };

    let registered = identity.registered();
    json!({
        "supported": true,
        "registered": registered.is_some(),
        "bls_pubkey": identity.keypair().public_key_hex(),
        "node_id": registered.map(|node| node.node_id.clone()),
        "signer_id": registered.map(|node| node.signer_id),
        "derived": identity.public().map(|public| json!({
            "account": public.account,
            "network": public.network.to_string(),
            "taproot_address": public.taproot_address,
            "node_id": public.node_id,
        })),
    })
}

/// Whether this node can still build the ledger its proofs are made against.
///
/// The rebuild runs inside the daemon task, where a failure is a log line and
/// nothing more: proving simply stops, and the counts above go on looking
/// healthy. That is the one failure an operator cannot infer from anywhere
/// else, so it is answered here.
///
/// `blocked` is computed rather than remembered — it is the same predicate
/// `FileLedger` applies (see [`MAX_LEDGER_INDEX_SPARSITY_GAP`]), so it also
/// says *why*, and says it before the next rebuild rather than after.
async fn ledger_status(state: &DownloadServerState) -> Result<Value, ApiError> {
    // Same split as `rebuild_ledger`: a row missing `root`/`padded_len` was
    // never post-processed and is neither placed nor waiting on a slot.
    let described = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .filter(agreements::Column::Root.is_not_null())
        .filter(agreements::Column::PaddedLen.is_not_null());

    let placed = described
        .clone()
        .filter(agreements::Column::LedgerIndex.is_not_null())
        .count(&state.db)
        .await
        .map_err(|err| database_error("count files placed in the ledger", &err))?;

    let awaiting = described
        .clone()
        .filter(agreements::Column::LedgerIndex.is_null())
        .count(&state.db)
        .await
        .map_err(|err| database_error("count files awaiting a ledger slot", &err))?;

    let highest_slot: Option<i64> = described
        .select_only()
        .column_as(Expr::col(agreements::Column::LedgerIndex).max(), "highest")
        .into_tuple::<Option<i64>>()
        .one(&state.db)
        .await
        .map_err(|err| database_error("read the highest ledger slot", &err))?
        .flatten();

    // `leaf_count = highest_slot + 1`, refused once it exceeds the file count
    // by more than the gap.
    let blocked = match (highest_slot, usize::try_from(placed)) {
        (Some(highest), Ok(placed)) => usize::try_from(highest)
            .ok()
            .and_then(|highest| highest.checked_add(1))
            .is_some_and(|leaves| leaves > placed.saturating_add(MAX_LEDGER_INDEX_SPARSITY_GAP)),
        _ => false,
    };

    Ok(json!({
        "placed": placed,
        "awaiting_ledger_index": awaiting,
        "highest_slot": highest_slot,
        "rebuild_blocked": blocked,
    }))
}

/// Sum of `original_size` over downloaded agreements — the node's own view of
/// how much it is storing, the same figure the capacity limit is checked
/// against.
async fn stored_bytes(state: &DownloadServerState) -> Result<u64, ApiError> {
    // `SUM(...)` always returns one row, but its value is NULL when nothing
    // matches, which arrives as `Some(None)`.
    let total: Option<i64> = Agreements::find()
        .filter(agreements::Column::Downloaded.eq(true))
        .select_only()
        .column_as(Expr::col(agreements::Column::OriginalSize).sum(), "total")
        .into_tuple::<Option<i64>>()
        .one(&state.db)
        .await
        .map_err(|err| database_error("sum stored bytes", &err))?
        .flatten();

    Ok(total.unwrap_or(0).try_into().unwrap_or(0))
}

fn database_error(what: &str, err: &sea_orm::DbErr) -> ApiError {
    error!("Database error trying to {what}: {err}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        error_codes::DATABASE_ERROR,
        format!("failed to {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::server::admin::AdminState;
    use crate::testutils::{setup_in_memory_db, tempdir, AgreementFixture};
    use sea_orm::ActiveModelTrait;

    /// A stored, fully post-processed agreement at `slot`; `None` for one the
    /// Portal has not reconciled yet.
    async fn insert_stored(db: &sea_orm::DatabaseConnection, index: usize, slot: Option<i64>) {
        AgreementFixture {
            root: Some("0".repeat(64)),
            padded_len: Some(128),
            ledger_index: slot,
            downloaded: true,
            ..AgreementFixture::new(format!("AGR-slot-{index}"), format!("FILE-slot-{index}"))
        }
        .into_active_model()
        .insert(db)
        .await
        .unwrap();
    }

    async fn state_with(sizes: &[(i64, bool)]) -> (DownloadServerState, tempfile::TempDir) {
        let db = setup_in_memory_db().await;
        for (index, (size, downloaded)) in sizes.iter().enumerate() {
            AgreementFixture {
                original_size: *size,
                downloaded: *downloaded,
                ..AgreementFixture::new(format!("AGR-{index}"), format!("FILE-{index}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }

        let dir = tempdir();
        let state = DownloadServerState {
            db,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: crate::app::lifecycle::NodeRuntime::for_tests(Some("NODE-status"), None),
            admin: AdminState::disabled(),
        };
        (state, dir)
    }

    /// Any timestamp will do: the endpoint echoes it rather than deriving it.
    const SESSION_EXPIRY: i64 = 1_800_000_000;

    #[tokio::test]
    async fn status_counts_only_downloaded_agreements_as_stored() {
        let (state, _dir) = state_with(&[(100, true), (250, true), (999, false)]).await;

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["node_id"], "NODE-status");
        assert_eq!(value["session_expires_at"], SESSION_EXPIRY);
        assert_eq!(value["agreements"]["total"], 3);
        assert_eq!(value["agreements"]["downloaded"], 2);
        assert_eq!(value["agreements"]["stored_bytes"], 350);
        assert_eq!(value["challenges"]["total"], 0);
        assert_eq!(value["storage"]["method"], "local");
        assert_eq!(
            value["storage"]["directory"],
            state.storage_dir.display().to_string()
        );
    }

    /// What the page keys the registration card off. A node that never
    /// onboarded reports the key an operator has to register, and nothing else
    /// — there is no node id or signer id to report yet.
    #[tokio::test]
    async fn status_reports_an_unregistered_node_and_the_key_to_register() {
        use crate::app::restart::RestartHandle;
        use crate::clients::PortalClient;
        use crate::crypto::BlsKeyPair;
        use crate::server::admin::NodeIdentity;
        use std::sync::Arc;

        let (mut state, dir) = state_with(&[]).await;
        let keypair = Arc::new(BlsKeyPair::generate().unwrap());
        let pubkey = keypair.public_key_hex();
        state.runtime = crate::app::lifecycle::NodeRuntime::for_tests(None, None);
        state.admin = AdminState::with_identity(
            NodeIdentity::new(
                keypair,
                PortalClient::try_new("http://portal.invalid", dir.path()).unwrap(),
                None,
                None,
            ),
            RestartHandle::new(),
        );

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["node_id"], Value::Null);
        assert_eq!(value["registration"]["supported"], true);
        assert_eq!(value["registration"]["registered"], false);
        assert_eq!(value["registration"]["bls_pubkey"], pubkey);
        assert_eq!(value["registration"]["node_id"], Value::Null);
        assert_eq!(value["registration"]["signer_id"], Value::Null);
    }

    #[tokio::test]
    async fn status_reports_a_registered_node_with_its_signer_id() {
        use crate::app::restart::RestartHandle;
        use crate::clients::PortalClient;
        use crate::crypto::BlsKeyPair;
        use crate::server::admin::{NodeIdentity, RegisteredNode};
        use std::sync::Arc;

        let (mut state, dir) = state_with(&[]).await;
        state.admin = AdminState::with_identity(
            NodeIdentity::new(
                Arc::new(BlsKeyPair::generate().unwrap()),
                PortalClient::try_new("http://portal.invalid", dir.path()).unwrap(),
                Some(RegisteredNode {
                    node_id: "node-status".to_string(),
                    signer_id: 42,
                }),
                None,
            ),
            RestartHandle::new(),
        );

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["registration"]["registered"], true);
        assert_eq!(value["registration"]["node_id"], "node-status");
        assert_eq!(value["registration"]["signer_id"], 42);
    }

    /// On a mnemonic node the address is the whole message: it is what a Portal
    /// admin has to whitelist, and the page exists so nobody has to grep a
    /// container's logs for it.
    #[tokio::test]
    async fn status_reports_the_derived_account_and_address() {
        use crate::app::restart::RestartHandle;
        use crate::clients::PortalClient;
        use crate::crypto::{BitcoinNetwork, BlsKeyPair, PublicIdentity};
        use crate::server::admin::NodeIdentity;
        use std::sync::Arc;

        let (mut state, dir) = state_with(&[]).await;
        let keypair = BlsKeyPair::generate().unwrap();
        state.admin = AdminState::with_identity(
            NodeIdentity::new(
                Arc::new(BlsKeyPair::from_secret_key_hex(&keypair.secret_key_hex()).unwrap()),
                PortalClient::try_new("http://portal.invalid", dir.path()).unwrap(),
                None,
                Some(PublicIdentity {
                    account: 2,
                    network: BitcoinNetwork::Signet,
                    xpubkey: "tpubExample".to_string(),
                    taproot_address: "tb1pexample".to_string(),
                    node_id: "node-derived".to_string(),
                    bls_pubkey: keypair.public_key_hex(),
                    schnorr_binding_sig: "bb".repeat(64),
                }),
            ),
            RestartHandle::new(),
        );

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["registration"]["registered"], false);
        assert_eq!(value["registration"]["derived"]["account"], 2);
        assert_eq!(value["registration"]["derived"]["network"], "signet");
        assert_eq!(
            value["registration"]["derived"]["taproot_address"],
            "tb1pexample"
        );
        assert_eq!(value["registration"]["derived"]["node_id"], "node-derived");
    }

    /// An imported node has no account to report, and the page keys the wallet
    /// flow off this being null.
    #[tokio::test]
    async fn status_reports_no_derived_block_for_an_imported_key() {
        use crate::app::restart::RestartHandle;
        use crate::clients::PortalClient;
        use crate::crypto::BlsKeyPair;
        use crate::server::admin::NodeIdentity;
        use std::sync::Arc;

        let (mut state, dir) = state_with(&[]).await;
        state.admin = AdminState::with_identity(
            NodeIdentity::new(
                Arc::new(BlsKeyPair::generate().unwrap()),
                PortalClient::try_new("http://portal.invalid", dir.path()).unwrap(),
                None,
                None,
            ),
            RestartHandle::new(),
        );

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["registration"]["derived"], Value::Null);
    }

    /// Tests that never load a key still read this block, so it has to say
    /// "nothing to register" rather than omit the field.
    #[tokio::test]
    async fn status_reports_registration_as_unsupported_without_a_key() {
        let (state, _dir) = state_with(&[]).await;

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["registration"]["supported"], false);
        assert_eq!(value["registration"]["registered"], false);
        assert_eq!(value["registration"]["bls_pubkey"], Value::Null);
    }

    /// The page needs this before the operator commits to anything, so the
    /// restart checkbox can be disabled with a reason rather than rejected.
    ///
    /// It follows the slots, and has to: a node set up through the wizard has
    /// no keystore when its `/admin` first answers and a machine slot moments
    /// later, in the same process and the same session.
    #[tokio::test]
    async fn status_reports_whether_a_restart_is_available() {
        use crate::crypto::keystore::SlotKind;

        let (state, _dir) = state_with(&[]).await;

        assert_eq!(
            node_status(&state, SESSION_EXPIRY).await.unwrap()["restart_available"],
            false,
            "a node with no keystore has nothing to come back up on"
        );

        state.runtime.set_slots(vec![SlotKind::Passphrase]);
        assert_eq!(
            node_status(&state, SESSION_EXPIRY).await.unwrap()["restart_available"],
            false,
            "a slot only a human can supply is not a way back from a restart"
        );

        state
            .runtime
            .set_slots(vec![SlotKind::File, SlotKind::Passphrase]);
        assert_eq!(
            node_status(&state, SESSION_EXPIRY).await.unwrap()["restart_available"],
            true
        );
    }

    /// An empty node answers zeros rather than erroring on `SUM(NULL)`.
    #[tokio::test]
    async fn status_of_an_empty_node_is_all_zeros() {
        let (state, _dir) = state_with(&[]).await;

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["agreements"]["total"], 0);
        assert_eq!(value["agreements"]["stored_bytes"], 0);
    }

    #[tokio::test]
    async fn gcs_status_reports_no_local_directory() {
        let (mut state, _dir) = state_with(&[(10, true)]).await;
        state.storage_backend = StorageBackend {
            method: StorageMethod::Gcs,
            gcs_client: None,
        };

        let value = node_status(&state, SESSION_EXPIRY).await.unwrap();

        assert_eq!(value["storage"]["method"], "gcs");
        assert_eq!(value["session_expires_at"], SESSION_EXPIRY);
        // Spelled as an equality rather than `is_null()`: `ExprTrait` is in
        // scope from the query above and its own `is_null` wins method
        // resolution on a `serde_json::Value`.
        assert_eq!(value["storage"]["directory"], Value::Null);
    }

    /// A row that was never post-processed counts as neither placed nor
    /// awaiting — exactly the split `rebuild_ledger` makes, and the reason the
    /// two numbers are worth showing separately.
    #[tokio::test]
    async fn ledger_splits_placed_from_files_still_awaiting_a_slot() {
        let (state, _dir) = state_with(&[]).await;
        insert_stored(&state.db, 0, Some(3)).await;
        insert_stored(&state.db, 1, Some(7)).await;
        insert_stored(&state.db, 2, None).await;
        // Downloaded but never post-processed: no root, so no ledger entry.
        AgreementFixture {
            downloaded: true,
            ..AgreementFixture::new("AGR-raw", "FILE-raw")
        }
        .into_active_model()
        .insert(&state.db)
        .await
        .unwrap();

        let ledger = &node_status(&state, SESSION_EXPIRY).await.unwrap()["ledger"];

        assert_eq!(ledger["placed"], 2);
        assert_eq!(ledger["awaiting_ledger_index"], 1);
        assert_eq!(ledger["highest_slot"], 7);
        assert_eq!(ledger["rebuild_blocked"], false);
    }

    /// An empty node has no slot at all, and must not read as blocked — that
    /// would send an operator chasing a wall it has not reached.
    #[tokio::test]
    async fn an_empty_ledger_is_not_blocked() {
        let (state, _dir) = state_with(&[]).await;

        let ledger = &node_status(&state, SESSION_EXPIRY).await.unwrap()["ledger"];

        assert_eq!(ledger["placed"], 0);
        assert_eq!(ledger["highest_slot"], Value::Null);
        assert_eq!(ledger["rebuild_blocked"], false);
    }

    /// A predicate that disagrees with the ledger it is predicting is worse
    /// than no signal at all, so it is pinned against the real
    /// `rebuild_ledger` — and pinned at the boundary, which is the only place
    /// an off-by-one could hide.
    ///
    /// For a lone stored file, `leaf_count = slot + 1` and the ledger accepts
    /// up to `placed + gap`: slot `gap` is the last one that still rebuilds.
    #[tokio::test]
    async fn the_blocked_predicate_agrees_with_an_actual_rebuild() {
        use crate::app::tasks::downloadagreements::rebuild_ledger;

        let gap = i64::try_from(MAX_LEDGER_INDEX_SPARSITY_GAP).unwrap();

        for (slot, expect_blocked) in [(gap, false), (gap + 1, true)] {
            let (state, dir) = state_with(&[]).await;
            insert_stored(&state.db, 0, Some(slot)).await;

            let ledger = &node_status(&state, SESSION_EXPIRY).await.unwrap()["ledger"];
            let blocked = ledger["rebuild_blocked"] == Value::Bool(true);
            let rebuild_failed = rebuild_ledger(&state.db, dir.path()).await.is_err();

            assert_eq!(ledger["highest_slot"], slot);
            assert_eq!(blocked, expect_blocked, "slot {slot}");
            assert_eq!(
                blocked, rebuild_failed,
                "the verdict predicted for slot {slot} must match what the ledger does"
            );
        }
    }

    /// A database the node cannot read is a 500, not a status page full of
    /// zeros that would talk an operator into a reset. Each count is its own
    /// query, so a table missing on either side has to surface the same way.
    #[tokio::test]
    async fn status_surfaces_database_errors() {
        for db in [
            crate::testutils::setup_challenges_db().await,
            crate::testutils::setup_agreements_db().await,
        ] {
            let (mut state, _dir) = state_with(&[]).await;
            state.db = db;

            let err = node_status(&state, SESSION_EXPIRY).await.unwrap_err();

            assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(err.code, error_codes::DATABASE_ERROR);
        }
    }

    /// The bond as the daemon last read it, with the policy it acts on. A node
    /// whose daemon has not read anything yet says so rather than showing
    /// zeros an operator could mistake for an empty stake.
    #[tokio::test]
    async fn status_reports_the_bond_the_daemon_last_read() {
        use crate::clients::portal::RegistryEntry;

        let (state, _dir) = state_with(&[]).await;
        let before = node_status(&state, SESSION_EXPIRY).await.unwrap();
        assert_eq!(before["staking"]["reported"], false);
        assert_eq!(before["staking"]["stake"], Value::Null);
        assert_eq!(before["staking"]["policy"]["auto_stake"], true);

        let entry: RegistryEntry = serde_json::from_value(json!({
            "signer_id": 42,
            "x_only_pubkey": "ab",
            "bls_pubkey": null,
            "next_nonce": 1,
            "kor_balance": "5",
            "stake": "995",
            "stake_reserved": "30",
            "stake_available": "965",
            "stake_withdrawal_height": null,
            "bond_cleanup_pending": false,
            "reward_balance": "2.5"
        }))
        .unwrap();
        state
            .runtime
            .staking()
            .observe(Some(&entry), std::time::Instant::now());

        let after = node_status(&state, SESSION_EXPIRY).await.unwrap();
        let staking = &after["staking"];
        assert_eq!(staking["reported"], true);
        assert_eq!(staking["kor_balance"], "5");
        assert_eq!(staking["stake"], "995");
        assert_eq!(staking["reserved"], "30");
        assert_eq!(staking["available"], "965");
        assert_eq!(staking["reward_balance"], "2.5");
        assert_eq!(staking["withdrawal_height"], Value::Null);
        assert_eq!(staking["bond_cleanup_pending"], false);
    }
}
