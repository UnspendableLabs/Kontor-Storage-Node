//! Bonded stake: keeping it topped up, and not joining what it cannot cover.
//!
//! Since the staking upgrade Kontor refuses `join-agreement` unless the node
//! has a bonded stake in the `staking` contract whose *unreserved* part covers
//! the agreement's `required-collateral`. Each membership then reserves that
//! amount, and a challenge the node misses is settled by slashing
//! `30 × required-collateral`. A stake slashed to zero puts the node in bond
//! cleanup: Kontor unwinds its memberships, and until it is done the node can
//! neither join nor add stake.
//!
//! The node never talks to Kontor. It reads its bond from the Portal's signer
//! entry (Portal `docs/node-portal-contract.md` §3) once per cycle — the same
//! request the nonce resync already makes — signs `add-stake` / `claim-rewards`
//! itself, and hands them to the Portal's relay (§2 of the same document). This
//! module decides *what* to sign:
//!
//! - **Auto-stake.** Everything above a gas reserve goes into the bond, up to an
//!   optional target, in one `add-stake` per cycle at most.
//! - **Auto-claim.** Rewards past a threshold are claimed, rate-limited, so the
//!   next cycle's auto-stake can bond them.
//! - **Join budget.** Before a ready agreement is downloaded, its collateral is
//!   checked against the unreserved stake, minus what this node has already
//!   committed to joins that have not executed yet. The Portal composes joins
//!   into the same batch as the agreement's `create-agreement`, so at join time
//!   the collateral is almost never known yet: those joins are budgeted at an
//!   estimate instead (see [`JoinBudget::decide`]).
//! - **Exit.** Once the operator's `begin-unstake` has executed, the node leaves
//!   its agreements, several leaves in flight at a time, and, when none is
//!   left, withdraws the bond (see [`ExitInputs`]). A node that has exited
//!   bonds nothing more on its own, and that is recorded in its database: a
//!   restart does not put the returned bond back at stake. The operator
//!   resumes staking from `/admin`.
//!
//! # Knowing when an op has landed
//!
//! The relay answers `202 queued`; nothing tells the node when the op executes.
//! The nonce does. Kontor's `next_nonce` only moves past an op's nonce once
//! that op has run, so an op is *in flight* while `next_nonce <= its nonce`,
//! and landed after. This is deliberately not the same as "succeeded": an op
//! that executed and failed, or that lost its nonce to another op, also
//! consumes it. That is fine because every decision here is recomputed from the
//! state the Portal reports — if a top-up did not happen, the balance is still
//! there next cycle and a new one is sent, after the same hour's pause a
//! refusal earns: a top-up Kontor refused for a reason neither the snapshot
//! nor the Portal's pre-check saw would otherwise be signed again every cycle,
//! burning gas each block — unless the Portal's listing says Kontor never ran
//! it: an op the Portal retired for a stale nonce, or that lost its nonce to a
//! proof batched ahead of it, is signed again at once (see
//! [`StakeTracker::classify_landed`]). What the in-flight rule prevents is the other
//! failure: re-sending the same 995 KOR every 30 seconds while the first one
//! waits for a block.
//!
//! An op the Portal accepted and then dropped would never consume its nonce,
//! so an op that has waited [`OP_LANDING_CHECK_INTERVAL`] is looked up in the
//! Portal's own listing of this node's ops (§2, `GET /api/nodes/{node_id}/ops`)
//! before it is given up: it stays in flight while the Portal still lists it
//! as `queued` or `submitted` — a signer's newer ops wait while its earlier
//! ones sit in an unconfirmed batch, so half an hour is routine — and is
//! declared dropped only when the Portal no longer lists it, or lists it as
//! `failed`. A listing that cannot be read leaves it in flight and is asked
//! for again on the next cycle, for as long as it takes: only the Portal's
//! word, or the nonce, ends the wait (§2: an op still `queued` or `submitted`
//! has not been lost and must not be signed again), and a Portal that cannot
//! say what it holds may hold the op. Giving an op up too early is the expensive
//! mistake here: the same `add-stake` signed again with a fresh nonce makes
//! both execute, and the bond overshoots its target. The same listing settles
//! an op whose answer never came — the request timed out, or the Portal
//! answered with a 5xx: the Portal may well hold it, so it is kept in flight
//! like one it accepted, not signed again.
//!
//! All of this lives in memory. A new process therefore starts by asking the
//! Portal which of the node's ops it still holds (§2,
//! `?status=queued|submitted`), adopts each as an op in flight and moves its
//! nonce counter past every one of them (see
//! [`StakeTracker::adopt_pending_ops`]): the top-up the previous process
//! queued is waited for, not signed again, and its nonce is not reused. The
//! same is done on every activation, since the tracker outlives the client
//! (see [`bootstrap_stake`]). What an exit has to carry across a restart —
//! when its withdrawal delay started, and that it finished — is kept in the
//! database instead (see [`restore_withdrawal_start`]).
//!
//! # Why the op goes out last
//!
//! The daemon sends its stake op — or, during an exit, its leaves — at the end
//! of the cycle, after joins and proofs, so it holds the cycle's highest
//! nonces. Should two ops ever collide
//! on a nonce, the Portal keeps the one it composes first and drops the other;
//! a dropped proof is a slash, a dropped `add-stake` is a retry. Losing is cheap
//! for stake ops, and this ordering keeps it that way.
//!
//! # Old Portals
//!
//! A Portal predating staking sends none of the signer stake fields (Portal
//! `docs/node-portal-contract.md` §3). That is not "zero stake": the node then
//! keeps its pre-staking behaviour — joins everything, signs no stake op. A
//! Portal that knows about staking always sends them, as `null` when it could
//! not read them from Kontor: a `stake` key, whatever it holds, is such a
//! Portal, from the very first read. Against one, a cycle where the stake
//! cannot be read joins nothing rather than joining blind.

use crate::app::tasks::getnewagreements::ReadyListing;
use crate::clients::http_helpers::status_and_code;
use crate::clients::kontor_op::DEFAULT_GAS_LIMIT;
use crate::clients::kor::Kor;
use crate::clients::portal::{NodeOp, NodeOpRecord, RegistryEntry, UnsettledOp, STAKE_UNREAD};
use crate::clients::PortalClient;
use anyhow::Context as _;
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// The smallest free balance worth a top-up.
pub const MIN_TOP_UP: Kor = Kor::ONE;

/// Kontor's price of one gas unit, in 10⁻¹⁸ KOR: `max(execution price,
/// collateral unit price)`, both 10⁻⁹ KOR at 80913826 (`Pricing::gas_hold`,
/// `core/indexer/src/protocol/v1/pricing.rs`).
const GAS_PRICE_UNITS: u128 = 1_000_000_000;

/// The smallest gas reserve with which an `add-stake` can run at all.
///
/// Before it runs a call, Kontor holds `gas_limit × gas price` from the payer
/// (`with_payment`, `core/indexer/src/protocol/v1/fees.rs`), and refuses the
/// call if the balance does not cover it. An `add-stake` of the whole balance
/// therefore always fails: once the hold is taken, the amount is no longer
/// there. The reserve must cover at least one op's hold — [`DEFAULT_GAS_LIMIT`]
/// gas, 0.0001 KOR. That is a floor, not a recommendation: it pays for the
/// top-up and nothing after it.
pub const MIN_GAS_RESERVE: Kor = Kor::from_units(DEFAULT_GAS_LIMIT as u128 * GAS_PRICE_UNITS);

/// How long an accepted op may stay unreflected before the node asks the
/// Portal whether it still holds it — and how often it asks again while the
/// Portal says it does. Long enough for a compose round and a couple of
/// blocks, so most ops never prompt the question.
pub const OP_LANDING_CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How long a wait may last before it is reported as a problem rather than
/// as routine: an op still in flight, or one whose nonce went and whose
/// outcome the Portal has not given.
///
/// It no longer ends an in-flight op. An op is given up on the Portal's word
/// only — its listing no longer shows it, or shows it `failed` — or when its
/// nonce is consumed. One the Portal keeps listing is waited for however long
/// that takes (Portal `docs/node-portal-contract.md` §2: an op still `queued`
/// or `submitted` has not been lost and must not be signed again) — a batch
/// the operator signs late, or that the Portal cancels and re-queues,
/// routinely takes longer than this. And one the Portal cannot be asked
/// about is waited for too: a listing that fails for six hours says nothing
/// about what the Portal holds, and signing the op again on that silence was
/// how the same top-up came to execute twice. Past this length the wait is
/// logged as an error on every failed attempt, so the operator hears of it.
///
/// It still bounds how long a landed op waits for the Portal to say how it
/// ended (see [`StakeTracker::classify_landed`]).
pub const OP_LANDING_HARD_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);

/// How long a join's collateral stays committed while the Portal cannot be
/// asked whether it still holds the join.
///
/// A join is released on evidence: its nonce consumed, or the Portal's rows
/// saying it will not execute (see [`settle_pending_joins`] and
/// [`StakeTracker::join_verified`]). The Portal can hold a join for a day by
/// default — an unsigned batch waits that long for its signature — so no
/// shorter clock may release it: released while the Portal still holds it,
/// the collateral is committed twice, and the join that loses is refused on
/// chain. Only when neither the ready listing nor the agreement's detail can
/// be read for this long is the join given up, twice the Portal's default
/// hold.
pub const JOIN_COMMITMENT_BACKSTOP: Duration = Duration::from_secs(48 * 60 * 60);

/// Agreement details read per cycle to settle pending joins (see
/// [`StakeTracker::joins_to_verify`]), so a node with many joins in flight
/// does not spend its cycle asking about them.
pub const MAX_JOIN_CHECKS_PER_CYCLE: usize = 8;

/// At most one automatic `claim-rewards` per this interval. Each claim costs
/// gas, and rewards accrue per block, so claiming more often only buys dust.
pub const CLAIM_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long an `add-stake`, or a `leave-agreement` for one agreement, waits
/// after the Portal refused it. A refusal is the Portal saying no to that op,
/// and it says the same thing to the same op signed again the next cycle; an
/// hour, like a claim, lets whatever it disagreed with change.
pub const REFUSED_OP_RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long joins stay paused after the Portal refuses one with a join
/// pre-check code (Portal `docs/node-portal-contract.md` §5).
///
/// The refusal means the node's own view of its stake disagreed with the
/// Portal's. Retrying every cycle would download a file and be refused again
/// each time; waiting lets the next few registry reads catch up.
pub const JOIN_REFUSAL_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// Joins of unknown collateral allowed in one cycle, whatever the budget says.
///
/// The estimate is a guess, so the number of guesses is bounded too: a node
/// that underestimates by a lot still takes on a handful of agreements per
/// cycle rather than every ready one. Being wrong is cheap — Kontor refuses a
/// join the stake cannot cover, which is not slashable — but each wrong guess
/// costs a download and a fee.
pub const MAX_UNKNOWN_COLLATERAL_JOINS_PER_CYCLE: usize = 3;

/// How long a collateral seen on an agreement informs the estimate for
/// agreements whose collateral is not known yet.
pub const COLLATERAL_MEMORY: Duration = Duration::from_secs(24 * 60 * 60);

/// How many of the exit's `leave-agreement` ops may be in flight at once.
///
/// Every other op goes out one at a time: the next is decided from what the
/// last one changed. A leave changes nothing the next leave depends on, and
/// one at a time — one per block at best, since each waits for its nonce to
/// be consumed — a node with more than a couple of thousand memberships could
/// not leave them all within Kontor's 2028-block withdrawal delay, and went on
/// proving and risking slashes for as many blocks as it had memberships. The
/// Portal takes 64 live relayed ops per node and batches 50 per transaction;
/// 32 leaves room for both and empties some 60 000 memberships within the
/// delay.
pub const MAX_LEAVES_IN_FLIGHT: usize = 32;

/// Leaves signed in one cycle at most, so a long exit does not turn the end
/// of every cycle into a burst of relay requests.
pub const MAX_LEAVES_PER_CYCLE: usize = 8;

/// Kontor's `WITHDRAWAL_DELAY`: `2016 + ACTIVATION_DELAY (12)` blocks between
/// `begin-unstake` and the first height `withdraw-stake` accepts
/// (`native-contracts/staking`).
pub const WITHDRAWAL_DELAY_BLOCKS: u64 = 2028;

/// Block interval assumed to turn that delay into a time. The node has no
/// view of the chain tip, so it times the delay from when it first saw the
/// withdrawal height — a moment it records in its database, so a restart does
/// not start the two weeks over; faster blocks only make it wait longer than
/// it had to, and the operator can always withdraw by hand from `/admin`.
pub const ASSUMED_BLOCK_TIME: Duration = Duration::from_secs(600);

/// How often an automatic `withdraw-stake` is retried after one that executed
/// without returning the bond (too early, or an obligation the node did not
/// know about).
pub const WITHDRAW_RETRY_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// The retry interval after a `withdraw-stake` Kontor refused for
/// [`KONTOR_UNRESOLVED_OBLIGATIONS`]: an obligation the node's rows did not
/// show, which the re-read of its memberships and the next cycles' challenge
/// sync pick up. Short, like a refusal, rather than the six hours a withdrawal
/// made too early waits.
pub const WITHDRAW_OBLIGATION_RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Kontor's `withdraw-stake` error while the node still has storage
/// obligations (`ensure_no_storage_obligations`, `native-contracts/staking`):
/// an active membership, or a challenge not settled yet — `active`, or
/// `expired`/`failed`/`invalid` with its penalty still to be applied.
pub const KONTOR_UNRESOLVED_OBLIGATIONS: &str = "unresolved storage obligations";

/// How long after the Portal marks a challenge `failed` it still counts as an
/// obligation Kontor has to settle. The Portal renders every challenge Kontor
/// holds `expired`, `failed` or `invalid` as `failed`, and Kontor keeps the
/// obligation until the penalty is applied — a bounded amount of settlement
/// work per block, so normally the next block or two. An hour covers that
/// with room; past it, a `withdraw-stake` Kontor still refuses is retried
/// after [`WITHDRAW_OBLIGATION_RETRY_INTERVAL`].
pub const FAILED_CHALLENGE_SETTLEMENT_GRACE: Duration = Duration::from_secs(60 * 60);

/// How the node manages its bond. The policy is the node's own: the Portal
/// relays the ops it signs and imposes none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakePolicy {
    /// Sign `add-stake` and `claim-rewards` automatically. Off, the node signs
    /// no money-moving op on its own; joins are still gated on the stake.
    pub auto_stake: bool,
    /// KOR kept liquid to pay gas for joins and proofs. Never staked. At
    /// least [`MIN_GAS_RESERVE`].
    pub gas_reserve: Kor,
    /// Cap on the total bond. `None` stakes everything above the reserve.
    pub stake_target: Option<Kor>,
    /// Claim rewards once at least this much is claimable.
    pub claim_threshold: Kor,
    /// What a join whose collateral is not known yet is budgeted at — the
    /// floor of the estimate, raised to the largest collateral seen in the
    /// last [`COLLATERAL_MEMORY`].
    pub unknown_collateral_estimate: Kor,
}

impl Default for StakePolicy {
    fn default() -> Self {
        Self {
            auto_stake: true,
            gas_reserve: Kor::whole(5),
            stake_target: None,
            claim_threshold: Kor::ONE,
            unknown_collateral_estimate: Kor::whole(10),
        }
    }
}

/// The node's bond as one registry read reported it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StakeSnapshot {
    /// Spendable KOR, `None` if the Portal did not say.
    pub kor_balance: Option<Kor>,
    pub stake: Kor,
    /// Stake held by joined agreements, when reported.
    pub reserved: Option<Kor>,
    /// What new joins can still reserve. `None` when the Portal reported
    /// neither it nor the reserved part this time: the bond is known, how
    /// much of it is free is not, and no join is made against it.
    pub available: Option<Kor>,
    /// Non-null once `begin-unstake` has executed.
    pub withdrawal_height: Option<u64>,
    /// Whether the stake was slashed to zero and Kontor is still unwinding
    /// the node's memberships; `None` when the Portal could not read it
    /// (Portal `docs/node-portal-contract.md` §3: null is unknown, not
    /// false).
    pub bond_cleanup_pending: Option<bool>,
    pub reward_balance: Option<Kor>,
    /// Kontor's next nonce for this signer at the time of the read.
    pub next_nonce: u64,
}

impl StakeSnapshot {
    /// Parse the Portal `docs/node-portal-contract.md` §3 fields of a signer
    /// entry.
    ///
    /// `None` when the Portal does not report a stake — absent, `null`, or
    /// unreadable — which is what an old Portal looks like. `stake_available`
    /// falls back to `stake − stake_reserved` when only those two are sent.
    ///
    /// An entry with the stake and neither of them still makes a snapshot,
    /// with `available` unknown. The Portal reads the reservation from another
    /// contract than the bond, and when that one view fails it sends both
    /// `stake_reserved` and `stake_available` as `null`: joining against a
    /// stake whose reservations are unknown would be joining blind, so joins
    /// close (see [`StakeTracker::join_budget`]) — but the bond, the balance
    /// and the withdrawal are known, and the top-up, the claims, the exit and
    /// `/admin` do not wait for a view none of them reads.
    #[must_use]
    pub fn from_entry(entry: &RegistryEntry) -> Option<Self> {
        // A `null` stake is the Portal saying it could not read the bond:
        // nothing to parse, and nothing to warn about field by field.
        let stake = entry
            .stake
            .as_deref()
            .filter(|raw| *raw != STAKE_UNREAD)
            .and_then(|raw| parse_field("stake", Some(raw)))?;
        let reserved = parse_field("stake_reserved", entry.stake_reserved.as_deref());
        let available = parse_field("stake_available", entry.stake_available.as_deref())
            .or_else(|| reserved.map(|reserved| stake.saturating_sub(reserved)));

        Some(Self {
            kor_balance: parse_field("kor_balance", entry.kor_balance.as_deref()),
            stake,
            reserved,
            available,
            withdrawal_height: entry.stake_withdrawal_height,
            bond_cleanup_pending: entry.bond_cleanup_pending,
            reward_balance: parse_field("reward_balance", entry.reward_balance.as_deref()),
            // Not known until the signer's first op: nothing has landed yet,
            // which is what 0 says about every op in flight.
            next_nonce: entry.next_nonce.unwrap_or(0),
        })
    }

    /// Why this bond cannot take on a new agreement at all, if it cannot.
    fn join_blocker(&self) -> Option<SkipReason> {
        if self.bond_cleanup_pending == Some(true) {
            Some(SkipReason::BondCleanupPending)
        } else if self.withdrawal_height.is_some() {
            Some(SkipReason::WithdrawalRequested)
        } else if self.stake.is_zero() {
            Some(SkipReason::NoStake)
        } else {
            None
        }
    }
}

fn parse_field(name: &str, raw: Option<&str>) -> Option<Kor> {
    let raw = raw?;
    match Kor::parse(raw) {
        Ok(amount) => Some(amount),
        Err(err) => {
            warn!("ignoring the Portal's {name}: {err:#}");
            None
        }
    }
}

/// The top-up the policy calls for, if any.
///
/// `min(kor_balance − reserve, target − stake)`, sent only when the free part
/// is at least [`MIN_TOP_UP`] and the target still has room. The amount itself
/// may be smaller than the minimum when it closes the gap to the target — one
/// op, then nothing more to do.
///
/// Nothing while bond cleanup is pending or a withdrawal is requested: Kontor
/// refuses `add-stake` in both. And nothing on an empty bond while the Portal
/// could not say whether cleanup is pending (`null`, Portal
/// `docs/node-portal-contract.md` §3): an empty bond is exactly what a slash
/// to zero leaves, and an `add-stake` sent into a cleanup is refused on chain
/// at the cost of its gas, hour after hour. The next read that answers
/// decides.
#[must_use]
pub fn top_up_amount(policy: &StakePolicy, snapshot: &StakeSnapshot) -> Option<Kor> {
    if snapshot.bond_cleanup_pending == Some(true) || snapshot.withdrawal_height.is_some() {
        return None;
    }
    if snapshot.bond_cleanup_pending.is_none() && snapshot.stake.is_zero() {
        return None;
    }
    let free = snapshot.kor_balance?.saturating_sub(policy.gas_reserve);
    if free < MIN_TOP_UP {
        return None;
    }
    let amount = match policy.stake_target {
        Some(target) => free.min(target.saturating_sub(snapshot.stake)),
        None => free,
    };
    (!amount.is_zero()).then_some(amount)
}

/// Why a ready agreement was left alone this cycle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SkipReason {
    BondCleanupPending,
    WithdrawalRequested,
    NoStake,
    /// The registry could not be read this cycle, on a Portal that reports
    /// stake: joining now would be joining blind.
    StakeUnknown,
    /// A recent join was refused by the Portal; the code it gave.
    RecentlyRefused(String),
    /// Not in this cycle's ready listing, so its collateral is unknown.
    NotListed,
    /// The collateral is not known and this cycle's guesses are used up
    /// ([`MAX_UNKNOWN_COLLATERAL_JOINS_PER_CYCLE`]), or the Portal sent one
    /// the node cannot read.
    CollateralUnknown,
    /// The operator has started leaving: an unstake is queued or in flight.
    Leaving,
    /// Kontor refuses joins on an agreement that requires nothing.
    NoCollateralRequirement,
    InsufficientCollateral,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::BondCleanupPending => f.write_str("bond cleanup pending"),
            SkipReason::WithdrawalRequested => f.write_str("withdrawal requested"),
            SkipReason::NoStake => f.write_str("no bonded stake"),
            SkipReason::StakeUnknown => f.write_str("stake unknown this cycle"),
            SkipReason::RecentlyRefused(code) => write!(f, "Portal refused a join ({code})"),
            SkipReason::NotListed => f.write_str("not in the ready listing"),
            SkipReason::CollateralUnknown => {
                f.write_str("collateral unknown and this cycle's estimates used up")
            }
            SkipReason::Leaving => f.write_str("leaving: unstake requested"),
            SkipReason::NoCollateralRequirement => f.write_str("no collateral requirement"),
            SkipReason::InsufficientCollateral => f.write_str("insufficient unreserved stake"),
        }
    }
}

/// Kontor's withdrawal delay as the node counts it. The node cannot see the
/// chain tip, so it counts [`WITHDRAWAL_DELAY_BLOCKS`] of
/// [`ASSUMED_BLOCK_TIME`] from the first read that showed the withdrawal
/// height; faster blocks only make it wait longer than it had to, and the
/// operator can always withdraw by hand from `/admin`.
#[derive(Clone, Copy, Debug)]
struct WithdrawalTimer {
    /// When the delay started: the first read that showed the height, in this
    /// process or — restored from the database — in an earlier one.
    started_at: DateTime<Utc>,
    /// When this process started counting.
    seen: Instant,
    /// How much of the delay had already run by `seen`: zero for a start this
    /// process witnessed itself.
    head_start: Duration,
}

impl WithdrawalTimer {
    fn starting_now(now: Instant) -> Self {
        Self {
            started_at: Utc::now(),
            seen: now,
            head_start: Duration::ZERO,
        }
    }

    fn elapsed(&self, now: Instant) -> Duration {
        now.duration_since(self.seen)
            .saturating_add(self.head_start)
    }

    /// When the node first tries `withdraw-stake` on its own.
    fn due_at(&self) -> DateTime<Utc> {
        self.started_at + chrono::Duration::from_std(withdrawal_delay()).unwrap_or_default()
    }
}

/// [`WITHDRAWAL_DELAY_BLOCKS`] at [`ASSUMED_BLOCK_TIME`].
fn withdrawal_delay() -> Duration {
    ASSUMED_BLOCK_TIME.saturating_mul(WITHDRAWAL_DELAY_BLOCKS as u32)
}

/// An op whose nonce Kontor has consumed, waiting for the Portal to say how
/// it ended (see [`StakeTracker::classify_landed`]).
#[derive(Clone, Debug)]
struct LandedOp {
    op: NodeOp,
    nonce: u64,
    /// When the nonce was seen consumed.
    landed: Instant,
    /// The Portal never confirmed storing the op (see [`InFlight::unsettled`]).
    unsettled: bool,
    /// The operator asked for it (see [`InFlight::requested`]).
    requested: bool,
}

/// An op the relay accepted and Kontor has not executed yet.
#[derive(Clone, Debug)]
struct InFlight {
    op: NodeOp,
    nonce: u64,
    sent: Instant,
    sent_at: DateTime<Utc>,
    /// The relay gave no answer that says whether it stored the op (see
    /// [`StakeTracker::record_unsettled`]): the Portal may hold it, or may
    /// never have seen it.
    unsettled: bool,
    /// The operator asked for this op from `/admin` — every `begin-unstake`,
    /// and a `withdraw-stake` made by hand. The policy does not plan these
    /// again on its own, so one that never ran is put back as a request
    /// instead of being forgotten.
    requested: bool,
    /// The bond when the op was planned, for an op this process planned: what
    /// an `add-stake` has to exceed to have raised it. `None` for an op
    /// adopted from the Portal's listing, whose starting point is not known.
    stake_before: Option<Kor>,
    /// When the Portal's listing was last read for it. A listing that could
    /// not be read does not count: the question is asked again next cycle.
    checked: Option<Instant>,
    /// When the Portal's listing last said it still holds the op.
    vouched: Option<Instant>,
    /// When the Portal's listing first said it lost track of the op (see
    /// [`PORTAL_ORPHANED_HEAD`]): its transaction may still confirm, so the
    /// op stays in flight for [`OP_LANDING_HARD_TIMEOUT`] from here.
    orphaned: Option<Instant>,
}

impl InFlight {
    /// How long the op has gone without the Portal's listing vouching for
    /// it, counted from when it was sent while the Portal has not been heard.
    fn unvouched_for(&self, now: Instant) -> Duration {
        now.duration_since(self.vouched.unwrap_or(self.sent))
    }
}

/// A join sent but not yet executed: its collateral is not in `stake_reserved`
/// yet, so it is held back from the budget until the nonce says it is.
#[derive(Clone, Debug)]
struct PendingJoin {
    agreement_id: String,
    collateral: Kor,
    nonce: u64,
    /// When the Portal's rows last showed the join still held — its row
    /// `valid` on an agreement still open — or when it was sent.
    heard: Instant,
    /// When the Portal's rows were last read for it, in the ready listing or
    /// in the agreement's detail.
    checked: Instant,
}

#[derive(Debug, Default)]
struct TrackerState {
    policy: StakePolicy,
    /// The latest snapshot, `None` when the last read reported none.
    snapshot: Option<StakeSnapshot>,
    /// The last snapshot that was read at all, kept through failed reads so a
    /// slash that happens across one is still noticed.
    last_known: Option<StakeSnapshot>,
    observed_at: Option<DateTime<Utc>>,
    /// Sticky: this Portal has reported a stake at least once.
    portal_reports_stake: bool,
    /// The ops the relay took that Kontor has not executed yet, by ascending
    /// nonce. One at a time for every op but the exit's leaves, of which up to
    /// [`MAX_LEAVES_IN_FLIGHT`] go together (see [`StakeTracker::plan`]).
    in_flight: Vec<InFlight>,
    /// The Portal's listing of this node's `queued` and `submitted` ops has
    /// been read once in this process, and the newest adopted as in flight
    /// (see [`StakeTracker::adopt_pending_ops`]). Nothing is planned before.
    pending_ops_checked: bool,
    pending_joins: Vec<PendingJoin>,
    last_claim: Option<Instant>,
    /// When the Portal last refused an `add-stake` (`None` key) or a
    /// `leave-agreement` (its agreement).
    refused: HashMap<RefusedOp, Instant>,
    /// The ops whose nonce Kontor consumed and whose outcome the registry read
    /// does not settle, each waiting for the Portal's listing to say what
    /// became of it (see [`StakeTracker::classify_landed`]): an `add-stake`
    /// that did not raise the bond — Kontor refused it, or the Portal retired
    /// it unexecuted — or a `leave-agreement`, which the registry says nothing
    /// about at all. Several at once is routine: the Portal reconciles a
    /// block some time after Kontor executes it, and the next op lands
    /// meanwhile.
    unexplained: Vec<LandedOp>,
    joins_paused: Option<(Instant, String)>,
    /// An unstake or withdrawal the operator asked for from `/admin`, waiting
    /// for the daemon's next cycle — the daemon is the only thing that signs,
    /// so the nonce counter never has two writers.
    operator_request: Option<NodeOp>,
    /// Last thing worth telling the operator about, with when.
    last_event: Option<(DateTime<Utc>, String)>,
    /// Collaterals seen on agreements lately, for the unknown-collateral
    /// estimate.
    recent_collateral: Vec<(Instant, Kor)>,
    /// Agreements a `leave-agreement` has executed for, this process.
    left: HashSet<String>,
    /// The rows the exit reads its memberships from have been brought up to
    /// date with the Portal since this process started — or since the last
    /// time the exit had to resend its leaves.
    memberships_refreshed: bool,
    /// The withdrawal delay, counted from when the node first saw the
    /// withdrawal height — in this process, or in an earlier one by the record
    /// it left in the database.
    withdrawal: Option<WithdrawalTimer>,
    /// What the database holds as the start of the delay, as far as this
    /// process knows: `None` for no row. Compared with `withdrawal` to decide
    /// what to write (see [`persist_withdrawal_start`]).
    persisted_withdrawal_start: Option<DateTime<Utc>>,
    /// The database has been read for an earlier process's record.
    withdrawal_restored: bool,
    last_withdraw: Option<Instant>,
    /// How long after `last_withdraw` the next automatic `withdraw-stake` may
    /// go: [`WITHDRAW_RETRY_INTERVAL`] unless Kontor said why it refused the
    /// last one (see [`StakeTracker::classify_landed`]).
    withdraw_retry: Option<Duration>,
    /// The bond came back: the operator left the network. Nothing more is
    /// bonded automatically, whatever auto-stake says — in this process and,
    /// by the record kept in the database, in the next ones — until the
    /// operator resumes staking from `/admin` (see [`StakeTracker::resume_staking`]).
    exited: bool,
    /// What the database holds as "the exit is over", as far as this process
    /// knows. Compared with `exited` to decide what to write (see
    /// [`persist_withdrawal_start`]).
    persisted_exited: bool,
    /// The database has been read for an earlier process's record of a
    /// finished exit. Until it has, nothing is bonded automatically: a
    /// top-up planned before the record is read would put back at stake the
    /// bond an exit has just returned.
    exit_record_read: bool,
    /// The exit as of the last plan, for `/admin`.
    exit: Option<ExitInputs>,
}

impl TrackerState {
    /// `op` consumed its nonce, or was failed by the Portal, without the
    /// effect it was sent for: remember it until the Portal's listing says
    /// how it ended (see [`StakeTracker::classify_landed`]), and take what
    /// each kind needs in the meantime.
    fn landed_without_effect(&mut self, flight: &InFlight, now: Instant) {
        let InFlight {
            op,
            nonce,
            unsettled,
            requested,
            ..
        } = flight;
        match op {
            // The same op signed again next cycle would most likely meet the
            // same answer, and each attempt costs gas: it waits as long as
            // one the Portal refused, unless the listing says it never ran.
            NodeOp::AddStake(_) => {
                self.refused.insert(refused_key(op), now);
            }
            // The bond is still there: too early, or an obligation the
            // node's own rows did not show. Forget which leaves "worked" so
            // they are sent again, and re-read the memberships.
            NodeOp::WithdrawStake => {
                self.left.clear();
                self.memberships_refreshed = false;
            }
            _ => {}
        }
        self.unexplained.retain(|landed| landed.nonce != *nonce);
        self.unexplained.push(LandedOp {
            op: op.clone(),
            nonce: *nonce,
            landed: now,
            unsettled: *unsettled,
            requested: *requested,
        });
    }

    /// The exit whose withdrawal delay an earlier process recorded as started
    /// at `started_at` ended while no process was watching: the first read
    /// shows no bond and no withdrawal pending. Withdrawn, or slashed to
    /// zero; either way the node is out, and stays out.
    fn end_exit_unseen(&mut self, started_at: DateTime<Utc>) {
        if self.exited {
            return;
        }
        warn!(
            "an exit was under way (its withdrawal delay started at {}) and no stake is bonded \
             any more: it ended while this node was not running. This node bonds nothing more \
             on its own; resume staking from /admin to bond again",
            started_at.to_rfc3339()
        );
        self.exited = true;
        self.last_event = Some((
            Utc::now(),
            "the exit ended while the node was not running".to_string(),
        ));
    }

    /// Put an operator's op that never ran back as a request, unless another
    /// one is waiting.
    fn request_again(&mut self, op: &NodeOp) {
        if self.operator_request.is_none() {
            self.operator_request = Some(op.clone());
        }
    }
}

/// An op kind, and the agreement it names, that the Portal refused.
type RefusedOp = (&'static str, Option<String>);

fn refused_key(op: &NodeOp) -> RefusedOp {
    (op.name(), op.agreement_id().map(str::to_string))
}

/// Whether `op` was refused less than [`REFUSED_OP_RETRY_INTERVAL`] ago.
fn refused_recently(state: &TrackerState, op: &NodeOp, now: Instant) -> bool {
    state
        .refused
        .get(&refused_key(op))
        .is_some_and(|at| now.duration_since(*at) < REFUSED_OP_RETRY_INTERVAL)
}

/// Where the node's exit stands, worked out by the daemon from its own rows.
///
/// A leave the node has seen execute in this process is remembered in the
/// tracker; one from an earlier process shows in the rows, as the `left`
/// status the Portal gives the membership once the leave is confirmed —
/// provided the rows are current, which [`refresh_memberships`] sees to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitInputs {
    /// Agreements this node holds a membership in, by its own rows.
    pub memberships: Vec<String>,
    /// Those of them with a challenge still `active`. Leaving one is allowed
    /// and not penalised by Kontor, but changes nothing: the reservation is
    /// only released once the challenge resolves, and the challenge must still
    /// be proved or it is slashed. So they are left after it resolves.
    pub deferred: Vec<String>,
    /// Challenges not resolved yet: `active`, proved and waiting, or `failed`
    /// less than [`FAILED_CHALLENGE_SETTLEMENT_GRACE`] ago, while Kontor may
    /// still have its penalty to settle. Kontor refuses `withdraw-stake` while
    /// any exists.
    pub unresolved_challenges: usize,
}

/// What the daemon knows about its bond across cycles, shared with `/admin`.
#[derive(Debug, Default)]
pub struct StakeTracker {
    state: Mutex<TrackerState>,
}

impl StakeTracker {
    #[cfg(test)]
    #[must_use]
    pub fn new(policy: StakePolicy) -> Self {
        Self {
            state: Mutex::new(TrackerState {
                policy,
                // No database behind a unit test's tracker: nothing to read.
                exit_record_read: true,
                ..TrackerState::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, TrackerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_policy(&self, policy: StakePolicy) {
        self.lock().policy = policy;
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<StakeSnapshot> {
        self.lock().snapshot.clone()
    }

    /// Remember a collateral the Portal reported on an agreement — this
    /// node's own, or one in the ready listing — for the unknown-collateral
    /// estimate.
    pub fn note_collateral(&self, raw: Option<&str>, now: Instant) {
        let Some(amount) = raw.and_then(|raw| Kor::parse(raw).ok()) else {
            return;
        };
        let mut state = self.lock();
        state
            .recent_collateral
            .retain(|(seen, _)| now.duration_since(*seen) < COLLATERAL_MEMORY);
        state.recent_collateral.push((now, amount));
        // Only the largest matters; keep the list from growing with the network.
        if state.recent_collateral.len() > 256 {
            state
                .recent_collateral
                .sort_by_key(|(_, amount)| std::cmp::Reverse(*amount));
            state.recent_collateral.truncate(64);
        }
    }

    /// Whether the exit has to re-read its memberships from the Portal before
    /// its next step (see [`refresh_memberships`]).
    #[must_use]
    pub fn memberships_need_refresh(&self) -> bool {
        !self.lock().memberships_refreshed
    }

    /// The memberships have been re-read; the rows are current.
    pub fn memberships_refreshed(&self) {
        self.lock().memberships_refreshed = true;
    }

    /// Whether the database has been read for the start of a withdrawal delay
    /// an earlier process recorded (see [`restore_withdrawal_start`]).
    #[must_use]
    pub fn withdrawal_start_restored(&self) -> bool {
        self.lock().withdrawal_restored
    }

    /// Count the withdrawal delay from `started_at`, the moment an earlier
    /// process first saw the withdrawal height; `None` when it recorded none.
    ///
    /// Overrides a start this process witnessed itself if the record is
    /// earlier — onboarding reads the registry before the daemon reads the
    /// database — and never a later one.
    pub fn restore_withdrawal_start(&self, started_at: Option<DateTime<Utc>>, now: Instant) {
        let mut state = self.lock();
        state.withdrawal_restored = true;
        state.persisted_withdrawal_start = started_at;
        let Some(started_at) = started_at else {
            return;
        };
        if state
            .withdrawal
            .is_some_and(|timer| timer.started_at <= started_at)
        {
            return;
        }
        // A read this process already made (onboarding reads the registry
        // before the daemon reads the database) that shows no withdrawal
        // pending outranks the record: the exit it belonged to is over, and
        // the row is stale. Left as it is, it is cleared on the next persist.
        if let Some(snapshot) = state
            .last_known
            .as_ref()
            .filter(|snapshot| snapshot.withdrawal_height.is_none())
        {
            if snapshot.stake.is_zero() {
                // An exit was under way when the last process stopped, and
                // now there is neither a bond nor a withdrawal pending: it
                // ended while nobody was watching. The exit is over.
                state.end_exit_unseen(started_at);
            } else {
                warn!(
                    "the database records a withdrawal delay started at {}, but no withdrawal \
                     is pending and a stake is bonded; the record is stale and is cleared",
                    started_at.to_rfc3339()
                );
            }
            return;
        }
        let head_start = (Utc::now() - started_at).to_std().unwrap_or_default();
        info!(
            "the withdrawal delay has been running since {}; {} hours of it are already behind",
            started_at.to_rfc3339(),
            head_start.as_secs() / 3600
        );
        state.withdrawal = Some(WithdrawalTimer {
            started_at,
            seen: now,
            head_start,
        });
    }

    /// The start of the withdrawal delay the database should hold, if it does
    /// not hold it already: `Some(None)` to clear a record whose delay is over.
    ///
    /// Nothing, until the record has been read (see
    /// [`Self::restore_withdrawal_start`]): before that there is nothing to
    /// compare with, and a start this process witnessed itself would be
    /// written over the earlier one a previous process recorded — restarting
    /// the two weeks the record exists to keep.
    #[must_use]
    pub fn withdrawal_start_to_persist(&self) -> Option<Option<DateTime<Utc>>> {
        let state = self.lock();
        if !state.withdrawal_restored {
            return None;
        }
        let wanted = state.withdrawal.map(|timer| timer.started_at);
        (wanted != state.persisted_withdrawal_start).then_some(wanted)
    }

    /// The database now holds `started_at` as the start of the delay.
    pub fn withdrawal_start_persisted(&self, started_at: Option<DateTime<Utc>>) {
        self.lock().persisted_withdrawal_start = started_at;
    }

    /// What an earlier process recorded in the database: whether the node had
    /// finished an exit (see [`restore_withdrawal_start`]). From here on the
    /// policy may bond again — or, if it had exited, may not.
    pub fn restore_exited(&self, recorded: bool) {
        let mut state = self.lock();
        state.exit_record_read = true;
        state.persisted_exited = recorded;
        if !recorded || state.exited {
            return;
        }
        // A read this process already made that shows a stake bonded with no
        // withdrawal pending outranks the record: the node stakes again, and
        // the row is cleared on the next persist.
        if state.last_known.as_ref().is_some_and(|snapshot| {
            !snapshot.stake.is_zero() && snapshot.withdrawal_height.is_none()
        }) {
            return;
        }
        info!(
            "this node has exited: it bonds nothing on its own until staking is resumed from \
             /admin"
        );
        state.exited = true;
    }

    /// Whether the database should be told the exit is over, or no longer
    /// is: `Some` when it does not hold what the tracker says. Nothing until
    /// the record has been read.
    #[must_use]
    pub fn exited_to_persist(&self) -> Option<bool> {
        let state = self.lock();
        (state.exit_record_read && state.exited != state.persisted_exited).then_some(state.exited)
    }

    /// The database now holds `exited`.
    pub fn exited_persisted(&self, exited: bool) {
        self.lock().persisted_exited = exited;
    }

    /// The operator, from `/admin`, puts a node that has exited back in the
    /// network: the policy bonds again as configured, from the next cycle.
    ///
    /// # Errors
    /// If the node has not exited: there is nothing to resume.
    pub fn resume_staking(&self) -> Result<(), &'static str> {
        let mut state = self.lock();
        if !state.exited {
            return Err("this node has not exited: its stake policy is already in force");
        }
        state.exited = false;
        state.last_event = Some((Utc::now(), "staking resumed from /admin".to_string()));
        info!("staking resumed from /admin: the stake policy is in force again");
        Ok(())
    }

    /// Whether the node is in its exit: the operator's unstake has executed.
    #[must_use]
    pub fn exiting(&self) -> bool {
        self.lock()
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.withdrawal_height.is_some())
    }

    /// Fold in this cycle's registry read: `None` when it failed outright.
    ///
    /// Retires in-flight work whose nonce Kontor has consumed, and says out
    /// loud when the stake shrank or bond cleanup started — the two things an operator must not
    /// learn from a dashboard a week later.
    pub fn observe(&self, entry: Option<&RegistryEntry>, now: Instant) {
        let snapshot = entry.and_then(StakeSnapshot::from_entry);
        let mut state = self.lock();

        // A `stake` field, readable or not, is a Portal that knows about
        // staking: an entry whose stake cannot be read must close this
        // cycle's joins, not pass for an old Portal. That includes a `null`
        // — the Portal could not read the bond from Kontor this time — which
        // deserializes as present (`STAKE_UNREAD`); only a Portal predating
        // staking omits the key.
        let reports_stake = entry.is_some_and(|entry| entry.stake.is_some());
        if reports_stake {
            state.portal_reports_stake = true;
        }
        let Some(snapshot) = snapshot else {
            if reports_stake {
                warn!(
                    "the Portal could not report this node's stake this time; joins are paused \
                     and no stake op is signed this cycle"
                );
            } else if entry.is_some() && state.portal_reports_stake {
                warn!("the Portal's signer entry no longer reports a stake; joins are paused");
            }
            state.snapshot = None;
            return;
        };

        if snapshot.available.is_none() {
            warn!(
                "the Portal's signer entry reports a stake but not how much of it is unreserved; \
                 joins are paused this cycle, everything else goes on"
            );
        }

        let exited_before = state.exited;
        let mut landed: Vec<InFlight> = Vec::new();
        for op in std::mem::take(&mut state.in_flight) {
            if snapshot.next_nonce > op.nonce {
                info!(
                    op = op.op.name(),
                    nonce = op.nonce,
                    "the {} op has executed on Kontor",
                    op.op.name()
                );
                landed.push(op);
            } else {
                state.in_flight.push(op);
            }
        }

        for flight in &landed {
            let InFlight {
                op,
                nonce,
                stake_before,
                ..
            } = flight;
            match op {
                NodeOp::LeaveAgreement(agreement_id) => {
                    // Its nonce went; whether Kontor accepted the leave is not in
                    // the registry. The Portal's listing says, and until it does
                    // the agreement is neither left nor left again (see
                    // `classify_landed` and `next_exit_op`).
                    info!(
                        "the leave of agreement {agreement_id} has executed; asking the Portal \
                         whether Kontor accepted it"
                    );
                    state.landed_without_effect(flight, now);
                }
                NodeOp::AddStake(amount) => match stake_before {
                    // The bond is above what it was when the op was planned:
                    // it ran. Measured from the plan, not from the previous
                    // read — the Portal reads the nonce and the bond in two
                    // requests, so a read can already show the raised bond
                    // under the old nonce, and the next one, which shows the
                    // nonce consumed, then finds the bond "unchanged".
                    Some(before) if snapshot.stake > *before => {}
                    // An op adopted from the Portal's listing: what the bond
                    // was before it is not known, so the bond cannot say
                    // whether it ran. The listing will; until it does the
                    // next top-up waits like one behind a refusal, since that
                    // is what it may turn out to be.
                    None => {
                        info!(
                            "the add-stake of {amount} KOR adopted at nonce {nonce} has \
                             executed; asking the Portal how it ended before signing another"
                        );
                        state.landed_without_effect(flight, now);
                    }
                    Some(_) => {
                        // Its nonce went, its KOR did not. Either Kontor executed and
                        // refused it for a reason the snapshot and the Portal's
                        // pre-check did not see — the same op signed again next cycle
                        // meets the same answer, and each attempt costs gas, so it
                        // waits as long as one the Portal refused — or the Portal
                        // retired it before Kontor saw it, which its listing says, and
                        // `classify_landed` lifts the wait for. Or it did run and a
                        // slash took more than it added: the listing says
                        // `confirmed`, and the wait is lifted as well.
                        warn!(
                        "add-stake of {amount} KOR executed without raising the bond; not signing \
                     it again for {} hour unless the Portal says it never ran",
                        REFUSED_OP_RETRY_INTERVAL.as_secs() / 3600
                    );
                        state.landed_without_effect(flight, now);
                        state.last_event = Some((
                            Utc::now(),
                            format!("add_stake {amount} KOR executed without raising the bond"),
                        ));
                    }
                },
                NodeOp::WithdrawStake if !snapshot.stake.is_zero() => {
                    // Executed, and the bond is still there: too early, or an
                    // obligation the node's own rows did not show (a leave that
                    // failed on chain, a challenge Kontor has still to settle).
                    // Forget which leaves "worked" so they are sent again, re-read
                    // the memberships, and retry later — sooner if the Portal's
                    // listing says Kontor named an obligation (see
                    // `classify_landed`).
                    warn!(
                    "withdraw-stake executed without returning the bond; leaves will be resent \
                     and the withdrawal retried in {} hours unless Kontor named an obligation",
                    WITHDRAW_RETRY_INTERVAL.as_secs() / 3600
                );
                    state.landed_without_effect(flight, now);
                }
                NodeOp::WithdrawStake => state.exited = true,
                NodeOp::BeginUnstake if snapshot.withdrawal_height.is_none() => {
                    // Its nonce went and no withdrawal is pending: Kontor
                    // refused it, or the Portal retired it before Kontor saw
                    // it. The operator asked for this by hand and nothing
                    // plans it again, so it must not just disappear: the
                    // Portal's listing says which it was (`classify_landed`),
                    // and until it does no join is made.
                    warn!(
                        "begin-unstake at nonce {nonce} executed without starting the \
                         withdrawal; asking the Portal how it ended"
                    );
                    state.landed_without_effect(flight, now);
                    state.last_event = Some((
                        Utc::now(),
                        "begin_unstake executed without starting the withdrawal".to_string(),
                    ));
                }
                _ => {}
            }
        }
        // The snapshot says so too, whether or not the withdrawal is still
        // tracked in flight — one given up as lost has been forgotten by then
        // (see `verify_in_flight`), and auto-stake would re-bond
        // the whole bond it just returned. An exit under way at the last read,
        // and now no bond and no withdrawal pending: the bond came back — or
        // was slashed to the last KOR, which Kontor clears the withdrawal
        // height for as well. The exit is over either way, and nothing is
        // bonded again; `describe_transition` says which it was.
        //
        //
        // On this process's first read, the start of a withdrawal delay
        // restored from the database says the same of the process before it:
        // an exit was under way when it stopped. No bond and no withdrawal
        // now, and that exit ended while nobody was watching — the withdrawal
        // landed just after the process died, typically. It used to be taken
        // for a stale row, and the restarted node bonded the returned
        // balance again.
        let was_exiting = state
            .last_known
            .as_ref()
            .is_some_and(|previous| previous.withdrawal_height.is_some());
        let exit_ended = snapshot.stake.is_zero() && snapshot.withdrawal_height.is_none();
        if was_exiting && exit_ended {
            state.exited = true;
        }
        if let (None, Some(timer), true) = (&state.last_known, state.withdrawal, exit_ended) {
            state.end_exit_unseen(timer.started_at);
        }
        // A bond with no withdrawal pending is a node that stakes: whatever
        // said it had exited — a record older than the stake — no longer
        // holds.
        if state.exited && !snapshot.stake.is_zero() && snapshot.withdrawal_height.is_none() {
            info!("a stake is bonded and no withdrawal is pending: the recorded exit is over");
            state.exited = false;
        }
        if state.exited && !exited_before && snapshot.bond_cleanup_pending == Some(false) {
            warn!(
                "the bond has been withdrawn: this node bonds nothing more on its own, and a \
                 restart does not change that. Resume staking from /admin to bond again"
            );
        }
        if snapshot.withdrawal_height.is_some() {
            state
                .withdrawal
                .get_or_insert_with(|| WithdrawalTimer::starting_now(now));
        } else {
            state.withdrawal = None;
        }

        // A join's collateral is held until its nonce says it has executed —
        // or until the Portal's rows say it never will (`settle_pending_joins`
        // from the ready listing, `join_verified` from the agreement's
        // detail). Not on a clock: the Portal can hold a join for a day.
        state
            .pending_joins
            .retain(|join| snapshot.next_nonce <= join.nonce);

        if let Some(previous) = &state.last_known {
            let event = describe_transition(previous, &snapshot);
            if let Some(event) = event {
                state.last_event = Some((Utc::now(), event));
            }
        } else if snapshot.bond_cleanup_pending == Some(true) {
            error!(
                "bond cleanup is pending: this node's stake was slashed to zero. It cannot join \
                 or add stake until Kontor finishes unwinding its memberships"
            );
            state.last_event = Some((Utc::now(), "bond cleanup pending".to_string()));
        }

        // A request the bond has overtaken is dropped rather than signed: a
        // withdrawal with none pending any more (it completed, or a slash to
        // zero cleared it), an unstake once a withdrawal is pending or there
        // is nothing bonded. `/admin` checks the same when it takes the
        // request; a request put back after its op was lost (see
        // `request_again`) is checked here.
        let moot = match &state.operator_request {
            Some(NodeOp::WithdrawStake) => snapshot.withdrawal_height.is_none(),
            Some(NodeOp::BeginUnstake) => {
                snapshot.withdrawal_height.is_some() || snapshot.stake.is_zero()
            }
            _ => false,
        };
        if moot {
            if let Some(op) = state.operator_request.take() {
                info!(
                    "dropping the {} requested from /admin: the bond no longer calls for it",
                    op.name()
                );
            }
        }

        state.last_known = Some(snapshot.clone());
        state.snapshot = Some(snapshot);
        state.observed_at = Some(Utc::now());
    }

    /// Whether the Portal's listing of this node's pending ops has been read
    /// in this process (see [`Self::adopt_pending_ops`]).
    #[must_use]
    pub fn pending_ops_checked(&self) -> bool {
        self.lock().pending_ops_checked
    }

    /// The Portal's listing has to be read again before anything is planned:
    /// the relay answered `409`, so the Portal holds an op of this node the
    /// tracker does not know (see [`Self::adopt_pending_ops`]).
    pub fn recheck_pending_ops(&self) {
        self.lock().pending_ops_checked = false;
    }

    /// The highest nonce among the ops and joins this tracker still waits
    /// for. A client built for a new activation starts its counter at Kontor's
    /// `next_nonce`, which is at or below every one of them.
    #[must_use]
    pub fn highest_tracked_nonce(&self) -> Option<u64> {
        let state = self.lock();
        state
            .in_flight
            .iter()
            .map(|op| op.nonce)
            .chain(state.pending_joins.iter().map(|join| join.nonce))
            .max()
    }

    /// Take the ops the Portal still holds for this node — `queued` or
    /// `submitted`, from `GET /api/nodes/{node_id}/ops?status=queued|submitted`
    /// — as ops in flight, each one the tracker does not know already.
    ///
    /// In-flight tracking lives in memory. After a restart the node knows
    /// nothing of the `add-stake` it signed before, which may well still be
    /// queued at the Portal behind an unconfirmed batch; planned again from
    /// the registry it would sign a second top-up — refused `409` while the
    /// amount matches the first byte for byte, accepted at the next nonce as
    /// soon as a proof's gas has changed the balance, and then both execute.
    /// The listing is the Portal's own word on what it holds, the same word
    /// [`Self::verify_in_flight`] trusts, so the op is adopted from it: tracked
    /// as sent now and vouched for now, and waited for like one this process
    /// sent. The same is done after a `409`: the nonce went to an op the
    /// Portal already holds, which may be exactly this one.
    ///
    /// Returns the newest op adopted, if any. Marks the listing read either
    /// way.
    pub fn adopt_pending_ops(&self, ops: &[NodeOpRecord], now: Instant) -> Option<(NodeOp, u64)> {
        let mut state = self.lock();
        let state = &mut *state;
        state.pending_ops_checked = true;
        // An op whose nonce Kontor has already consumed by the latest registry
        // read has executed, or never will: the Portal's listing is simply
        // behind (it reconciles a block after Kontor runs it). Adopted, it
        // would be seen "landing" on the next read without the bond moving.
        let next_nonce = state
            .last_known
            .as_ref()
            .map_or(0, |snapshot| snapshot.next_nonce);
        let mut held: Vec<(NodeOp, &NodeOpRecord)> = ops
            .iter()
            .filter(|record| matches!(record.status.as_str(), "queued" | "submitted"))
            .filter(|record| record.nonce >= next_nonce)
            .filter(|record| !state.in_flight.iter().any(|op| op.nonce == record.nonce))
            .filter_map(|record| NodeOp::from_record(record).map(|op| (op, record)))
            .collect();
        held.sort_by_key(|(_, record)| record.nonce);
        let mut newest = None;
        for (op, record) in held {
            let nonce = record.nonce;
            info!(
                op = op.name(),
                nonce,
                status = %record.status,
                "the Portal still holds a {} op of this node; waiting for it rather than \
                 signing another",
                op.name()
            );
            match op {
                NodeOp::ClaimRewards => state.last_claim = Some(now),
                NodeOp::WithdrawStake => state.last_withdraw = Some(now),
                _ => {}
            }
            // An unstake is only ever the operator's; an adopted withdrawal
            // is one only if the request for it is still waiting here.
            let requested =
                op == NodeOp::BeginUnstake || state.operator_request.as_ref() == Some(&op);
            if state.operator_request.as_ref() == Some(&op) {
                state.operator_request = None;
            }
            state.last_event = Some((
                Utc::now(),
                format!(
                    "{} {} at the Portal (nonce {nonce}); adopted as in flight",
                    op.name(),
                    record.status
                ),
            ));
            state.in_flight.push(InFlight {
                op: op.clone(),
                nonce,
                sent: now,
                sent_at: Utc::now(),
                unsettled: false,
                requested,
                stake_before: None,
                checked: Some(now),
                vouched: Some(now),
                orphaned: None,
            });
            newest = Some((op, nonce));
        }
        state.in_flight.sort_by_key(|op| op.nonce);
        newest
    }

    /// The nonces of the in-flight ops the Portal should be asked about this
    /// cycle: those that have waited [`OP_LANDING_CHECK_INTERVAL`] since they
    /// were sent or since the listing was last read for them. A listing that
    /// could not be read is not a reading: the op is asked about again on the
    /// next cycle, not half an hour later.
    #[must_use]
    pub fn ops_to_verify(&self, now: Instant) -> Vec<u64> {
        let state = self.lock();
        state
            .in_flight
            .iter()
            .filter(|op| {
                now.duration_since(op.checked.unwrap_or(op.sent)) >= OP_LANDING_CHECK_INTERVAL
            })
            .map(|op| op.nonce)
            .collect()
    }

    /// The first of [`Self::ops_to_verify`].
    #[cfg(test)]
    #[must_use]
    pub fn op_to_verify(&self, now: Instant) -> Option<u64> {
        self.ops_to_verify(now).first().copied()
    }

    /// What the Portal's listing of this node's ops says about the in-flight
    /// op at `nonce` (see [`Self::ops_to_verify`]).
    ///
    /// Still `queued` or `submitted`: it is waiting for a batch, or in one that
    /// is not confirmed yet, and stays in flight. `confirmed`: it has executed
    /// and the registry read is behind; it stays in flight for the nonce to
    /// say so. Missing from the listing: the Portal will never relay it, so
    /// it is given up and the next plan decides again. `failed`: it will not
    /// be relayed either, and why decides what comes next, so it is handed to
    /// [`Self::classify_landed`] like an op whose nonce went — a refusal by
    /// Kontor waits its hour, a retirement by the Portal is signed again at
    /// once. `failed` because the Portal lost the transaction that carried it
    /// ([`PORTAL_ORPHANED_HEAD`]) is the one case where the op may still
    /// execute: it stays in flight until its nonce is consumed, for
    /// [`OP_LANDING_HARD_TIMEOUT`] at most. A listing
    /// that could not be read says nothing: the op stays in flight and the
    /// next cycle asks again, however long the Portal stays silent — it may
    /// hold the op all that time.
    #[cfg(test)]
    pub fn verify_in_flight(
        &self,
        nonce: u64,
        listing: anyhow::Result<Vec<NodeOpRecord>>,
        now: Instant,
    ) {
        self.verify_in_flight_from(nonce, listing.as_ref().map(Vec::as_slice), now);
    }

    /// [`Self::verify_in_flight`] from a listing that is not consumed, so one
    /// read of it answers for every op in flight.
    fn verify_in_flight_from(
        &self,
        nonce: u64,
        listing: Result<&[NodeOpRecord], &anyhow::Error>,
        now: Instant,
    ) {
        let mut state = self.lock();
        let state = &mut *state;
        let Some(op) = state.in_flight.iter_mut().find(|op| op.nonce == nonce) else {
            return;
        };
        let name = op.op.name();
        let listed = match listing {
            Ok(ops) => ops.iter().find(|listed| listed.nonce == nonce),
            Err(err) => {
                let silent = op.unvouched_for(now);
                if silent >= OP_LANDING_HARD_TIMEOUT {
                    error!(
                        "the Portal has not been able to say whether it holds the {name} op at \
                         nonce {nonce} for {} hours; no other stake op is signed until its \
                         listing can be read or the nonce is consumed: {err:#}",
                        silent.as_secs() / 3600
                    );
                } else {
                    warn!(
                        "could not ask the Portal about the {name} op at nonce {nonce}; keeping \
                         it in flight and asking again next cycle: {err:#}"
                    );
                }
                return;
            }
        };
        op.checked = Some(now);
        if let Some(other) = listed.as_ref().filter(|listed| listed.op != name) {
            // Another op of this node holds the nonce — the relay's `409`
            // after the fact. Ours was never stored.
            warn!(
                "the Portal holds a {} op, not the {name} op, at nonce {nonce}; the {name} op \
                 was not relayed and is decided again",
                other.op
            );
            let flight = op.clone();
            state.in_flight.retain(|op| op.nonce != nonce);
            if flight.requested {
                state.request_again(&flight.op);
            }
            state.last_event = Some((
                Utc::now(),
                format!("{name} lost nonce {nonce} to a {} op", other.op),
            ));
            return;
        }
        let dropped = match listed.as_ref().map(|listed| listed.status.as_str()) {
            Some(status @ ("queued" | "submitted")) => {
                // Held by the Portal: waited for, however long — a `submitted`
                // op whose batch the Portal gave up on comes back as `queued`
                // and is batched again, still under this nonce.
                op.vouched = Some(now);
                let waited = now.duration_since(op.sent);
                if waited >= OP_LANDING_HARD_TIMEOUT {
                    warn!(
                        "the {name} op at nonce {nonce} has been {status} at the Portal for {} \
                         hours; it is not lost, and is not signed again while the Portal holds it",
                        waited.as_secs() / 3600
                    );
                } else {
                    info!(
                        "the {name} op at nonce {nonce} is still {status} at the Portal after {} \
                         minutes; waiting",
                        waited.as_secs() / 60
                    );
                }
                return;
            }
            Some("confirmed") => {
                op.vouched = Some(now);
                debug!(
                    "the {name} op at nonce {nonce} is confirmed at the Portal; waiting for the \
                     registry to reflect it"
                );
                return;
            }
            Some("failed") => {
                let error = listed
                    .as_ref()
                    .and_then(|listed| listed.error.as_deref())
                    .unwrap_or("no error given");
                if orphaned_by_portal(error) {
                    // The Portal no longer has the transaction the op was
                    // batched in, so it cannot say whether the op ran — and
                    // if that transaction is still out there, it may yet.
                    // Signing the op again now could make both execute. The
                    // nonce decides: consumed, the op is over one way or the
                    // other; still free after the timeout, it is given up.
                    let since = *op.orphaned.get_or_insert(now);
                    if now.duration_since(since) < OP_LANDING_HARD_TIMEOUT {
                        warn!(
                            "the Portal lost track of the {name} op at nonce {nonce} ({error}); \
                             keeping it in flight until its nonce is consumed, for {} hours at \
                             most",
                            OP_LANDING_HARD_TIMEOUT.as_secs() / 3600
                        );
                        return;
                    }
                    warn!(
                        "the {name} op at nonce {nonce}, which the Portal lost track of, has not \
                         executed in {} hours; deciding again",
                        OP_LANDING_HARD_TIMEOUT.as_secs() / 3600
                    );
                    format!("{name} lost by the Portal (nonce {nonce})")
                } else {
                    warn!("the Portal reports the {name} op at nonce {nonce} as failed: {error}");
                    let flight = op.clone();
                    state.in_flight.retain(|op| op.nonce != nonce);
                    state.landed_without_effect(&flight, now);
                    state.last_event = Some((
                        Utc::now(),
                        format!("{name} failed at the Portal (nonce {nonce})"),
                    ));
                    return;
                }
            }
            Some(other) => {
                warn!(
                    "the Portal lists the {name} op at nonce {nonce} with an unknown status \
                     {other:?}; deciding again"
                );
                format!("{name} in an unknown state at the Portal (nonce {nonce})")
            }
            None => {
                warn!(
                    "the Portal no longer lists the {name} op at nonce {nonce}; assuming it \
                     dropped it and deciding again"
                );
                format!("{name} dropped by the Portal (nonce {nonce})")
            }
        };
        // The Portal will not relay it. An op the policy plans is planned
        // again from the state as it stands; one the operator asked for is
        // put back as their request.
        let flight = op.clone();
        state.in_flight.retain(|op| op.nonce != nonce);
        if flight.requested {
            state.request_again(&flight.op);
        }
        state.last_event = Some((Utc::now(), dropped));
    }

    /// The nonces of the landed ops the Portal's listing should be asked
    /// about: an `add-stake` that executed without raising the bond, a leave
    /// (see [`Self::classify_landed`]). Lowest first.
    #[must_use]
    pub fn ops_to_classify(&self) -> Vec<u64> {
        let mut nonces: Vec<u64> = self
            .lock()
            .unexplained
            .iter()
            .map(|landed| landed.nonce)
            .collect();
        nonces.sort_unstable();
        nonces
    }

    /// The first of [`Self::ops_to_classify`].
    #[cfg(test)]
    #[must_use]
    pub fn op_to_classify(&self) -> Option<u64> {
        self.ops_to_classify().first().copied()
    }

    /// What the Portal's listing of this node's ops says about the op at
    /// `nonce` whose nonce Kontor consumed (see [`Self::ops_to_classify`]).
    ///
    /// For an `add-stake` whose nonce went while the bond did not move, it
    /// went one of two ways. Kontor executed and refused it: the Portal lists
    /// it `failed` with Kontor's error, and the hour's backoff `observe` put
    /// on it stands — the same op meets the same answer. Or the Portal retired
    /// it without Kontor seeing it: a proof batched ahead of it took the nonce,
    /// and the Portal lists it `failed` with "no receipt"; or its nonce was
    /// stale by compose time, and the listing says so. Nothing was refused
    /// then, and the backoff is lifted so the op is signed again. The same
    /// goes for an op the relay gave no answer for ([`Self::record_unsettled`])
    /// that the Portal turns out not to hold: it was never stored, and its
    /// nonce went to another op.
    ///
    /// For a `leave-agreement` the registry says nothing at all, so the
    /// listing is the only word: `confirmed` and the agreement is left;
    /// `failed` by Kontor because there is no membership to leave (see
    /// [`no_membership_to_leave`]) and it is left all the same; `failed` by
    /// Kontor for another reason and it is tried again after the hour a
    /// refusal earns; retired by the Portal, or no longer listed, and it is
    /// tried again at once. Until then the exit neither counts the agreement as
    /// left nor leaves it again.
    ///
    /// A listing that still shows the op `queued` or `submitted` — the Portal
    /// has not reconciled the block yet — or that cannot be read, settles
    /// nothing: the op is asked about again next cycle, up to
    /// [`OP_LANDING_HARD_TIMEOUT`] after it landed, then forgotten: the next
    /// plan decides again from the rows and the bond as they stand.
    #[cfg(test)]
    pub fn classify_landed(
        &self,
        nonce: u64,
        listing: anyhow::Result<Vec<NodeOpRecord>>,
        now: Instant,
    ) {
        self.classify_landed_from(nonce, listing.as_ref().map(Vec::as_slice), now);
    }

    /// [`Self::classify_landed`] from a listing that is not consumed, so one
    /// read of it answers for every landed op.
    fn classify_landed_from(
        &self,
        nonce: u64,
        listing: Result<&[NodeOpRecord], &anyhow::Error>,
        now: Instant,
    ) {
        let mut state = self.lock();
        let Some(index) = state
            .unexplained
            .iter()
            .position(|landed| landed.nonce == nonce)
        else {
            return;
        };
        let landed = state.unexplained.remove(index);
        let op = landed.op.clone();
        let name = op.name();
        let keep_asking = |state: &mut TrackerState, landed: LandedOp| {
            if now.duration_since(landed.landed) < OP_LANDING_HARD_TIMEOUT {
                state.unexplained.push(landed);
            } else {
                warn!(
                    "the Portal has not said how the {name} op at nonce {nonce} ended in {} \
                     hours; deciding again from the rows as they stand",
                    OP_LANDING_HARD_TIMEOUT.as_secs() / 3600
                );
            }
        };
        let listed = match listing {
            Ok(ops) => ops
                .iter()
                .find(|listed| listed.nonce == nonce && listed.op == name),
            Err(err) => {
                warn!(
                    "could not ask the Portal how the {name} op at nonce {nonce} ended; asking \
                     again next cycle: {err:#}"
                );
                keep_asking(&mut state, landed);
                return;
            }
        };
        let status = listed.as_ref().map(|listed| listed.status.as_str());
        let error = listed
            .as_ref()
            .and_then(|listed| listed.error.as_deref())
            .unwrap_or("no error given");
        if matches!(status, Some("queued" | "submitted")) {
            debug!(
                "the Portal still lists the {name} op at nonce {nonce} as {}; asking again next \
                 cycle",
                status.unwrap_or_default()
            );
            keep_asking(&mut state, landed);
            return;
        }
        let retired = status == Some("failed") && retired_by_portal(error);
        // The Portal lost the transaction that carried the op, and cannot say
        // whether Kontor ran it. Not a refusal: the nonce is consumed, so the
        // op is over, and it is decided again from the state as it stands —
        // an `add-stake` that did run shows in the bond, a leave that did run
        // is answered "not in agreement" the second time, which counts as
        // left.
        let orphaned = status == Some("failed") && orphaned_by_portal(error);
        match &op {
            NodeOp::LeaveAgreement(agreement_id) => match status {
                Some("confirmed") => {
                    info!("left agreement {agreement_id}");
                    state.left.insert(agreement_id.clone());
                    state.last_event = Some((Utc::now(), format!("left agreement {agreement_id}")));
                }
                Some("failed")
                    if !retired && !orphaned && no_membership_to_leave(error, agreement_id) =>
                {
                    // Kontor holds no membership of this node in the
                    // agreement: bond cleanup unwound it after a slash to
                    // zero, or the Portal's row was behind. Nothing is left
                    // to leave, which is what the exit wanted; asking again
                    // every hour would never get another answer, and the
                    // withdrawal would wait behind it for ever.
                    info!(
                        "Kontor holds no membership of this node in agreement {agreement_id} \
                         ({error}); counting it as left"
                    );
                    state.left.insert(agreement_id.clone());
                    state.last_event = Some((
                        Utc::now(),
                        format!("agreement {agreement_id} was already left on Kontor"),
                    ));
                }
                Some("failed") if !retired && !orphaned => {
                    warn!(
                        "Kontor refused the leave of agreement {agreement_id} ({error}); trying \
                         again in {} hour",
                        REFUSED_OP_RETRY_INTERVAL.as_secs() / 3600
                    );
                    state.refused.insert(refused_key(&op), now);
                    state.last_event = Some((
                        Utc::now(),
                        format!("leave_agreement {agreement_id} failed on Kontor: {error}"),
                    ));
                }
                _ => {
                    // Retired unexecuted, lost track of, or not held by the
                    // Portal at all: for all the node knows the membership
                    // stands, and the leave is signed again.
                    state.refused.remove(&refused_key(&op));
                    warn!(
                        "the leave of agreement {agreement_id} at nonce {nonce} is not known to \
                         have run ({}); signing it again",
                        if listed.is_some() {
                            error
                        } else {
                            "the Portal does not list it"
                        }
                    );
                    state.last_event = Some((
                        Utc::now(),
                        format!(
                            "leave_agreement {agreement_id} not known to have run (nonce \
                             {nonce}); signing again"
                        ),
                    ));
                }
            },
            _ if orphaned => {
                warn!(
                    "the Portal cannot say whether the {name} op at nonce {nonce} ran ({error}); \
                     deciding again from the bond as it stands"
                );
                state.refused.remove(&refused_key(&op));
                if op == NodeOp::WithdrawStake {
                    state.last_withdraw = None;
                }
                if landed.requested {
                    state.request_again(&op);
                }
                state.last_event = Some((
                    Utc::now(),
                    format!("{name} lost by the Portal (nonce {nonce}); deciding again"),
                ));
            }
            _ if retired => {
                info!(
                    "the Portal retired the {name} op at nonce {nonce} before Kontor ran it \
                     ({error}); signing it again"
                );
                state.refused.remove(&refused_key(&op));
                if op == NodeOp::WithdrawStake {
                    state.last_withdraw = None;
                }
                if landed.requested {
                    state.request_again(&op);
                }
                state.last_event = Some((
                    Utc::now(),
                    format!(
                        "{name} retired by the Portal unexecuted (nonce {nonce}); signing again"
                    ),
                ));
            }
            _ if listed.is_none() && landed.unsettled => {
                // The relay never answered for this op, and the Portal does
                // not hold it: it was never stored, so Kontor never saw it.
                // Its nonce went to another op, and nothing was refused.
                info!(
                    "the Portal never stored the {name} op at nonce {nonce} (no answer came back \
                     for it); another op took the nonce, and it is signed again"
                );
                state.refused.remove(&refused_key(&op));
                if op == NodeOp::WithdrawStake {
                    state.last_withdraw = None;
                }
                if landed.requested {
                    state.request_again(&op);
                }
                state.last_event = Some((
                    Utc::now(),
                    format!("{name} never reached the Portal (nonce {nonce}); signing again"),
                ));
            }
            NodeOp::WithdrawStake
                if status == Some("failed") && error.contains(KONTOR_UNRESOLVED_OBLIGATIONS) =>
            {
                // Kontor still counts a membership or a challenge against the
                // node: a leave that did not take, or a failed challenge whose
                // penalty it has yet to settle. The memberships are re-read
                // (`observe` saw to that) and the challenges synced every
                // cycle, so the retry is short.
                warn!(
                    "Kontor refused the withdrawal at nonce {nonce}: {error}; the memberships \
                     and challenges are re-read, and it is retried in {} hour",
                    WITHDRAW_OBLIGATION_RETRY_INTERVAL.as_secs() / 3600
                );
                state.withdraw_retry = Some(WITHDRAW_OBLIGATION_RETRY_INTERVAL);
                state.last_event = Some((
                    Utc::now(),
                    format!("withdraw_stake refused by Kontor: {error}; retrying within the hour"),
                ));
            }
            NodeOp::BeginUnstake if status == Some("failed") => {
                // Kontor ran the operator's unstake and refused it. Signing
                // it again would meet the same answer; the operator is told
                // why, and asks again once it no longer holds.
                error!(
                    "Kontor refused the unstake requested from /admin (nonce {nonce}): {error}. \
                     No withdrawal is pending; request it again once that no longer holds"
                );
                state.last_event = Some((
                    Utc::now(),
                    format!("begin_unstake refused by Kontor: {error}"),
                ));
            }
            NodeOp::AddStake(amount) if status == Some("confirmed") => {
                // It ran. The bond did not show it — a slash took more than
                // the op added, or the op was adopted and its starting point
                // unknown — and nothing was refused.
                info!(
                    "the Portal confirms the add-stake of {amount} KOR at nonce {nonce} ran; \
                     nothing to retry"
                );
                state.refused.remove(&refused_key(&op));
            }
            NodeOp::AddStake(amount) if status == Some("failed") => {
                // Kontor ran it and refused it. `observe` has already put the
                // hour's wait on one it saw land; one the Portal's listing
                // reported first gets it here.
                warn!(
                    "Kontor refused the add-stake of {amount} KOR at nonce {nonce} ({error}); \
                     not signing it again for {} hour",
                    REFUSED_OP_RETRY_INTERVAL.as_secs() / 3600
                );
                state
                    .refused
                    .entry(refused_key(&op))
                    .or_insert(landed.landed);
                state.last_event = Some((
                    Utc::now(),
                    format!("add_stake {amount} KOR refused by Kontor: {error}"),
                ));
            }
            _ => match status {
                Some(status) => debug!(
                    "the Portal lists the {name} op at nonce {nonce} as {status} ({error}); the \
                     backoff stands"
                ),
                None => debug!(
                    "the Portal does not list the {name} op at nonce {nonce}: Kontor ran it, and \
                     the backoff stands"
                ),
            },
        }
    }

    /// The agreements whose joins still hold collateral in the budget.
    #[must_use]
    pub fn pending_join_agreements(&self) -> Vec<String> {
        self.lock()
            .pending_joins
            .iter()
            .map(|join| join.agreement_id.clone())
            .collect()
    }

    /// The pending joins whose rows at the Portal have not been read for
    /// [`OP_LANDING_CHECK_INTERVAL`] — neither in a ready listing nor in
    /// their agreement's detail — longest unread first, at most
    /// [`MAX_JOIN_CHECKS_PER_CYCLE`]. Each is looked up in its agreement's
    /// detail (see [`Self::join_verified`]).
    #[must_use]
    pub fn joins_to_verify(&self, now: Instant) -> Vec<String> {
        let state = self.lock();
        let mut due: Vec<&PendingJoin> = state
            .pending_joins
            .iter()
            .filter(|join| now.duration_since(join.checked) >= OP_LANDING_CHECK_INTERVAL)
            .collect();
        due.sort_by_key(|join| join.checked);
        let mut ids: Vec<String> = Vec::new();
        for join in due {
            if !ids.contains(&join.agreement_id) {
                ids.push(join.agreement_id.clone());
            }
            if ids.len() == MAX_JOIN_CHECKS_PER_CYCLE {
                break;
            }
        }
        ids
    }

    /// The Portal's rows show these joins still held: the row `valid`, the
    /// agreement still open.
    pub fn joins_vouched(&self, agreement_ids: &[String], now: Instant) {
        let mut state = self.lock();
        for join in &mut state.pending_joins {
            if agreement_ids.contains(&join.agreement_id) {
                join.heard = now;
                join.checked = now;
            }
        }
    }

    /// What the agreement's detail says about the pending join of
    /// `agreement_id` (see [`Self::joins_to_verify`]): `Some(true)` while the
    /// Portal still holds it, `Some(false)` when it will never execute — the
    /// collateral goes back to the budget — and `None` when the detail could
    /// not be read. Unread, the join stays committed and is asked about again
    /// next cycle; only after [`JOIN_COMMITMENT_BACKSTOP`] without a word is
    /// it given up.
    pub fn join_verified(&self, agreement_id: &str, held: Option<bool>, now: Instant) {
        match held {
            Some(true) => self.joins_vouched(&[agreement_id.to_string()], now),
            Some(false) => self.release_joins(&[agreement_id.to_string()]),
            None => {
                let mut state = self.lock();
                state.pending_joins.retain(|join| {
                    let lost = join.agreement_id == agreement_id
                        && now.duration_since(join.heard) >= JOIN_COMMITMENT_BACKSTOP;
                    if lost {
                        warn!(
                            "the Portal has not been able to say whether it holds the join of {} \
                             for {} hours; giving its {} KOR back to the budget",
                            join.agreement_id,
                            JOIN_COMMITMENT_BACKSTOP.as_secs() / 3600,
                            join.collateral
                        );
                    }
                    !lost
                });
            }
        }
    }

    /// Give back the collateral of joins that will never reserve anything.
    pub fn release_joins(&self, agreement_ids: &[String]) {
        if agreement_ids.is_empty() {
            return;
        }
        let mut state = self.lock();
        state.pending_joins.retain(|join| {
            let settled = agreement_ids.contains(&join.agreement_id);
            if settled {
                info!(
                    "the join of {} will not execute; its {} KOR are back in the budget",
                    join.agreement_id, join.collateral
                );
            }
            !settled
        });
    }

    /// The next op to send, if any. One at a time — the next waits until the
    /// last has landed — except the exit's leaves, which go out while others
    /// are still in flight, up to [`MAX_LEAVES_IN_FLIGHT`] of them: a leave
    /// changes nothing another leave depends on (see [`manage_stake`], which
    /// asks again after each leave it has sent).
    ///
    /// `exit` is the daemon's view of its memberships, passed while the node is
    /// [`exiting`](Self::exiting). The exit was started by the operator and is
    /// carried through whatever auto-stake says: leave every membership whose
    /// challenges are settled, then withdraw once none is left, no leave is
    /// in flight and the delay has (by the node's reckoning) passed.
    #[must_use]
    pub fn plan(&self, now: Instant, exit: Option<&ExitInputs>) -> Option<NodeOp> {
        let mut state = self.lock();
        state.exit = exit.cloned();
        let state = &*state;
        let snapshot = state.snapshot.as_ref()?;
        if !state.in_flight.is_empty() {
            // Only another leave may join leaves in flight — and not when the
            // operator has asked for something, which goes next, alone.
            let leaves_only = state
                .in_flight
                .iter()
                .all(|op| matches!(op.op, NodeOp::LeaveAgreement(_)));
            if !leaves_only
                || state.in_flight.len() >= MAX_LEAVES_IN_FLIGHT
                || state.operator_request.is_some()
            {
                return None;
            }
            return match (snapshot.withdrawal_height, exit) {
                (Some(_), Some(exit)) => next_leave(state, exit, now),
                _ => None,
            };
        }

        // The operator's own request outranks the policy, and is honoured
        // whatever auto-stake says: it was asked for by hand.
        if let Some(op) = &state.operator_request {
            return Some(op.clone());
        }

        if let (Some(_), Some(exit)) = (snapshot.withdrawal_height, exit) {
            if let Some(op) = next_exit_op(state, exit, now) {
                return Some(op);
            }
        }

        if !state.policy.auto_stake {
            return None;
        }

        if !state.exited && state.exit_record_read {
            if let Some(amount) = top_up_amount(&state.policy, snapshot) {
                let op = NodeOp::AddStake(amount);
                if !refused_recently(state, &op, now) {
                    return Some(op);
                }
            }
        }

        let claim_due = state
            .last_claim
            .is_none_or(|last| now.duration_since(last) >= CLAIM_INTERVAL);
        let claimable = snapshot
            .reward_balance
            .is_some_and(|rewards| rewards >= state.policy.claim_threshold);
        (claim_due && claimable).then_some(NodeOp::ClaimRewards)
    }

    /// The relay accepted `op` at `nonce`.
    pub fn record_sent(&self, op: NodeOp, nonce: u64, now: Instant) {
        let event = describe_sent(&op, nonce);
        self.track(op, nonce, now, event, false);
    }

    /// `op` was signed at `nonce` and sent, and no answer came back that says
    /// whether the Portal kept it (see [`UnsettledOp`]). It is tracked exactly
    /// like one the relay accepted: its nonce is consumed either way, and if
    /// the Portal did store it, signing it again would execute it twice. The
    /// Portal's listing settles it after [`OP_LANDING_CHECK_INTERVAL`] (see
    /// [`Self::verify_in_flight`]) — gone, the plan is made again.
    pub fn record_unsettled(&self, op: NodeOp, nonce: u64, now: Instant) {
        let event = format!("{}; the Portal gave no answer", describe_sent(&op, nonce));
        self.track(op, nonce, now, event, true);
    }

    fn track(&self, op: NodeOp, nonce: u64, now: Instant, event: String, unsettled: bool) {
        let mut state = self.lock();
        match op {
            NodeOp::ClaimRewards => state.last_claim = Some(now),
            NodeOp::WithdrawStake => {
                state.last_withdraw = Some(now);
                state.withdraw_retry = None;
            }
            _ => {}
        }
        let requested = op == NodeOp::BeginUnstake || state.operator_request.as_ref() == Some(&op);
        if state.operator_request.as_ref() == Some(&op) {
            state.operator_request = None;
        }
        state.last_event = Some((Utc::now(), event));
        let stake_before = state.snapshot.as_ref().map(|snapshot| snapshot.stake);
        state.in_flight.push(InFlight {
            op,
            nonce,
            sent: now,
            sent_at: Utc::now(),
            unsettled,
            requested,
            stake_before,
            checked: None,
            vouched: None,
            orphaned: None,
        });
        state.in_flight.sort_by_key(|op| op.nonce);
    }

    /// The relay refused `op`. A refusal is not retried until something
    /// changes: a claim waits its interval, a withdrawal its retry interval,
    /// an `add-stake` — and a leave, for its agreement only —
    /// [`REFUSED_OP_RETRY_INTERVAL`], and an operator request is dropped (the
    /// operator sees why and can ask again).
    pub fn record_refused(&self, op: &NodeOp, reason: &str, now: Instant) {
        let mut state = self.lock();
        match op {
            NodeOp::ClaimRewards => state.last_claim = Some(now),
            NodeOp::WithdrawStake => state.last_withdraw = Some(now),
            NodeOp::AddStake(_) | NodeOp::LeaveAgreement(_) => {
                state
                    .refused
                    .retain(|_, at| now.duration_since(*at) < REFUSED_OP_RETRY_INTERVAL);
                state.refused.insert(refused_key(op), now);
            }
            NodeOp::BeginUnstake => {}
        }
        if state.operator_request.as_ref() == Some(op) {
            state.operator_request = None;
        }
        state.last_event = Some((Utc::now(), format!("{} refused: {reason}", op.name())));
    }

    /// Queue an unstake or withdrawal for the daemon's next cycle.
    ///
    /// # Errors
    /// If `op` is not one an operator may request, another request is
    /// already waiting, or the same op is already in flight — signed and not
    /// executed yet; asked for again it would run twice.
    pub fn request(&self, op: NodeOp) -> Result<(), &'static str> {
        if !matches!(op, NodeOp::BeginUnstake | NodeOp::WithdrawStake) {
            return Err("only an unstake or a withdrawal can be requested");
        }
        let mut state = self.lock();
        if state.operator_request.is_some() {
            return Err("another request is already waiting for the next cycle");
        }
        if state.in_flight.iter().any(|sent| sent.op == op) {
            return Err(match op {
                NodeOp::BeginUnstake => {
                    "an unstake is already in flight: signed, and not executed yet"
                }
                _ => "a withdrawal is already in flight: signed, and not executed yet",
            });
        }
        state.last_event = Some((Utc::now(), format!("{} requested from /admin", op.name())));
        state.operator_request = Some(op);
        Ok(())
    }

    /// This cycle's join budget, from the latest snapshot.
    #[must_use]
    pub fn join_budget(&self, now: Instant) -> JoinBudget {
        let mut state = self.lock();
        if let Some((until, _)) = &state.joins_paused {
            if now >= *until {
                state.joins_paused = None;
            }
        }

        // An unstake on its way: no join from the moment the operator asked,
        // not only from the block it executes in — nor while one that landed
        // without starting the withdrawal waits for the Portal to say whether
        // it ran at all (it is signed again if it did not).
        let leaving = matches!(state.operator_request, Some(NodeOp::BeginUnstake))
            || state
                .in_flight
                .iter()
                .any(|op| op.op == NodeOp::BeginUnstake)
            || state
                .unexplained
                .iter()
                .any(|landed| landed.op == NodeOp::BeginUnstake);

        let mode = match (&state.snapshot, &state.joins_paused) {
            (None, _) if !state.portal_reports_stake => BudgetMode::Unmetered,
            (None, _) => BudgetMode::Closed(SkipReason::StakeUnknown),
            (Some(_), _) if leaving => BudgetMode::Closed(SkipReason::Leaving),
            (Some(_), Some((_, code))) => {
                BudgetMode::Closed(SkipReason::RecentlyRefused(code.clone()))
            }
            (Some(snapshot), None) => match (snapshot.join_blocker(), snapshot.available) {
                (Some(reason), _) => BudgetMode::Closed(reason),
                // The bond is known, what is free of it is not: no join
                // against reservations nobody could read.
                (None, None) => BudgetMode::Closed(SkipReason::StakeUnknown),
                (None, Some(available)) => {
                    let held = state.pending_joins.iter().fold(Kor::ZERO, |sum, join| {
                        sum.checked_add(join.collateral).unwrap_or(sum)
                    });
                    let seen = state
                        .recent_collateral
                        .iter()
                        .filter(|(at, _)| now.duration_since(*at) < COLLATERAL_MEMORY)
                        .map(|(_, amount)| *amount)
                        .max()
                        .unwrap_or(Kor::ZERO);
                    BudgetMode::Metered {
                        remaining: available.saturating_sub(held),
                        estimate: state.policy.unknown_collateral_estimate.max(seen),
                        guesses_left: MAX_UNKNOWN_COLLATERAL_JOINS_PER_CYCLE,
                    }
                }
            },
        };
        JoinBudget {
            mode,
            skipped: HashMap::new(),
        }
    }

    /// A join was accepted; hold its collateral until it executes.
    pub fn record_join(&self, agreement_id: &str, collateral: Kor, nonce: u64, now: Instant) {
        self.lock().pending_joins.push(PendingJoin {
            agreement_id: agreement_id.to_string(),
            collateral,
            nonce,
            heard: now,
            checked: now,
        });
    }

    /// The Portal refused a join with `code`; stop trying for a while.
    pub fn pause_joins(&self, code: &str, now: Instant) {
        let mut state = self.lock();
        state.joins_paused = Some((now + JOIN_REFUSAL_COOLDOWN, code.to_string()));
        state.last_event = Some((
            Utc::now(),
            format!(
                "join refused ({code}); joins paused for {} minutes",
                JOIN_REFUSAL_COOLDOWN.as_secs() / 60
            ),
        ));
    }

    /// What `GET /api/admin/status` shows under `staking`.
    #[must_use]
    pub fn status(&self) -> Value {
        let state = self.lock();
        let policy = &state.policy;
        json!({
            "reported": state.snapshot.is_some(),
            "portal_reports_stake": state.portal_reports_stake,
            "observed_at": state.observed_at.map(|at| at.to_rfc3339()),
            "kor_balance": state.snapshot.as_ref().and_then(|s| s.kor_balance),
            "stake": state.snapshot.as_ref().map(|s| s.stake),
            "reserved": state.snapshot.as_ref().and_then(|s| s.reserved),
            "available": state.snapshot.as_ref().and_then(|s| s.available),
            "withdrawal_height": state.snapshot.as_ref().and_then(|s| s.withdrawal_height),
            "bond_cleanup_pending": state.snapshot.as_ref().and_then(|s| s.bond_cleanup_pending),
            "reward_balance": state.snapshot.as_ref().and_then(|s| s.reward_balance),
            "policy": {
                "auto_stake": policy.auto_stake,
                "gas_reserve": policy.gas_reserve,
                "stake_target": policy.stake_target,
                "claim_threshold": policy.claim_threshold,
            },
            "in_flight": state.in_flight.last().map(|op| json!({
                "op": op.op.name(),
                "amount": op.op.amount(),
                "nonce": op.nonce,
                "sent_at": op.sent_at.to_rfc3339(),
            })),
                        "in_flight_count": state.in_flight.len(),
            "pending_joins": state.pending_joins.iter().map(|join| json!({
                "agreement_id": join.agreement_id,
                "collateral": join.collateral,
                "nonce": join.nonce,
            })).collect::<Vec<_>>(),
            "joins_paused": state.joins_paused.as_ref().map(|(_, code)| code.clone()),
            "operator_request": state.operator_request.as_ref().map(NodeOp::name),
            "exit": state.exit.as_ref().filter(|_| {
                state.snapshot.as_ref().is_some_and(|s| s.withdrawal_height.is_some())
            }).map(|exit| {
                let remaining: Vec<&String> = exit
                    .memberships
                    .iter()
                    .filter(|id| !state.left.contains(*id))
                    .collect();
                let withdraw_from = state
                    .withdrawal
                    .map(|timer| timer.due_at().to_rfc3339());
                json!({
                    "memberships_left": remaining,
                    "deferred": exit.deferred,
                    "left": state.left.len(),
                    "unresolved_challenges": exit.unresolved_challenges,
                    "withdraw_estimated_from": withdraw_from,
                })
            }),
            "exited": state.exited,
            "last_event": state.last_event.as_ref().map(|(at, what)| json!({
                "at": at.to_rfc3339(),
                "message": what,
            })),
        })
    }
}

/// The `error` the Portal writes on a `failed` op that Kontor never ran
/// (Portal `docs/node-portal-contract.md` §2 "Retirement reasons"). The
/// Portal promises a stable token at the start of each message; the text
/// after the colon is for humans and may change, so only the token is
/// matched, with `starts_with`, never a word Kontor's own errors could share:
///
/// - `NO_RECEIPT_ERROR`, the whole message, for an op whose nonce another op
///   consumed before it ran (or whose gas hold the node's balance did not
///   cover);
/// - `nonce already passed:`, the stale-nonce retirement at compose time;
/// - `signature no longer verifies:`, the key-rotation retirement, for a
///   signature that no longer verifies against the key the node registered
///   after signing;
/// - `the stored op cannot be batched by this Portal`, the start of the
///   message for a stored op the Portal cannot rebuild (`… (reason), so it
///   never executed (no receipt); sign a new op`).
const PORTAL_NO_RECEIPT: &str = "no receipt recorded by Kontor (op never executed)";
const PORTAL_STALE_NONCE_TOKEN: &str = "nonce already passed:";
const PORTAL_UNVERIFIABLE_TOKEN: &str = "signature no longer verifies:";
const PORTAL_UNBATCHABLE_HEAD: &str = "the stored op cannot be batched by this Portal";

/// The start of the `error` the Portal writes on a `submitted` op whose
/// transaction row it no longer has (§2, same list): `the Portal transaction
/// that carried the op no longer exists, so whether it executed cannot be
/// checked; …`. Neither a retirement nor a refusal — the Portal does not know
/// whether Kontor ran the op. See [`orphaned_by_portal`].
const PORTAL_ORPHANED_HEAD: &str = "the Portal transaction that carried the op no longer exists";

/// Whether a `failed` op's error is the Portal retiring it unexecuted rather
/// than Kontor refusing it. Only the Portal's own retirement messages count
/// (see [`PORTAL_NO_RECEIPT`] and the constants after it): an op the Portal
/// retired is signed again at once, one Kontor refused waits
/// [`REFUSED_OP_RETRY_INTERVAL`], so a Kontor `ContractErr` that happens to
/// mention a nonce must not pass for a retirement.
fn retired_by_portal(error: &str) -> bool {
    let error = error.trim();
    error == PORTAL_NO_RECEIPT
        || error.starts_with(PORTAL_STALE_NONCE_TOKEN)
        || error.starts_with(PORTAL_UNVERIFIABLE_TOKEN)
        || error.starts_with(PORTAL_UNBATCHABLE_HEAD)
}

/// Whether Kontor's error for a `leave-agreement` says this node holds no
/// membership in `agreement_id` to leave. `filestorage::leave-agreement`
/// answers `node {signer} not in agreement {id}` when the membership row is
/// missing or no longer active — which is how bond cleanup leaves every
/// membership of a node slashed to zero, without the Portal's row ever
/// turning `left` — and `agreement not found: {id}` when the agreement itself
/// is gone. The Portal relays the receipt as `ContractErr: <value>`, so the
/// phrases are looked for inside it.
fn no_membership_to_leave(error: &str, agreement_id: &str) -> bool {
    error.contains(&format!("not in agreement {agreement_id}"))
        || error.contains(&format!("agreement not found: {agreement_id}"))
}

/// Whether a `failed` op's error is the Portal saying it lost the transaction
/// that carried the op ([`PORTAL_ORPHANED_HEAD`]), and so cannot tell whether
/// the op ran. Decided by what the nonce and the bond say: while the nonce is
/// free the op may still execute and is not signed again
/// ([`StakeTracker::verify_in_flight`]); once it is consumed the op is over,
/// and the next plan is made from the state as it stands, without the wait a
/// refusal by Kontor earns ([`StakeTracker::classify_landed`]).
fn orphaned_by_portal(error: &str) -> bool {
    error.trim().starts_with(PORTAL_ORPHANED_HEAD)
}

fn describe_sent(op: &NodeOp, nonce: u64) -> String {
    match (op.amount(), op.agreement_id()) {
        (Some(amount), _) => format!("{} {amount} KOR sent (nonce {nonce})", op.name()),
        (None, Some(agreement_id)) => {
            format!("{} {agreement_id} sent (nonce {nonce})", op.name())
        }
        (None, None) => format!("{} sent (nonce {nonce})", op.name()),
    }
}

/// The leaves whose outcome is not known yet: in flight, or executed without
/// the Portal having said how (see `classify_landed`). Their agreements are
/// not left, are not left again, and nothing is withdrawn behind them.
fn undecided_leaves(state: &TrackerState) -> Vec<&str> {
    state
        .in_flight
        .iter()
        .map(|op| &op.op)
        .chain(state.unexplained.iter().map(|landed| &landed.op))
        .filter_map(NodeOp::agreement_id)
        .collect()
}

/// The next membership to leave, if any is due: not left yet, no leave of it
/// in flight or undecided, no open challenge on it, not refused in the last
/// hour.
fn next_leave(state: &TrackerState, exit: &ExitInputs, now: Instant) -> Option<NodeOp> {
    let undecided = undecided_leaves(state);
    exit.memberships
        .iter()
        .find(|id| {
            !state.left.contains(*id)
                && !undecided.contains(&id.as_str())
                && !exit.deferred.contains(id)
                && !refused_recently(state, &NodeOp::LeaveAgreement((*id).clone()), now)
        })
        .map(|agreement_id| NodeOp::LeaveAgreement(agreement_id.clone()))
}

/// The next step of the exit, if one is due: a leave, or — every membership
/// left and no leave undecided — the withdrawal.
fn next_exit_op(state: &TrackerState, exit: &ExitInputs, now: Instant) -> Option<NodeOp> {
    if let Some(leave) = next_leave(state, exit, now) {
        return Some(leave);
    }
    let all_left = exit.memberships.iter().all(|id| state.left.contains(id));
    (all_left
        && undecided_leaves(state).is_empty()
        && exit.unresolved_challenges == 0
        && withdraw_due(state, now))
    .then_some(NodeOp::WithdrawStake)
}

/// The delay has passed by the node's reckoning, and the last automatic
/// attempt is far enough back.
fn withdraw_due(state: &TrackerState, now: Instant) -> bool {
    let Some(timer) = state.withdrawal else {
        return false;
    };
    let retry = state.withdraw_retry.unwrap_or(WITHDRAW_RETRY_INTERVAL);
    timer.elapsed(now) >= withdrawal_delay()
        && state
            .last_withdraw
            .is_none_or(|last| now.duration_since(last) >= retry)
}

/// Log, and return for the status page, what changed between two reads that
/// the operator has to know about.
fn describe_transition(previous: &StakeSnapshot, current: &StakeSnapshot) -> Option<String> {
    let mut event = None;

    // A bond that went to zero while a withdrawal was pending is the
    // withdrawal completing — whether or not its op is still tracked in
    // flight, which one that landed after the in-flight expiry is not —
    // unless the node is in bond cleanup. A withdrawal returns the bond and
    // leaves nothing to clean up; a slash to zero leaves the memberships to
    // unwind, and Kontor clears the withdrawal height with the stake, so the
    // registry otherwise looks the same. Whether cleanup is pending has to be
    // known for that: unread, the drop is reported as what it may be.
    //
    // That a `withdraw-stake` landed on this read says nothing by itself:
    // Kontor refuses one made too early or with an obligation outstanding,
    // and the bond is then still there. If it shrank on the same read, that
    // was a slash, and it is reported as one.
    let exit_over = current.stake.is_zero() && previous.withdrawal_height.is_some();
    let withdrawn = exit_over && current.bond_cleanup_pending == Some(false);
    let undecided = exit_over && current.bond_cleanup_pending.is_none();
    if current.stake < previous.stake && !withdrawn && !undecided {
        let lost = previous.stake.saturating_sub(current.stake);
        error!(
            "stake dropped from {} to {} KOR (−{lost}): a missed challenge was slashed at 30× \
             the agreement's collateral",
            previous.stake, current.stake
        );
        event = Some(format!(
            "stake dropped by {lost} KOR ({} → {}): slashed",
            previous.stake, current.stake
        ));
    }

    match (previous.bond_cleanup_pending, current.bond_cleanup_pending) {
        (Some(false) | None, Some(true)) => {
            error!(
                "bond cleanup is pending: this node's stake was slashed to zero. It cannot join \
                 or add stake until Kontor finishes unwinding its memberships"
            );
            event = Some("bond cleanup pending".to_string());
        }
        (Some(true), Some(false)) => {
            info!("bond cleanup has finished; the node can add stake and join again");
            event = Some("bond cleanup finished".to_string());
        }
        _ => {}
    }

    match (previous.withdrawal_height, current.withdrawal_height) {
        (None, Some(height)) => {
            warn!("withdrawal requested: joins stop, and the stake can be withdrawn from height {height} once no agreement holds it");
            event = Some(format!("withdrawal requested, unlocks at height {height}"));
        }
        (Some(_), None) if current.bond_cleanup_pending.is_none() => {
            warn!(
                "the exit is over: no stake is bonded and no withdrawal is pending, but the \
                 Portal could not say whether bond cleanup is pending, so whether the bond was \
                                  withdrawn or slashed to zero is not known. This node bonds nothing more on its \
                 own, across restarts too; check the balance, and resume staking from /admin \
                 to bond again"
            );
            event =
                Some("exit over: withdrawn or slashed, the Portal could not say which".to_string());
        }
        (Some(_), None) if current.bond_cleanup_pending == Some(true) => {
            warn!(
                "the exit ended in a slash: the stake went to zero before it was withdrawn, \
                                  and Kontor cleared the withdrawal with it. This node bonds nothing more on \
                 its own, across restarts too; resume staking from /admin to bond again once \
                 bond cleanup is done"
            );
            event = Some("slashed to zero during the exit: nothing left to withdraw".to_string());
        }
        (Some(_), None) => {
            info!("the withdrawal has completed");
            event = Some("withdrawal completed".to_string());
        }
        _ => {}
    }

    event
}

/// This cycle's allowance for new joins.
#[derive(Debug)]
pub struct JoinBudget {
    mode: BudgetMode,
    skipped: HashMap<SkipReason, usize>,
}

#[derive(Debug)]
enum BudgetMode {
    /// The Portal predates staking: join as before.
    Unmetered,
    /// No new join this cycle, for this reason.
    Closed(SkipReason),
    /// Unreserved stake left for this cycle's joins, what a join of unknown
    /// collateral is assumed to take, and how many of those are still allowed.
    Metered {
        remaining: Kor,
        estimate: Kor,
        guesses_left: usize,
    },
}

/// Whether to download (and join) one pending agreement.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinDecision {
    /// Go ahead. `collateral` is what was set aside for it, to hold until the
    /// join executes — `None` when nothing new is reserved.
    Join {
        collateral: Option<Kor>,
    },
    Skip(SkipReason),
}

impl JoinBudget {
    /// A budget that gates nothing, for callers that predate staking.
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            mode: BudgetMode::Unmetered,
            skipped: HashMap::new(),
        }
    }

    /// Decide on one agreement.
    ///
    /// `already_member` short-circuits everything: a membership the node holds
    /// already reserved its collateral, and a file it is obligated to store but
    /// has not downloaded is exactly what a challenge will slash it for — so
    /// that download is never held back, not even during cleanup.
    ///
    /// `listed` is the agreement's entry in this cycle's ready listing: `None`
    /// when it is not listed, `Some(None)` when it is but the Portal does not
    /// know its collateral yet.
    ///
    /// A known collateral is checked exactly. An unknown one — the usual case,
    /// since the Portal joins in the same batch that creates the agreement — is
    /// a guess: allowed only while the unreserved stake left covers the
    /// estimate, at most [`MAX_UNKNOWN_COLLATERAL_JOINS_PER_CYCLE`] per cycle,
    /// and charged the estimate, so a few of them use the budget up. A stake
    /// that cannot cover even the estimate would most likely be refused the
    /// join on chain, so the download is not made. A guess that still turns out
    /// short costs a refused join on chain, which is not slashable: only the
    /// download is wasted.
    pub fn decide(&mut self, already_member: bool, listed: Option<Option<&str>>) -> JoinDecision {
        if already_member {
            return JoinDecision::Join { collateral: None };
        }
        let decision = match &mut self.mode {
            BudgetMode::Unmetered => JoinDecision::Join {
                collateral: listed.flatten().and_then(|raw| Kor::parse(raw).ok()),
            },
            BudgetMode::Closed(reason) => JoinDecision::Skip(reason.clone()),
            BudgetMode::Metered {
                remaining,
                estimate,
                guesses_left,
            } => match listed {
                None => JoinDecision::Skip(SkipReason::NotListed),
                Some(None) if *remaining < *estimate => {
                    JoinDecision::Skip(SkipReason::InsufficientCollateral)
                }
                Some(None) if *guesses_left == 0 => {
                    JoinDecision::Skip(SkipReason::CollateralUnknown)
                }
                Some(None) => {
                    *remaining = remaining.saturating_sub(*estimate);
                    *guesses_left -= 1;
                    JoinDecision::Join {
                        collateral: Some(*estimate),
                    }
                }
                Some(Some(raw)) => match Kor::parse(raw) {
                    Err(err) => {
                        warn!("ignoring an unreadable required_collateral: {err:#}");
                        JoinDecision::Skip(SkipReason::CollateralUnknown)
                    }
                    Ok(required) if required.is_zero() => {
                        JoinDecision::Skip(SkipReason::NoCollateralRequirement)
                    }
                    Ok(required) if required > *remaining => {
                        JoinDecision::Skip(SkipReason::InsufficientCollateral)
                    }
                    Ok(required) => {
                        *remaining = remaining.saturating_sub(required);
                        JoinDecision::Join {
                            collateral: Some(required),
                        }
                    }
                },
            },
        };
        if let JoinDecision::Skip(reason) = &decision {
            *self.skipped.entry(reason.clone()).or_default() += 1;
        }
        decision
    }

    /// Give back what [`Self::decide`] set aside for a join that did not
    /// happen.
    pub fn refund(&mut self, collateral: Option<Kor>) {
        if let (BudgetMode::Metered { remaining, .. }, Some(amount)) = (&mut self.mode, collateral)
        {
            *remaining = remaining.checked_add(amount).unwrap_or(*remaining);
        }
    }

    /// The Portal refused a join for a reason that holds node-wide: nothing
    /// else this cycle.
    pub fn close(&mut self, code: &str) {
        self.mode = BudgetMode::Closed(SkipReason::RecentlyRefused(code.to_string()));
    }

    /// One line for the cycle's log, if anything was skipped.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        if self.skipped.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = self
            .skipped
            .iter()
            .map(|(reason, count)| format!("{count} × {reason}"))
            .collect();
        parts.sort();
        Some(parts.join(", "))
    }
}

/// Agreement statuses under which this node cannot hold a membership on chain
/// yet, or any more: a `ready`/`pending` agreement is not created yet (the
/// Portal joins in the batch that creates it), a `failed` one never was.
const NOT_ON_CHAIN: [&str; 3] = ["ready", "pending", "failed"];

/// Statuses of this node's row in an agreement's `nodes` under which it holds
/// no membership — the Portal's `agreement_nodes` statuses other than `valid`:
/// the join `failed` on chain, was `invalid`ated before it ran, or the node has
/// `left`. Old rows store bare node-id strings, which count as memberships.
pub const NO_MEMBERSHIP: [&str; 3] = ["failed", "invalid", "left"];

/// The one status in [`NO_MEMBERSHIP`] the Portal takes a new join in place of
/// while the agreement is still `ready`: an `invalid` join was never applied
/// on chain — its nonce was stale when the batch was composed, its signature
/// no longer matched the node's key, or Kontor refused it — so nothing is
/// owed, and nothing stops a fresh one. A `failed` or `left` row is final.
pub const REJOINABLE_MEMBERSHIP: &str = "invalid";

/// Whether a `nodes[]` status (`None` for a bare node-id string) is a
/// membership this node holds.
#[must_use]
pub fn is_membership_status(status: Option<&str>) -> bool {
    status.is_none_or(|status| !NO_MEMBERSHIP.contains(&status))
}

/// Challenge statuses that are not resolved yet: still to prove, or proved
/// and waiting for the verdict. A `failed` one is unresolved too for
/// [`FAILED_CHALLENGE_SETTLEMENT_GRACE`] after the Portal marked it so.
const UNRESOLVED: [&str; 3] = ["active", "proved", "submitted"];

/// The `node_state` key under which the start of the withdrawal delay is kept,
/// as an RFC 3339 timestamp.
pub const WITHDRAWAL_STARTED_AT: &str = "stake_withdrawal_started_at";

/// The `node_state` key that records a finished exit: present, with the
/// moment it was recorded as an RFC 3339 timestamp, from when the bond came
/// back until the operator resumes staking from `/admin`.
pub const EXITED_AT: &str = "stake_exited_at";

/// Read what an earlier process recorded about the node's exit into the
/// tracker: the start of the withdrawal delay, if one was running, and
/// whether the exit had finished. Once per process, before anything is
/// planned from it — the policy bonds nothing until the second is known (see
/// [`StakeTracker::restore_exited`]).
///
/// A row that does not hold a timestamp is deleted and reported, and the
/// tracker counts from this process: a record nothing can read would
/// otherwise fail this step every cycle, and with it the write of the start
/// this process witnesses.
///
/// # Errors
/// If the row cannot be read or the unreadable one cannot be deleted; the
/// tracker then still counts from this process and the next cycle tries
/// again.
pub async fn restore_withdrawal_start(
    database: &DatabaseConnection,
    tracker: &StakeTracker,
    now: Instant,
) -> anyhow::Result<()> {
    use crate::entities::prelude::NodeState;
    use sea_orm::EntityTrait;

    let exited = NodeState::find_by_id(EXITED_AT)
        .one(database)
        .await
        .context("reading whether the node has exited")?
        .is_some();
    tracker.restore_exited(exited);

    let row = NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
        .one(database)
        .await
        .context("reading the start of the withdrawal delay")?;
    let started_at = match row {
        Some(row) => match DateTime::parse_from_rfc3339(&row.value) {
            Ok(started_at) => Some(started_at.with_timezone(&Utc)),
            Err(err) => {
                warn!(
                    "the recorded start of the withdrawal delay is unreadable ({:?}: {err}); \
                     deleting it and counting from this process",
                    row.value
                );
                NodeState::delete_by_id(WITHDRAWAL_STARTED_AT)
                    .exec(database)
                    .await
                    .context("deleting the unreadable start of the withdrawal delay")?;
                None
            }
        },
        None => None,
    };
    tracker.restore_withdrawal_start(started_at, now);
    Ok(())
}

/// Record the exit as the tracker has it: the start of the withdrawal delay
/// as it counts it, cleared once the withdrawal is over, and that the exit
/// has finished, cleared when the operator resumes staking. A no-op while
/// the database already says the same.
///
/// # Errors
/// If a row cannot be written; the next cycle tries again.
pub async fn persist_withdrawal_start(
    database: &DatabaseConnection,
    tracker: &StakeTracker,
) -> anyhow::Result<()> {
    use crate::entities::node_state;
    use crate::entities::prelude::NodeState;
    use sea_orm::{ActiveValue, EntityTrait};

    // The finished exit first: it is what keeps a restart from bonding the
    // returned balance again, and must not wait behind the other row.
    if let Some(exited) = tracker.exited_to_persist() {
        if exited {
            let now = Utc::now();
            let row = node_state::ActiveModel {
                key: ActiveValue::Set(EXITED_AT.to_string()),
                value: ActiveValue::Set(now.to_rfc3339()),
                updated_at: ActiveValue::Set(now.fixed_offset()),
            };
            NodeState::insert(row)
                .on_conflict(
                    sea_orm::sea_query::OnConflict::column(node_state::Column::Key)
                        .update_columns([node_state::Column::Value, node_state::Column::UpdatedAt])
                        .to_owned(),
                )
                .exec(database)
                .await
                .context("recording that the node has exited")?;
        } else {
            NodeState::delete_by_id(EXITED_AT)
                .exec(database)
                .await
                .context("clearing the record of the node's exit")?;
        }
        tracker.exited_persisted(exited);
    }

    let Some(started_at) = tracker.withdrawal_start_to_persist() else {
        return Ok(());
    };
    match started_at {
        Some(started_at) => {
            let row = node_state::ActiveModel {
                key: ActiveValue::Set(WITHDRAWAL_STARTED_AT.to_string()),
                value: ActiveValue::Set(started_at.to_rfc3339()),
                updated_at: ActiveValue::Set(Utc::now().fixed_offset()),
            };
            NodeState::insert(row)
                .on_conflict(
                    sea_orm::sea_query::OnConflict::column(node_state::Column::Key)
                        .update_columns([node_state::Column::Value, node_state::Column::UpdatedAt])
                        .to_owned(),
                )
                .exec(database)
                .await
                .context("recording the start of the withdrawal delay")?;
        }
        None => {
            NodeState::delete_by_id(WITHDRAWAL_STARTED_AT)
                .exec(database)
                .await
                .context("clearing the start of the withdrawal delay")?;
        }
    }
    tracker.withdrawal_start_persisted(started_at);
    Ok(())
}

/// Release the collateral of pending joins that will never execute, from what
/// this cycle learned about their agreements.
///
/// A join is held in the budget until its nonce is consumed. It never is when
/// the Portal retires the join instead — `invalid`, a stale nonce or a
/// signature that no longer verifies — or when the agreement it was for never
/// makes it on chain. Both show in what the cycle has just read: this node's
/// row in `listing` (the ready agreements, with every member's status) is in
/// [`NO_MEMBERSHIP`] or missing, or the agreement is no longer
/// `ready`/`pending` by its local row.
///
/// A join the listing shows still held — its row `valid` — is vouched for.
/// One the listing does not carry while the local row still says
/// `ready`/`pending` is not settled here: the agreement is in a batch, or the
/// local row is behind. Its agreement's detail says which, and is read for it
/// after [`OP_LANDING_CHECK_INTERVAL`] (see [`StakeTracker::joins_to_verify`]).
/// No clock releases a join the Portal may still hold.
///
/// # Errors
/// If the rows cannot be read.
pub async fn settle_pending_joins(
    database: &DatabaseConnection,
    tracker: &StakeTracker,
    node_id: &str,
    listing: &ReadyListing,
) -> anyhow::Result<()> {
    use crate::entities::agreements;
    use crate::entities::prelude::Agreements;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let pending = tracker.pending_join_agreements();
    if pending.is_empty() {
        return Ok(());
    }
    let mut settled = Vec::new();
    let mut vouched = Vec::new();
    let mut unlisted = Vec::new();
    for agreement_id in pending {
        match listing.get(&agreement_id) {
            // Every pending join was accepted before this listing was read,
            // so its row is in it: `valid` and still held, or retired — and a
            // listing with no row of this node at all holds no join of it.
            Some(listed) if holds_join_of(&listed.nodes, node_id) => vouched.push(agreement_id),
            Some(_) => settled.push(agreement_id),
            None => unlisted.push(agreement_id),
        }
    }
    tracker.joins_vouched(&vouched, Instant::now());
    if !unlisted.is_empty() {
        let rows = Agreements::find()
            .filter(agreements::Column::AgreementId.is_in(unlisted))
            .all(database)
            .await
            .context("loading the agreements of pending joins")?;
        settled.extend(
            rows.into_iter()
                .filter(|row| !matches!(row.status.as_str(), "ready" | "pending"))
                .map(|row| row.agreement_id),
        );
    }
    tracker.release_joins(&settled);
    Ok(())
}

/// Whether `nodes`, an agreement's member rows as the Portal lists them,
/// carry a row of `node_id` that is a membership — a join still held, or one
/// that has executed.
fn holds_join_of(nodes: &[crate::clients::portal::AgreementNode], node_id: &str) -> bool {
    nodes
        .iter()
        .any(|node| node.node_id == node_id && is_membership_status(Some(node.status.as_str())))
}

/// Ask the Portal about the pending joins the ready listing has not shown
/// for a while (see [`StakeTracker::joins_to_verify`]): each agreement's
/// detail says whether the join is still held — the agreement not failed,
/// this node's row a membership — or will never execute. A `404` is the
/// Portal no longer knowing the agreement, which is an answer; any other
/// failure is none.
async fn settle_overdue_joins(client: &PortalClient, tracker: &StakeTracker, now: Instant) {
    let Some(node_id) = client.node_id() else {
        return;
    };
    for agreement_id in tracker.joins_to_verify(now) {
        let held = match client.get_agreement(&agreement_id).await {
            Ok(agreement) => {
                Some(agreement.status != "failed" && holds_join_of(&agreement.nodes, node_id))
            }
            Err(err) => match status_and_code(&err) {
                Some((404, _)) => Some(false),
                _ => {
                    debug!("could not ask the Portal about the join of {agreement_id}: {err:#}");
                    None
                }
            },
        };
        tracker.join_verified(&agreement_id, held, now);
    }
}

/// Bring the rows of the memberships the exit acts on up to date with the
/// Portal.
///
/// Reconciliation lists the agreements this node *validly* belongs to
/// (`GET /api/agreements?nodes=`), so once the Portal marks a membership
/// `left` — a confirmed leave — or `invalid` or `failed`, the agreement drops
/// out of that listing and the local row keeps saying `valid`. Before the
/// exit's first step in a process, and again whenever it has to resend its
/// leaves, each membership the rows still show is re-read one by one, and its
/// `nodes` and `status` rewritten. A leave is then not paid for a membership
/// that is already gone.
///
/// One agreement the Portal cannot serve does not hold the others back, nor
/// the exit: its row is left as it is and reported, and the rest are
/// refreshed. Acting on that one stale row costs at most a leave Kontor
/// answers "not in agreement" — which counts as left — where waiting for it
/// stalled the whole exit for as long as that one request kept failing.
/// Reconciliation re-reads the stale rows every cycle, so it is tried again.
///
/// # Errors
/// If the rows cannot be read or written; the exit then waits a cycle.
pub async fn refresh_memberships(
    client: &PortalClient,
    database: &DatabaseConnection,
    node_id: &str,
) -> anyhow::Result<()> {
    refresh_memberships_except(client, database, node_id, &[]).await
}

/// [`refresh_memberships`] for the rows not among `current`: the agreements
/// the Portal's filtered listing has just returned, which reconciliation has
/// already rewritten from it. What is left are the rows that claim a live
/// membership the Portal no longer lists for this node — the stale `valid`
/// rows of memberships that went `left`, `invalid` or `failed` — each re-read
/// from its detail, which carries every row whatever its status.
///
/// # Errors
/// As [`refresh_memberships`].
pub async fn refresh_memberships_except(
    client: &PortalClient,
    database: &DatabaseConnection,
    node_id: &str,
    current: &[String],
) -> anyhow::Result<()> {
    use crate::entities::agreements;
    use crate::entities::prelude::Agreements;
    use sea_orm::{ActiveValue, EntityTrait};

    let rows = Agreements::find().all(database).await?;
    let mut unread = Vec::new();
    for row in rows
        .into_iter()
        .filter(|agreement| !current.contains(&agreement.agreement_id))
        .filter(|agreement| !NOT_ON_CHAIN.contains(&agreement.status.as_str()))
        .filter(|agreement| is_live_member(&agreement.nodes, node_id))
    {
        let remote = match client.get_agreement(&row.agreement_id).await {
            Ok(remote) => remote,
            Err(err) => {
                debug!("could not re-read membership {}: {err:#}", row.agreement_id);
                unread.push(row.agreement_id);
                continue;
            }
        };
        let nodes = serde_json::to_value(&remote.nodes).context("serializing agreement nodes")?;
        if nodes == row.nodes && remote.status == row.status {
            continue;
        }
        if !is_live_member(&nodes, node_id) {
            info!(
                "membership {} is over according to the Portal; no leave will be sent for it",
                row.agreement_id
            );
        }
        Agreements::update(agreements::ActiveModel {
            agreement_id: ActiveValue::Unchanged(row.agreement_id),
            nodes: ActiveValue::Set(nodes),
            status: ActiveValue::Set(remote.status),
            ..Default::default()
        })
        .exec(database)
        .await
        .context("updating a membership's row")?;
    }
    if !unread.is_empty() {
        warn!(
            "could not re-read {} membership(s) from the Portal ({}); their rows stand as they \
             are until the next cycle",
            unread.len(),
            unread
                .iter()
                .take(5)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Read the node's memberships and open challenges from its own rows.
///
/// A membership is an agreement on chain whose `nodes` lists this node with a
/// status outside [`NO_MEMBERSHIP`] (old rows store bare node-id strings, which
/// count).
///
/// # Errors
/// If the rows cannot be read.
pub async fn exit_inputs(
    database: &DatabaseConnection,
    node_id: &str,
) -> anyhow::Result<ExitInputs> {
    use crate::entities::prelude::{Agreements, Challenges};
    use sea_orm::EntityTrait;

    let mut memberships: Vec<String> = Agreements::find()
        .all(database)
        .await?
        .into_iter()
        .filter(|agreement| !NOT_ON_CHAIN.contains(&agreement.status.as_str()))
        .filter(|agreement| is_live_member(&agreement.nodes, node_id))
        .map(|agreement| agreement.agreement_id)
        .collect();
    memberships.sort();

    let challenges = Challenges::find().all(database).await?;
    let settling_until = Utc::now()
        - chrono::Duration::from_std(FAILED_CHALLENGE_SETTLEMENT_GRACE).unwrap_or_default();
    let unresolved_challenges = challenges
        .iter()
        .filter(|challenge| {
            UNRESOLVED.contains(&challenge.status.as_str())
                || (challenge.status == "failed"
                    && DateTime::<Utc>::from(challenge.updated_at) > settling_until)
        })
        .count();
    let mut deferred: Vec<String> = challenges
        .iter()
        .filter(|challenge| challenge.status == "active")
        .map(|challenge| challenge.agreement_id.clone())
        .filter(|agreement_id| memberships.contains(agreement_id))
        .collect();
    deferred.sort();
    deferred.dedup();

    Ok(ExitInputs {
        memberships,
        deferred,
        unresolved_challenges,
    })
}

/// Whether `nodes` (an agreement row's `nodes` JSON) lists `node_id` with a
/// membership it still holds.
fn is_live_member(nodes: &Value, node_id: &str) -> bool {
    nodes.as_array().is_some_and(|nodes| {
        nodes.iter().any(|node| {
            node.as_str() == Some(node_id)
                || (node.get("node_id").and_then(Value::as_str) == Some(node_id)
                    && is_membership_status(Some(
                        node.get("status").and_then(Value::as_str).unwrap_or(""),
                    )))
        })
    })
}

/// Apply the policy for this cycle: send at most one stake or claim op — or,
/// during an exit, up to [`MAX_LEAVES_PER_CYCLE`] leaves. Returns the first
/// op sent.
///
/// Never fails the cycle. A stake op that does not go out this time is
/// re-planned from fresh state on the next one.
///
/// `exit` is the daemon's view of its memberships while the node is exiting
/// (see [`exit_inputs`]); `None` otherwise.
pub async fn manage_stake(
    client: &PortalClient,
    tracker: &StakeTracker,
    exit: Option<&ExitInputs>,
) -> Option<NodeOp> {
    client.node_id()?;
    settle_overdue_joins(client, tracker, Instant::now()).await;
    // Once per process, before anything is planned: what the Portal still
    // holds from before this process started (see
    // [`StakeTracker::adopt_pending_ops`]). Unreadable, nothing is signed
    // this cycle; the next one asks again.
    if !tracker.pending_ops_checked() && !adopt_pending_ops(client, tracker).await {
        return None;
    }
    verify_overdue_op(client, tracker, Instant::now()).await;
    classify_landed_op(client, tracker).await;
    let mut first = None;
    for _ in 0..MAX_LEAVES_PER_CYCLE {
        let Some(op) = tracker.plan(Instant::now(), exit) else {
            break;
        };
        let is_leave = matches!(op, NodeOp::LeaveAgreement(_));
        // An op that did not go out ends the cycle's sending, whatever the
        // reason: refused, unanswered, or the Portal's queue for this node
        // full (`429`).
        let Some(sent) = send(client, tracker, op).await else {
            break;
        };
        first.get_or_insert(sent);
        // Only leaves follow one another within a cycle.
        if !is_leave {
            break;
        }
    }
    first
}

/// Read the ops the Portal still holds for this node and adopt the newest as
/// in flight (see [`StakeTracker::adopt_pending_ops`]), moving the nonce
/// counter past every one of them. Returns whether the question is settled.
///
/// Only a Portal that has no such endpoint (`404`, `405`: one predating the
/// relay) holds nothing to adopt. Every other failure is no answer — the
/// session expired (`401`), the Portal asks to come back later (`408`,
/// `429`), it cannot be reached — and the Portal may well hold a queued
/// `add-stake`: nothing is signed until the listing has actually been read.
async fn adopt_pending_ops(client: &PortalClient, tracker: &StakeTracker) -> bool {
    match client.list_node_ops(&["queued", "submitted"]).await {
        Ok(ops) => {
            if let Some(top) = ops.iter().map(|record| record.nonce).max() {
                client.raise_nonce_above(top);
            }
            tracker.adopt_pending_ops(&ops, Instant::now());
            true
        }
        Err(err) => match status_and_code(&err) {
            Some((status @ (404 | 405), _)) => {
                debug!("this Portal has no listing of relayed ops ({status}): {err:#}");
                tracker.adopt_pending_ops(&[], Instant::now());
                true
            }
            _ => {
                warn!(
                    "could not ask the Portal which ops it still holds for this node; signing \
                     nothing this cycle: {err:#}"
                );
                false
            }
        },
    }
}

/// Ask the Portal how an op that just landed ended — an `add-stake` that did
/// not raise the bond, a leave (see [`StakeTracker::classify_landed`]) —
/// before this cycle's plan.
async fn classify_landed_op(client: &PortalClient, tracker: &StakeTracker) {
    let nonces = tracker.ops_to_classify();
    if nonces.is_empty() {
        return;
    }
    let listing = client.list_node_ops(&[]).await;
    let now = Instant::now();
    for nonce in nonces {
        tracker.classify_landed_from(nonce, listing.as_ref().map(Vec::as_slice), now);
    }
}

/// Ask the Portal about an in-flight op that has waited long enough to be
/// asked about (see [`StakeTracker::verify_in_flight`]).
async fn verify_overdue_op(client: &PortalClient, tracker: &StakeTracker, now: Instant) {
    let nonces = tracker.ops_to_verify(now);
    if nonces.is_empty() {
        return;
    }
    let listing = client.list_node_ops(&[]).await;
    for nonce in nonces {
        tracker.verify_in_flight_from(nonce, listing.as_ref().map(Vec::as_slice), now);
    }
}

async fn send(client: &PortalClient, tracker: &StakeTracker, op: NodeOp) -> Option<NodeOp> {
    match client.submit_node_op(&op).await {
        Ok(response) => {
            let nonce = response.nonce.unwrap_or_default();
            match op.amount() {
                Some(amount) => info!(nonce, "{}: {amount} KOR queued by the Portal", op.name()),
                None => info!(nonce, "{} queued by the Portal", op.name()),
            }
            tracker.record_sent(op.clone(), nonce, Instant::now());
            Some(op)
        }
        Err(err) => {
            match status_and_code(&err) {
                // Not a refusal of the op: another op of this node holds the
                // nonce, which stays consumed. That op may be this very one,
                // signed by an earlier process and still queued, so the
                // Portal's listing is read before anything is planned again
                // (see `StakeTracker::adopt_pending_ops`) — now, or at the
                // start of each following cycle until it has been read.
                Some((409, _)) => {
                    warn!(
                        "{} lost its nonce to an op the Portal already holds: {err:#}",
                        op.name()
                    );
                    tracker.recheck_pending_ops();
                    adopt_pending_ops(client, tracker).await;
                }
                // Nor these, which say nothing about the op — the same rule
                // as for proofs (`computeproofs::refused_by_portal`): the
                // session expired (401), or the Portal asks to come back
                // later (408, 429). The next cycle signs it again.
                Some((status @ (401 | 408 | 429), _)) => {
                    warn!("{} not taken this cycle ({status}): {err:#}", op.name());
                }
                Some((status, code)) if (400..500).contains(&status) => {
                    let code = code.unwrap_or_else(|| status.to_string());
                    warn!("the Portal refused {} ({code}): {err:#}", op.name());
                    tracker.record_refused(&op, &code, Instant::now());
                }
                // Unreachable, timed out, or a 5xx: whether the Portal kept
                // it is unknown, and the nonce it was signed at is consumed
                // either way. Planning again from an unchanged snapshot would
                // sign the same op at the next nonce, and a Portal that did
                // store the first — it answers only after several Kontor
                // reads, so a timeout after the row is written is routine —
                // would relay both. So it is kept in flight, and the Portal's
                // listing says what became of it (see `verify_in_flight`).
                _ => match err.downcast_ref::<UnsettledOp>() {
                    Some(unsettled) => {
                        let nonce = unsettled.nonce;
                        warn!(
                            nonce,
                            "{} may or may not have reached the Portal; keeping it in flight                              until the Portal's listing says: {err:#}",
                            op.name()
                        );
                        tracker.record_unsettled(op.clone(), nonce, Instant::now());
                    }
                    None => debug!("{} not sent this cycle: {err:#}", op.name()),
                },
            }
            None
        }
    }
}

/// Stake what the faucet just funded, before the daemon's first cycle.
///
/// The same decision a cycle makes, from a fresh registry read, so a node that
/// onboards with an empty bond has its first `add-stake` queued before it
/// looks at any agreement — joins are refused until it lands. Best effort:
/// failure here only defers the top-up to the first cycle.
///
/// The policy bonds nothing before it knows whether the node has exited, so
/// the record an earlier process left of that is read here first (see
/// [`restore_withdrawal_start`]), and what this read learns is recorded
/// before anything is signed.
///
/// # Errors
/// Only if the progress line cannot be written.
pub async fn bootstrap_stake(
    client: &PortalClient,
    database: &DatabaseConnection,
    tracker: &Arc<StakeTracker>,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    // The tracker outlives activations; `client` does not. A node onboarded
    // again in the same process (`/admin` can re-register a running node)
    // gets a client whose nonce counter starts over at Kontor's `next_nonce`,
    // and the daemon it replaces may have been stopped in the middle of a
    // relay request the Portal went on to store. So each activation moves the
    // new counter past what the tracker still waits for, and reads the
    // Portal's listing again before anything is signed.
    tracker.recheck_pending_ops();
    if let Some(nonce) = tracker.highest_tracked_nonce() {
        client.raise_nonce_above(nonce);
    }
    if !tracker.withdrawal_start_restored() {
        if let Err(err) = restore_withdrawal_start(database, tracker, Instant::now()).await {
            warn!(
                "could not read what the database records of this node's exit; nothing is \
                 bonded until the first cycle has read it: {err:#}"
            );
        }
    }

    let entry = match client.resync_from_registry().await {
        Ok(entry) => entry,
        Err(err) => {
            warn!("could not read the stake at startup; the first cycle will retry: {err:#}");
            return Ok(());
        }
    };
    tracker.observe(Some(&entry), Instant::now());
    if let Err(err) = persist_withdrawal_start(database, tracker).await {
        warn!("could not record the state of this node's exit: {err:#}");
    }

    let Some(snapshot) = tracker.snapshot() else {
        if tracker.status()["portal_reports_stake"] == true {
            writeln!(
                writer,
                "⚠ Stake: reported by the Portal but not readable this time; joins wait for \
                 the first cycle's read"
            )?;
        } else {
            writeln!(
                writer,
                "Stake: not reported by this Portal (it predates staking); joining as before"
            )?;
        }
        return Ok(());
    };
    match snapshot.available {
        Some(available) => writeln!(
            writer,
            "✓ Stake: {} KOR bonded, {available} KOR unreserved",
            snapshot.stake
        )?,
        None => writeln!(
            writer,
            "✓ Stake: {} KOR bonded; ⚠ the unreserved part was not reported this time, joins \
             wait for a read that has it",
            snapshot.stake
        )?,
    }
    if snapshot.bond_cleanup_pending == Some(true) {
        writeln!(
            writer,
            "⚠ Bond cleanup pending: the stake was slashed to zero; no joins until it finishes"
        )?;
    }
    if tracker.status()["exited"] == true {
        writeln!(
            writer,
            "⚠ This node has exited: it bonds nothing on its own. Resume staking from /admin \
             to bond again"
        )?;
    }

    if let Some(op) = manage_stake(client, tracker, None).await {
        if let Some(amount) = op.amount() {
            writeln!(writer, "✓ Staking {amount} KOR as collateral")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(stake: Option<&str>, available: Option<&str>) -> RegistryEntry {
        RegistryEntry {
            signer_id: 42,
            x_only_pubkey: Some("ab".into()),
            bls_pubkey: None,
            next_nonce: Some(10),
            kor_balance: Some("1000".into()),
            user_id: None,
            stake: stake.map(Into::into),
            stake_reserved: None,
            stake_available: available.map(Into::into),
            stake_withdrawal_height: None,
            bond_cleanup_pending: Some(false),
            reward_balance: Some("0".into()),
        }
    }

    fn kor(raw: &str) -> Kor {
        Kor::parse(raw).unwrap()
    }

    fn snapshot(balance: &str, stake: &str) -> StakeSnapshot {
        StakeSnapshot {
            kor_balance: Some(kor(balance)),
            stake: kor(stake),
            reserved: Some(Kor::ZERO),
            available: Some(kor(stake)),
            withdrawal_height: None,
            bond_cleanup_pending: Some(false),
            reward_balance: None,
            next_nonce: 10,
        }
    }

    #[test]
    fn an_entry_without_a_stake_is_an_old_portal() {
        assert_eq!(StakeSnapshot::from_entry(&entry(None, None)), None);
        assert_eq!(
            StakeSnapshot::from_entry(&entry(Some("x"), Some("1"))),
            None
        );
        // A stake with nothing saying how much of it is free is still a
        // bond: read, with its unreserved part unknown.
        let partial = StakeSnapshot::from_entry(&entry(Some("10"), None)).unwrap();
        assert_eq!(partial.stake, kor("10"));
        assert_eq!(partial.available, None);
    }

    /// A stake reported without its unreserved part is not an old Portal: on
    /// a first read it used to pass for one, and the cycle joined unmetered.
    /// It closes the cycle's joins instead, and the Portal counts as
    /// reporting stake from then on.
    #[test]
    fn a_stake_without_its_free_part_closes_joins_even_on_the_first_read() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("10"), None), t0);
        assert_eq!(tracker.status()["portal_reports_stake"], true);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown)
        );

        // An unreadable stake says the same: this Portal has the field.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &entry(Some("x"), Some("1")), t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown)
        );
    }

    #[test]
    fn available_falls_back_to_stake_minus_reserved() {
        let mut e = entry(Some("100"), None);
        e.stake_reserved = Some("30.5".into());
        let snapshot = StakeSnapshot::from_entry(&e).unwrap();
        assert_eq!(snapshot.available, Some(kor("69.5")));
        assert_eq!(snapshot.reserved, Some(kor("30.5")));
        assert_eq!(snapshot.kor_balance, Some(kor("1000")));
    }

    #[test]
    fn top_up_stakes_everything_above_the_reserve() {
        let policy = StakePolicy::default();
        assert_eq!(
            top_up_amount(&policy, &snapshot("1000", "0")),
            Some(kor("995"))
        );
        assert_eq!(
            top_up_amount(&policy, &snapshot("6.25", "995")),
            Some(kor("1.25"))
        );
    }

    #[test]
    fn top_up_waits_for_at_least_one_free_kor() {
        let policy = StakePolicy::default();
        assert_eq!(top_up_amount(&policy, &snapshot("5.999", "995")), None);
        assert_eq!(top_up_amount(&policy, &snapshot("3", "995")), None);
        let mut unknown = snapshot("1000", "0");
        unknown.kor_balance = None;
        assert_eq!(top_up_amount(&policy, &unknown), None);
    }

    #[test]
    fn top_up_stops_at_the_target_and_may_close_the_gap_below_one() {
        let policy = StakePolicy {
            stake_target: Some(kor("100")),
            ..StakePolicy::default()
        };
        assert_eq!(
            top_up_amount(&policy, &snapshot("1000", "0")),
            Some(kor("100"))
        );
        assert_eq!(
            top_up_amount(&policy, &snapshot("1000", "99.5")),
            Some(kor("0.5"))
        );
        assert_eq!(top_up_amount(&policy, &snapshot("1000", "100")), None);
        assert_eq!(top_up_amount(&policy, &snapshot("1000", "150")), None);
    }

    #[test]
    fn top_up_never_fights_a_withdrawal_or_a_cleanup() {
        let policy = StakePolicy::default();
        let mut withdrawing = snapshot("1000", "10");
        withdrawing.withdrawal_height = Some(500);
        assert_eq!(top_up_amount(&policy, &withdrawing), None);

        let mut cleaning = snapshot("1000", "0");
        cleaning.bond_cleanup_pending = Some(true);
        assert_eq!(top_up_amount(&policy, &cleaning), None);
    }

    fn observed(tracker: &StakeTracker, e: &RegistryEntry, now: Instant) {
        tracker.observe(Some(e), now);
    }

    /// The failure the in-flight rule exists for: the same top-up sent again
    /// every cycle while the first one waits for a block.
    #[test]
    fn one_op_at_a_time_until_its_nonce_is_consumed() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);

        let op = tracker.plan(t0, None).unwrap();
        assert_eq!(op, NodeOp::AddStake(kor("995")));
        tracker.record_sent(op.clone(), 10, t0);

        // Next cycle: Kontor has not run it yet, nonce 10 still next.
        observed(
            &tracker,
            &entry(Some("0"), Some("0")),
            t0 + Duration::from_secs(30),
        );
        assert_eq!(tracker.plan(t0 + Duration::from_secs(30), None), None);

        // It executed: the nonce moved on, the balance went into the bond.
        let mut landed = entry(Some("995"), Some("995"));
        landed.next_nonce = Some(11);
        landed.kor_balance = Some("5".into());
        observed(&tracker, &landed, t0 + Duration::from_secs(60));
        assert_eq!(tracker.plan(t0 + Duration::from_secs(60), None), None);
    }

    /// An op that consumed its nonce without raising the bond — it failed on
    /// chain, or lost the nonce to another op — is planned again, but only
    /// after the hour a refusal earns: re-planned every cycle, it would burn
    /// gas each block for as long as Kontor keeps refusing it.
    #[test]
    fn a_top_up_that_landed_without_raising_the_bond_waits_an_hour() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let mut consumed = entry(Some("0"), Some("0"));
        consumed.next_nonce = Some(12);
        let soon = t0 + Duration::from_secs(30);
        observed(&tracker, &consumed, soon);
        assert_eq!(tracker.plan(soon, None), None, "not re-signed next cycle");
        let message = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("without raising the bond"), "{message}");

        let later = soon + REFUSED_OP_RETRY_INTERVAL;
        observed(&tracker, &consumed, later);
        assert_eq!(
            tracker.plan(later, None),
            Some(NodeOp::AddStake(kor("995")))
        );

        // One that did raise the bond, even by less than it asked, is not a
        // refusal: the rest is planned again at once.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
        let mut partial = entry(Some("500"), Some("500"));
        partial.next_nonce = Some(11);
        partial.kor_balance = Some("500".into());
        observed(&tracker, &partial, soon);
        assert_eq!(tracker.plan(soon, None), Some(NodeOp::AddStake(kor("495"))));
    }

    fn listed_op(op: &str, nonce: u64, status: &str, error: Option<&str>) -> NodeOpRecord {
        NodeOpRecord {
            op: op.into(),
            amount: None,
            agreement_id: None,
            nonce,
            status: status.into(),
            error: error.map(Into::into),
            txid: None,
        }
    }

    /// Half an hour in, the Portal is asked. While it still lists the op as
    /// queued or submitted — a signer's newer ops wait behind its unconfirmed
    /// batch, so this is routine — the op stays in flight and nothing is
    /// re-signed; the question is asked again every interval, not every
    /// cycle. A listing that cannot be read changes nothing either.
    #[test]
    fn an_op_the_portal_still_holds_stays_in_flight() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let soon = t0 + Duration::from_secs(60);
        assert_eq!(tracker.op_to_verify(soon), None, "too early to ask");
        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        observed(&tracker, &entry(Some("0"), Some("0")), check);
        assert_eq!(tracker.op_to_verify(check), Some(10));

        tracker.verify_in_flight(
            10,
            Ok(vec![
                listed_op("claim_rewards", 11, "queued", None),
                listed_op("add_stake", 10, "submitted", None),
            ]),
            check,
        );
        assert_eq!(tracker.plan(check, None), None, "still in flight");
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);
        assert_eq!(
            tracker.op_to_verify(check + Duration::from_secs(30)),
            None,
            "asked a moment ago"
        );
        let again = check + OP_LANDING_CHECK_INTERVAL;
        assert_eq!(tracker.op_to_verify(again), Some(10));

        tracker.verify_in_flight(10, Err(anyhow::anyhow!("timed out")), again);
        assert_eq!(tracker.plan(again, None), None, "unknown is not dropped");
        assert_eq!(
            tracker.op_to_verify(again + Duration::from_secs(30)),
            Some(10),
            "a listing that could not be read is asked for again next cycle"
        );

        tracker.verify_in_flight(
            10,
            Ok(vec![listed_op("add_stake", 10, "confirmed", None)]),
            again,
        );
        assert_eq!(
            tracker.plan(again, None),
            None,
            "confirmed: the nonce will say so at the next read"
        );
        assert_eq!(
            tracker.op_to_verify(again + Duration::from_secs(1)),
            None,
            "a stale nonce is never asked about"
        );
        tracker.verify_in_flight(99, Ok(vec![]), again);
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);
    }

    /// Dropped for good: the Portal no longer lists the op, or lists it as
    /// failed (with Kontor's reason). The next plan decides again.
    #[test]
    fn an_op_the_portal_dropped_or_failed_is_decided_again() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        tracker.verify_in_flight(
            10,
            Ok(vec![listed_op("claim_rewards", 9, "confirmed", None)]),
            check,
        );
        assert_eq!(
            tracker.plan(check, None),
            Some(NodeOp::AddStake(kor("995")))
        );
        let message = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("dropped"), "{message}");

        // Another op of this node at the nonce: ours was never stored.
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, check);
        tracker.verify_in_flight(
            10,
            Ok(vec![listed_op("claim_rewards", 10, "queued", None)]),
            check,
        );
        assert_eq!(
            tracker.plan(check, None),
            Some(NodeOp::AddStake(kor("995")))
        );

        tracker.record_sent(NodeOp::AddStake(kor("995")), 11, check);
        tracker.verify_in_flight(
            11,
            Ok(vec![listed_op(
                "add_stake",
                11,
                "failed",
                Some("nonce already passed: nonce 11 is below the signer's next nonce 12"),
            )]),
            check + OP_LANDING_CHECK_INTERVAL,
        );
        assert_eq!(tracker.status()["in_flight"], Value::Null);
        let message = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("failed"), "{message}");
    }

    /// A Portal that cannot say what it holds may hold the op. However long
    /// its listing stays unreadable, the op stays in flight and nothing is
    /// signed again — the op used to be given up for lost at the hard
    /// timeout, and the same top-up then executed twice. The question is
    /// asked on every cycle, and the Portal's word, when it comes, decides.
    #[test]
    fn an_op_the_portal_cannot_be_asked_about_is_never_given_up_on_silence() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let mut at = t0 + OP_LANDING_CHECK_INTERVAL;
        while at < t0 + OP_LANDING_HARD_TIMEOUT * 2 {
            observed(&tracker, &entry(Some("0"), Some("0")), at);
            assert_eq!(tracker.op_to_verify(at), Some(10), "asked every cycle");
            tracker.verify_in_flight(10, Err(anyhow::anyhow!("503")), at);
            assert_eq!(tracker.plan(at, None), None, "at +{:?}", at - t0);
            at += Duration::from_secs(600);
        }

        // The listing reads again, and no longer shows the op: dropped.
        tracker.verify_in_flight(10, Ok(vec![]), at);
        assert_eq!(tracker.plan(at, None), Some(NodeOp::AddStake(kor("995"))));
    }

    /// Through the client: the Portal's listing is what decides. Listed as
    /// queued, the op stays in flight and no new one is signed; gone from the
    /// listing, the next plan goes out.
    #[tokio::test]
    async fn the_portal_s_listing_decides_whether_an_overdue_op_is_dropped() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let page = |ops: Value| json!({"offset": 0, "limit": 100, "total": 1, "node_id": "NODE-test", "ops": ops});
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(json!([{
                "id": "a", "node_id": "NODE-test", "op": "add_stake", "amount": "995",
                "agreement_id": null, "nonce": 10, "status": "queued",
                "transaction_id": null, "error": null, "txid": null,
                "created_at": "2026-11-03T10:00:00+00:00",
                "updated_at": "2026-11-03T10:00:00+00:00"
            }]))))
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = PortalClient::try_with_auth(
            mock_server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            10,
        )
        .unwrap();
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        verify_overdue_op(&client, &tracker, check).await;
        assert_eq!(tracker.plan(check, None), None, "the Portal still has it");

        mock_server.reset().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(json!([]))))
            .expect(1)
            .mount(&mock_server)
            .await;
        let again = check + OP_LANDING_CHECK_INTERVAL;
        verify_overdue_op(&client, &tracker, again).await;
        assert_eq!(
            tracker.plan(again, None),
            Some(NodeOp::AddStake(kor("995")))
        );
    }

    #[test]
    fn auto_stake_off_signs_nothing_on_its_own() {
        let tracker = StakeTracker::new(StakePolicy {
            auto_stake: false,
            ..StakePolicy::default()
        });
        let t0 = Instant::now();
        let mut e = entry(Some("0"), Some("0"));
        e.reward_balance = Some("50".into());
        observed(&tracker, &e, t0);
        assert_eq!(tracker.plan(t0, None), None);

        // An operator request is still carried out.
        tracker.request(NodeOp::BeginUnstake).unwrap();
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::BeginUnstake));
    }

    #[test]
    fn rewards_are_claimed_past_the_threshold_at_most_once_an_hour() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut e = entry(Some("995"), Some("995"));
        e.kor_balance = Some("5".into());
        e.reward_balance = Some("0.99".into());
        observed(&tracker, &e, t0);
        assert_eq!(tracker.plan(t0, None), None, "below the threshold");

        e.reward_balance = Some("1".into());
        observed(&tracker, &e, t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::ClaimRewards));
        tracker.record_sent(NodeOp::ClaimRewards, 10, t0);

        // Landed, but the claim is rate-limited even if more is claimable.
        e.next_nonce = Some(11);
        e.reward_balance = Some("2".into());
        let soon = t0 + Duration::from_secs(60);
        observed(&tracker, &e, soon);
        assert_eq!(tracker.plan(soon, None), None);

        let later = t0 + CLAIM_INTERVAL;
        observed(&tracker, &e, later);
        assert_eq!(tracker.plan(later, None), Some(NodeOp::ClaimRewards));
    }

    #[test]
    fn a_top_up_takes_precedence_over_a_claim() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut e = entry(Some("0"), Some("0"));
        e.reward_balance = Some("50".into());
        observed(&tracker, &e, t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));
    }

    #[test]
    fn only_unstake_and_withdraw_can_be_requested_and_one_at_a_time() {
        let tracker = StakeTracker::new(StakePolicy::default());
        assert!(tracker.request(NodeOp::ClaimRewards).is_err());
        assert!(tracker.request(NodeOp::AddStake(Kor::ONE)).is_err());
        tracker.request(NodeOp::WithdrawStake).unwrap();
        assert!(tracker.request(NodeOp::BeginUnstake).is_err());

        // Sent: the request is done, another may follow.
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "10"), t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::WithdrawStake));
        tracker.record_sent(NodeOp::WithdrawStake, 10, t0);
        assert!(tracker.request(NodeOp::BeginUnstake).is_ok());
    }

    /// A request the bond has overtaken is dropped at the next read, not
    /// signed: a withdrawal when none is pending any more, an unstake once
    /// one is.
    #[test]
    fn a_request_the_bond_has_overtaken_is_dropped() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        tracker.request(NodeOp::WithdrawStake).unwrap();
        let mut bonded = entry(Some("10"), Some("10"));
        bonded.kor_balance = Some("5".into());
        observed(&tracker, &bonded, t0);
        assert_eq!(tracker.status()["operator_request"], Value::Null);
        assert_eq!(tracker.plan(t0, None), None);

        let tracker = StakeTracker::new(StakePolicy::default());
        tracker.request(NodeOp::BeginUnstake).unwrap();
        observed(&tracker, &exiting_entry(10, "10"), t0);
        assert_eq!(tracker.status()["operator_request"], Value::Null);
    }

    #[test]
    fn an_old_portal_gates_nothing_and_a_new_one_never_joins_blind() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();

        observed(&tracker, &entry(None, None), t0);
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, None),
            JoinDecision::Join { collateral: None },
            "old Portal: as before"
        );

        observed(&tracker, &entry(Some("10"), Some("10")), t0);
        tracker.observe(None, t0); // the read failed this cycle
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown)
        );
    }

    #[test]
    fn the_budget_commits_collateral_within_a_cycle() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("50")), t0);

        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(Some("30"))),
            JoinDecision::Join {
                collateral: Some(kor("30"))
            }
        );
        assert_eq!(
            budget.decide(false, Some(Some("30"))),
            JoinDecision::Skip(SkipReason::InsufficientCollateral),
            "only 20 left"
        );
        assert_eq!(
            budget.decide(false, Some(Some("20"))),
            JoinDecision::Join {
                collateral: Some(kor("20"))
            },
            "exactly what is left is enough: Kontor refuses only reserved > stake"
        );
        assert_eq!(
            budget.decide(false, Some(None)),
            JoinDecision::Skip(SkipReason::InsufficientCollateral),
            "nothing left: an unknown collateral is not a free pass"
        );
        assert_eq!(
            budget.decide(false, None),
            JoinDecision::Skip(SkipReason::NotListed)
        );
        assert_eq!(
            budget.decide(false, Some(Some("0"))),
            JoinDecision::Skip(SkipReason::NoCollateralRequirement)
        );
        assert_eq!(
            budget.decide(true, Some(Some("1000"))),
            JoinDecision::Join { collateral: None },
            "an existing membership is never held back"
        );

        budget.refund(Some(kor("20")));
        assert_eq!(
            budget.decide(false, Some(Some("20"))),
            JoinDecision::Join {
                collateral: Some(kor("20"))
            }
        );
        let summary = budget.summary().unwrap();
        assert!(
            summary.contains("2 × insufficient unreserved stake"),
            "{summary}"
        );
    }

    /// Joins sent in an earlier cycle hold their collateral until they
    /// execute, so a second cycle before the next block does not spend it
    /// again.
    #[test]
    fn pending_joins_hold_collateral_across_cycles_until_they_land() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("50")), t0);
        tracker.record_join("AGR-1", kor("40"), 10, t0);

        observed(&tracker, &entry(Some("100"), Some("50")), t0);
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(Some("20"))),
            JoinDecision::Skip(SkipReason::InsufficientCollateral)
        );

        // Executed: the reservation now shows in stake_available instead.
        let mut landed = entry(Some("100"), Some("10"));
        landed.next_nonce = Some(11);
        observed(&tracker, &landed, t0);
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(Some("10"))),
            JoinDecision::Join {
                collateral: Some(kor("10"))
            }
        );
    }

    /// A join's collateral is released when its row says the join will never
    /// execute — this node's row in the listing is `invalid`, or the
    /// agreement is no longer `ready`/`pending` — and otherwise held up to the
    /// hard timeout, not the half hour an op is first asked about.
    #[tokio::test]
    async fn pending_joins_are_released_by_their_rows_not_by_a_clock() {
        use crate::clients::portal::{Agreement, AgreementNode};
        use crate::testutils::{setup_in_memory_db, AgreementFixture};
        use sea_orm::ActiveModelTrait;

        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        for id in ["AGR-invalid", "AGR-live", "AGR-failed", "AGR-still"] {
            tracker.record_join(id, kor("10"), 10, t0);
        }

        let listed = |id: &str, status: &str| -> Agreement {
            let mut agreement: Agreement = serde_json::from_value(json!({
                "agreement_id": id,
                "user_id": "user_1",
                "file_id": format!("F-{id}"),
                "filename": "test.bin",
                "mime_type": "application/octet-stream",
                "original_size": 123,
                "nodes": [],
                "transaction_id": null,
                "status": "ready",
                "created_at": "2024-01-01T00:00:00Z"
            }))
            .unwrap();
            agreement.nodes = vec![AgreementNode {
                node_id: "NODE-me".into(),
                status: status.into(),
            }];
            agreement
        };
        let listing: ReadyListing = [
            listed("AGR-invalid", "invalid"),
            listed("AGR-live", "valid"),
        ]
        .into_iter()
        .map(|agreement| (agreement.agreement_id.clone(), agreement))
        .collect();

        let db = setup_in_memory_db().await;
        for (id, status) in [("AGR-failed", "failed"), ("AGR-still", "ready")] {
            AgreementFixture {
                status: status.into(),
                nodes: json!([{"node_id": "NODE-me", "status": "valid"}]),
                ..AgreementFixture::new(id, format!("F-{id}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }

        settle_pending_joins(&db, &tracker, "NODE-me", &listing)
            .await
            .unwrap();
        let mut held = tracker.pending_join_agreements();
        held.sort();
        assert_eq!(held, vec!["AGR-live", "AGR-still"]);

        // No clock releases what the Portal may still hold: a day later the
        // two are still committed.
        let day = t0 + Duration::from_secs(24 * 60 * 60);
        observed(&tracker, &entry(Some("100"), Some("100")), day);
        assert_eq!(tracker.pending_join_agreements().len(), 2, "still held");

        // A listing that carries the agreement with no row of this node holds
        // no join of it.
        let mut rowless = listed("AGR-live", "valid");
        rowless.nodes.clear();
        let listing: ReadyListing = [(rowless.agreement_id.clone(), rowless)]
            .into_iter()
            .collect();
        settle_pending_joins(&db, &tracker, "NODE-me", &listing)
            .await
            .unwrap();
        assert_eq!(tracker.pending_join_agreements(), vec!["AGR-still"]);
    }

    #[test]
    fn cleanup_withdrawal_no_stake_and_refusals_close_the_budget() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();

        let mut cleaning = entry(Some("0"), Some("0"));
        cleaning.bond_cleanup_pending = Some(true);
        observed(&tracker, &cleaning, t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::BondCleanupPending)
        );

        let mut withdrawing = entry(Some("10"), Some("10"));
        withdrawing.stake_withdrawal_height = Some(900);
        observed(&tracker, &withdrawing, t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::WithdrawalRequested)
        );

        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::NoStake)
        );

        observed(&tracker, &entry(Some("10"), Some("10")), t0);
        tracker.pause_joins("INSUFFICIENT_COLLATERAL", t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::RecentlyRefused(
                "INSUFFICIENT_COLLATERAL".into()
            ))
        );
        let after = t0 + JOIN_REFUSAL_COOLDOWN;
        assert_eq!(
            tracker.join_budget(after).decide(false, Some(Some("1"))),
            JoinDecision::Join {
                collateral: Some(kor("1"))
            },
            "the pause expires"
        );
    }

    #[test]
    fn a_slash_and_a_cleanup_are_recorded_for_the_operator() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("70")), t0);
        observed(&tracker, &entry(Some("40"), Some("10")), t0);
        let status = tracker.status();
        let message = status["last_event"]["message"].as_str().unwrap();
        assert!(
            message.contains("slashed") && message.contains("60"),
            "{message}"
        );

        let mut cleaning = entry(Some("0"), Some("0"));
        cleaning.bond_cleanup_pending = Some(true);
        observed(&tracker, &cleaning, t0);
        let status = tracker.status();
        assert_eq!(status["last_event"]["message"], "bond cleanup pending");
        assert_eq!(status["bond_cleanup_pending"], true);
        assert_eq!(status["stake"], "0");
    }

    /// A withdrawal empties the bond on purpose; that is not a slash — not
    /// even when its op is no longer tracked in flight (one requested from
    /// /admin and given up as lost, say, or sent by an earlier process). A
    /// slash while the withdrawal is pending still is one: it does not take
    /// the bond to zero.
    #[test]
    fn a_withdrawal_is_not_reported_as_a_slash() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut requested = entry(Some("100"), Some("100"));
        requested.stake_withdrawal_height = Some(5);
        observed(&tracker, &requested, t0);
        tracker.record_sent(NodeOp::WithdrawStake, 10, t0);

        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(11);
        observed(&tracker, &withdrawn, t0);
        let message = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!message.contains("slashed"), "{message}");

        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &requested, t0);
        observed(&tracker, &withdrawn, t0);
        assert_eq!(
            tracker.status()["last_event"]["message"],
            "withdrawal completed",
            "no op in flight, same withdrawal"
        );

        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &requested, t0);
        let mut slashed = entry(Some("40"), Some("40"));
        slashed.stake_withdrawal_height = Some(5);
        observed(&tracker, &slashed, t0);
        let message = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("slashed"), "{message}");
    }

    #[test]
    fn status_renders_amounts_as_strings() {
        let tracker = StakeTracker::new(StakePolicy {
            stake_target: Some(kor("250.5")),
            ..StakePolicy::default()
        });
        let status = tracker.status();
        assert_eq!(status["reported"], false);
        assert_eq!(status["policy"]["auto_stake"], true);
        assert_eq!(status["policy"]["gas_reserve"], "5");
        assert_eq!(status["policy"]["stake_target"], "250.5");
        assert_eq!(status["policy"]["claim_threshold"], "1");

        let t0 = Instant::now();
        let mut e = entry(Some("995"), Some("965"));
        e.stake_reserved = Some("30".into());
        observed(&tracker, &e, t0);
        tracker.record_sent(NodeOp::AddStake(kor("0.25")), 10, t0);
        let status = tracker.status();
        assert_eq!(status["stake"], "995");
        assert_eq!(status["reserved"], "30");
        assert_eq!(status["available"], "965");
        assert_eq!(status["in_flight"]["op"], "add_stake");
        assert_eq!(status["in_flight"]["amount"], "0.25");
        assert_eq!(status["in_flight"]["nonce"], 10);
    }

    /// The usual case: the Portal joins in the batch that creates the
    /// agreement, so the collateral is not known yet. Joined anyway while the
    /// free stake covers the estimate, charged the estimate, at most a few per
    /// cycle.
    #[test]
    fn unknown_collateral_is_budgeted_at_the_estimate_and_capped_per_cycle() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("1000"), Some("1000")), t0);

        let mut budget = tracker.join_budget(t0);
        for _ in 0..MAX_UNKNOWN_COLLATERAL_JOINS_PER_CYCLE {
            assert_eq!(
                budget.decide(false, Some(None)),
                JoinDecision::Join {
                    collateral: Some(kor("10"))
                }
            );
        }
        assert_eq!(
            budget.decide(false, Some(None)),
            JoinDecision::Skip(SkipReason::CollateralUnknown),
            "the cycle's guesses are used up"
        );
        assert_eq!(
            budget.decide(false, Some(Some("500"))),
            JoinDecision::Join {
                collateral: Some(kor("500"))
            },
            "a known collateral is not limited by the guess cap"
        );
    }

    /// What is left must cover the estimate. A bond with less used to be
    /// charged "the rest" and download and join anyway — with 0.01 KOR free,
    /// a join Kontor was all but certain to refuse.
    #[test]
    fn an_estimate_above_what_is_left_is_not_joined() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("4"), Some("4")), t0);
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(None)),
            JoinDecision::Skip(SkipReason::InsufficientCollateral)
        );

        observed(&tracker, &entry(Some("15"), Some("15")), t0);
        let mut budget = tracker.join_budget(t0);
        assert_eq!(
            budget.decide(false, Some(None)),
            JoinDecision::Join {
                collateral: Some(kor("10"))
            },
            "15 covers one estimate of 10"
        );
        assert_eq!(
            budget.decide(false, Some(None)),
            JoinDecision::Skip(SkipReason::InsufficientCollateral),
            "the 5 left does not cover a second"
        );
        assert_eq!(
            budget.decide(false, Some(Some("5"))),
            JoinDecision::Join {
                collateral: Some(kor("5"))
            },
            "a known collateral still uses what is left"
        );
    }

    /// The estimate follows what agreements have actually cost lately, never
    /// below the configured floor, and forgets after a day.
    #[test]
    fn the_estimate_rises_to_the_largest_collateral_seen_recently() {
        let tracker = StakeTracker::new(StakePolicy {
            unknown_collateral_estimate: kor("2"),
            ..StakePolicy::default()
        });
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("1000"), Some("1000")), t0);
        tracker.note_collateral(Some("1.5"), t0);
        tracker.note_collateral(Some("37.25"), t0);
        tracker.note_collateral(None, t0);
        tracker.note_collateral(Some("garbage"), t0);

        let charged = |at| match tracker.join_budget(at).decide(false, Some(None)) {
            JoinDecision::Join { collateral } => collateral.unwrap(),
            other => panic!("{other:?}"),
        };
        assert_eq!(charged(t0), kor("37.25"));
        assert_eq!(charged(t0 + COLLATERAL_MEMORY), kor("2"), "forgotten");
    }

    /// From the moment the operator asks to unstake, nothing new is joined —
    /// not only once the unstake has executed.
    #[test]
    fn an_unstake_request_stops_joins_at_once() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        tracker.request(NodeOp::BeginUnstake).unwrap();
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::Leaving)
        );

        tracker.record_sent(NodeOp::BeginUnstake, 10, t0);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(None)),
            JoinDecision::Skip(SkipReason::Leaving),
            "still while it is in flight"
        );
    }

    fn exiting_entry(next_nonce: u64, stake: &str) -> RegistryEntry {
        let mut e = entry(Some(stake), Some("0"));
        e.next_nonce = Some(next_nonce);
        e.kor_balance = Some("5".into());
        e.stake_withdrawal_height = Some(5000);
        e
    }

    /// The Portal's listing of a `leave_agreement` op at `nonce`.
    fn leave_record(nonce: u64, status: &str, error: Option<&str>) -> NodeOpRecord {
        NodeOpRecord {
            op: "leave_agreement".into(),
            amount: None,
            agreement_id: None,
            nonce,
            status: status.into(),
            error: error.map(Into::into),
            txid: None,
        }
    }

    /// The leave at `nonce` has landed, and the Portal confirms it.
    fn leave_confirmed(tracker: &StakeTracker, nonce: u64, now: Instant) {
        assert!(tracker.ops_to_classify().contains(&nonce), "asked about");
        tracker.classify_landed(nonce, Ok(vec![leave_record(nonce, "confirmed", None)]), now);
    }

    /// The exit: leave each membership one op at a time, skipping one whose
    /// challenge is still open, then withdraw once nothing is held and the
    /// delay has run — and never re-bond what came back.
    #[test]
    fn the_exit_leaves_each_membership_then_withdraws() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert!(tracker.exiting());

        let mut exit = ExitInputs {
            memberships: vec!["AGR-a".into(), "AGR-b".into()],
            deferred: vec!["AGR-a".into()],
            unresolved_challenges: 1,
        };
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-b".into())),
            "AGR-a has an open challenge: it waits"
        );
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-b".into()), 10, t0);
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "one op at a time");

        observed(&tracker, &exiting_entry(11, "100"), t0);
        leave_confirmed(&tracker, 10, t0);
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "AGR-a still deferred");

        exit.deferred.clear();
        exit.unresolved_challenges = 0;
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into()))
        );
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 11, t0);
        observed(&tracker, &exiting_entry(12, "100"), t0);
        leave_confirmed(&tracker, 11, t0);

        // Nothing held; but the delay has not run by the node's reckoning.
        assert_eq!(tracker.plan(t0, Some(&exit)), None);
        let status = tracker.status();
        assert_eq!(status["exit"]["memberships_left"], json!([]));
        assert_eq!(status["exit"]["left"], 2);

        let later = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
        assert_eq!(
            tracker.plan(later, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );
        tracker.record_sent(NodeOp::WithdrawStake, 12, later);

        // Withdrawn: the bond is back in the balance, and stays there.
        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(13);
        withdrawn.kor_balance = Some("105".into());
        observed(&tracker, &withdrawn, later);
        assert!(!tracker.exiting());
        assert_eq!(
            tracker.plan(later, None),
            None,
            "no re-bonding after an exit"
        );
        assert_eq!(tracker.status()["exited"], true);
    }

    /// The delay is counted from when the withdrawal height was first seen,
    /// which a restart must not move: a start an earlier process recorded is
    /// honoured, and the hours already behind are not waited for again.
    #[test]
    fn the_withdrawal_delay_is_counted_from_the_recorded_start() {
        let exit = ExitInputs::default();
        let hour = Duration::from_secs(60 * 60);
        let delay = ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;

        // An earlier process saw the height all but an hour ago.
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let started_at = Utc::now() - chrono::Duration::from_std(delay - hour).unwrap();
        tracker.restore_withdrawal_start(Some(started_at), t0);
        assert!(tracker.withdrawal_start_restored());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "an hour still to go");
        assert_eq!(
            tracker.plan(t0 + hour, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );
        let estimated = tracker.status()["exit"]["withdraw_estimated_from"]
            .as_str()
            .unwrap()
            .to_string();
        let estimated = DateTime::parse_from_rfc3339(&estimated).unwrap();
        assert!(
            (estimated.with_timezone(&Utc)
                - (started_at + chrono::Duration::from_std(delay).unwrap()))
            .num_seconds()
            .abs()
                < 2,
            "{estimated}"
        );

        // No record: the delay runs from this process's first sight of it.
        let tracker = StakeTracker::new(StakePolicy::default());
        tracker.restore_withdrawal_start(None, t0);
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert_eq!(
            tracker.plan(t0 + delay - Duration::from_secs(1), Some(&exit)),
            None
        );
        assert_eq!(
            tracker.plan(t0 + delay, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );

        // Onboarding reads the registry before the daemon reads the database:
        // an earlier record overrides the start this process just witnessed,
        // a later one never does.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        tracker.restore_withdrawal_start(Some(Utc::now() + chrono::Duration::hours(1)), t0);
        assert_eq!(tracker.plan(t0 + delay - hour, Some(&exit)), None);
        tracker.restore_withdrawal_start(
            Some(Utc::now() - chrono::Duration::from_std(delay).unwrap()),
            t0,
        );
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::WithdrawStake),
            "the delay had run out before this process started"
        );
    }

    /// A record that could not be read is not written over. The daemon reads
    /// the record before it acts on its own reads, but a read that fails
    /// leaves the tracker counting from this process's first sight of the
    /// height — and writing that start would replace the earlier one, which
    /// is exactly what the record exists to keep. Nothing is written until
    /// the read has gone through.
    #[test]
    fn nothing_is_written_until_the_recorded_start_has_been_read() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert!(!tracker.withdrawal_start_restored());
        assert_eq!(
            tracker.withdrawal_start_to_persist(),
            None,
            "the record has not been read; it may hold an earlier start"
        );

        // Read at last, and earlier than this process's start: it stands,
        // and there is nothing to write.
        let started_at = Utc::now() - chrono::Duration::hours(48);
        tracker.restore_withdrawal_start(Some(started_at), t0);
        assert_eq!(tracker.withdrawal_start_to_persist(), None);
        assert_eq!(tracker.plan(t0, Some(&ExitInputs::default())), None);
        let estimated = tracker.status()["exit"]["withdraw_estimated_from"]
            .as_str()
            .unwrap()
            .to_string();
        let estimated = DateTime::parse_from_rfc3339(&estimated).unwrap();
        let delay = chrono::Duration::from_std(withdrawal_delay()).unwrap();
        assert_eq!(estimated.with_timezone(&Utc), started_at + delay);

        // No record after all: this process's start is the one to write.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert_eq!(tracker.withdrawal_start_to_persist(), None);
        tracker.restore_withdrawal_start(None, t0);
        assert!(matches!(
            tracker.withdrawal_start_to_persist(),
            Some(Some(_))
        ));
    }

    /// The start is written when first seen, left alone while nothing changed,
    /// read back by the next process, and cleared once the withdrawal is over.
    #[tokio::test]
    async fn the_withdrawal_start_is_kept_in_the_database_across_restarts() {
        use crate::entities::prelude::NodeState;
        use crate::testutils::setup_in_memory_db;
        use sea_orm::EntityTrait;

        let db = setup_in_memory_db().await;
        let t0 = Instant::now();
        let first = StakeTracker::new(StakePolicy::default());
        restore_withdrawal_start(&db, &first, t0).await.unwrap();
        assert!(first.withdrawal_start_restored());
        assert_eq!(
            first.withdrawal_start_to_persist(),
            None,
            "nothing to write yet"
        );

        observed(&first, &exiting_entry(10, "100"), t0);
        assert!(matches!(first.withdrawal_start_to_persist(), Some(Some(_))));
        persist_withdrawal_start(&db, &first).await.unwrap();
        let row = NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
            .one(&db)
            .await
            .unwrap()
            .expect("recorded");
        DateTime::parse_from_rfc3339(&row.value).expect("an RFC 3339 timestamp");
        assert_eq!(first.withdrawal_start_to_persist(), None, "already written");
        persist_withdrawal_start(&db, &first).await.unwrap();

        // The next process picks it up and counts from the same moment.
        let second = StakeTracker::new(StakePolicy::default());
        let t1 = t0 + Duration::from_secs(3600);
        restore_withdrawal_start(&db, &second, t1).await.unwrap();
        observed(&second, &exiting_entry(10, "100"), t1);
        assert_eq!(
            second.status()["exit"]["withdraw_estimated_from"],
            first.status()["exit"]["withdraw_estimated_from"]
        );
        assert_eq!(
            second.withdrawal_start_to_persist(),
            None,
            "the record is the one it restored"
        );
        // Withdrawn: no delay to count, and no record to mislead a later exit.
        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(11);
        observed(&second, &withdrawn, t1);
        assert_eq!(second.withdrawal_start_to_persist(), Some(None));
        persist_withdrawal_start(&db, &second).await.unwrap();
        assert!(NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
            .one(&db)
            .await
            .unwrap()
            .is_none());
        assert_eq!(second.withdrawal_start_to_persist(), None);
    }

    /// An exit was under way when the last process stopped — the database
    /// holds the start of its withdrawal delay — and the first read of this
    /// one shows neither a bond nor a withdrawal pending: the exit ended while
    /// the node was not running. That used to be taken for a stale row, which
    /// was cleared, and the restarted node bonded the returned balance again:
    /// two more weeks before it could be withdrawn. The node is out, stays
    /// out, and says so in its database.
    #[tokio::test]
    async fn an_exit_that_ended_while_the_node_was_down_is_not_bonded_again() {
        use crate::entities::node_state;
        use crate::entities::prelude::NodeState;
        use crate::testutils::setup_in_memory_db;
        use sea_orm::{ActiveValue, EntityTrait};

        let db = setup_in_memory_db().await;
        let started_at = (Utc::now() - chrono::Duration::days(20)).to_rfc3339();
        NodeState::insert(node_state::ActiveModel {
            key: ActiveValue::Set(WITHDRAWAL_STARTED_AT.to_string()),
            value: ActiveValue::Set(started_at),
            updated_at: ActiveValue::Set(Utc::now().fixed_offset()),
        })
        .exec(&db)
        .await
        .unwrap();

        // Restored before any read of this process, as startup does it.
        let tracker = StakeTracker::default();
        let t0 = Instant::now();
        restore_withdrawal_start(&db, &tracker, t0).await.unwrap();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(tracker.status()["exited"], true);
        assert_eq!(tracker.plan(t0, None), None, "1000 KOR back, none bonded");
        persist_withdrawal_start(&db, &tracker).await.unwrap();
        assert!(
            NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
                .one(&db)
                .await
                .unwrap()
                .is_none(),
            "the delay is over"
        );
        assert!(
            NodeState::find_by_id(EXITED_AT)
                .one(&db)
                .await
                .unwrap()
                .is_some(),
            "and the exit is on record"
        );

        // Restored after a read, as when the registry was read first.
        let later = StakeTracker::new(StakePolicy::default());
        observed(&later, &entry(Some("0"), Some("0")), t0);
        later.restore_withdrawal_start(Some(Utc::now() - chrono::Duration::days(20)), t0);
        assert_eq!(later.status()["exited"], true);
        assert_eq!(later.withdrawal_start_to_persist(), Some(None));
        assert_eq!(later.plan(t0, None), None);
    }

    /// The start of a withdrawal delay recorded for a node that has a stake
    /// bonded and no withdrawal pending belongs to an exit long over: the
    /// row is cleared, and the policy goes on as configured.
    #[test]
    fn a_withdrawal_record_older_than_the_stake_is_stale() {
        let t0 = Instant::now();
        let mut bonded = entry(Some("100"), Some("100"));
        bonded.kor_balance = Some("105".into());
        let old = Some(Utc::now() - chrono::Duration::days(20));

        let tracker = StakeTracker::new(StakePolicy::default());
        tracker.restore_withdrawal_start(old, t0);
        observed(&tracker, &bonded, t0);
        assert_eq!(tracker.status()["exited"], false);
        assert_eq!(tracker.withdrawal_start_to_persist(), Some(None));
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("100"))));

        let later = StakeTracker::new(StakePolicy::default());
        observed(&later, &bonded, t0);
        later.restore_withdrawal_start(old, t0);
        assert_eq!(later.status()["exited"], false);
        assert_eq!(later.withdrawal_start_to_persist(), Some(None));
    }

    /// A record nothing can read is deleted and reported, not tripped over
    /// every cycle.
    #[tokio::test]
    async fn an_unreadable_withdrawal_record_is_deleted() {
        use crate::entities::node_state;
        use crate::entities::prelude::NodeState;
        use crate::testutils::setup_in_memory_db;
        use sea_orm::{ActiveValue, EntityTrait};

        let db = setup_in_memory_db().await;
        NodeState::insert(node_state::ActiveModel {
            key: ActiveValue::Set(WITHDRAWAL_STARTED_AT.to_string()),
            value: ActiveValue::Set("yesterday-ish".to_string()),
            updated_at: ActiveValue::Set(Utc::now().fixed_offset()),
        })
        .exec(&db)
        .await
        .unwrap();

        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        restore_withdrawal_start(&db, &tracker, t0).await.unwrap();
        assert!(tracker.withdrawal_start_restored());
        assert!(NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
            .one(&db)
            .await
            .unwrap()
            .is_none());
        // This process counts from its own first sight of the height.
        observed(&tracker, &exiting_entry(10, "100"), t0);
        assert!(matches!(
            tracker.withdrawal_start_to_persist(),
            Some(Some(_))
        ));
    }

    /// A withdrawal that executed without returning the bond means a leave
    /// did not take: they are all sent again, and the withdrawal retried later.
    #[test]
    fn a_withdrawal_that_did_not_take_resends_the_leaves() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
        observed(&tracker, &exiting_entry(11, "100"), t0);
        leave_confirmed(&tracker, 10, t0);

        let later = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
        assert_eq!(
            tracker.plan(later, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );
        tracker.record_sent(NodeOp::WithdrawStake, 11, later);
        tracker.memberships_refreshed();
        observed(&tracker, &exiting_entry(12, "100"), later);

        assert!(
            tracker.memberships_need_refresh(),
            "the rows are re-read before the leaves are resent"
        );
        assert_eq!(
            tracker.plan(later, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into()))
        );
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 12, later);
        observed(&tracker, &exiting_entry(13, "100"), later);
        leave_confirmed(&tracker, 12, later);
        assert_eq!(tracker.plan(later, Some(&exit)), None, "retry interval");
        assert_eq!(
            tracker.plan(later + WITHDRAW_RETRY_INTERVAL, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );
    }

    /// A withdrawal Kontor refused for an obligation the node's rows did not
    /// show — a failed challenge whose penalty it had still to settle — is
    /// retried within the hour, not six: the rows are re-read and the
    /// challenges synced every cycle. One made too early keeps the long wait,
    /// and one the Portal retired unexecuted is tried again at once.
    #[test]
    fn a_withdrawal_kontor_refused_for_an_obligation_is_retried_sooner() {
        let withdraw_record = |error: &str| NodeOpRecord {
            op: "withdraw_stake".into(),
            amount: None,
            agreement_id: None,
            nonce: 11,
            status: "failed".into(),
            error: Some(error.into()),
            txid: Some("ff".into()),
        };
        for (error, retried_after) in [
            (
                "ContractErr: err(message(\"unresolved storage obligations\"))",
                Some(WITHDRAW_OBLIGATION_RETRY_INTERVAL),
            ),
            (
                "ContractErr: err(message(\"withdrawal delay has not elapsed\"))",
                Some(WITHDRAW_RETRY_INTERVAL),
            ),
            ("no receipt recorded by Kontor (op never executed)", None),
        ] {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &exiting_entry(10, "100"), t0);
            let exit = ExitInputs {
                memberships: vec!["AGR-a".into()],
                ..ExitInputs::default()
            };
            tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
            observed(&tracker, &exiting_entry(11, "100"), t0);
            leave_confirmed(&tracker, 10, t0);

            let due = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
            assert_eq!(tracker.plan(due, Some(&exit)), Some(NodeOp::WithdrawStake));
            tracker.record_sent(NodeOp::WithdrawStake, 11, due);
            tracker.memberships_refreshed();
            observed(&tracker, &exiting_entry(12, "100"), due);
            assert!(tracker.memberships_need_refresh());
            assert_eq!(tracker.op_to_classify(), Some(11), "asked how it ended");
            tracker.classify_landed(11, Ok(vec![withdraw_record(error)]), due);

            // The leave is resent and confirmed; then the withdrawal waits.
            assert_eq!(
                tracker.plan(due, Some(&exit)),
                Some(NodeOp::LeaveAgreement("AGR-a".into())),
                "{error}"
            );
            tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 12, due);
            observed(&tracker, &exiting_entry(13, "100"), due);
            leave_confirmed(&tracker, 12, due);
            match retried_after {
                Some(interval) => {
                    assert_eq!(
                        tracker.plan(due + interval / 2, Some(&exit)),
                        None,
                        "{error}: still waiting"
                    );
                    assert_eq!(
                        tracker.plan(due + interval, Some(&exit)),
                        Some(NodeOp::WithdrawStake),
                        "{error}"
                    );
                }
                None => assert_eq!(
                    tracker.plan(due, Some(&exit)),
                    Some(NodeOp::WithdrawStake),
                    "{error}: never ran, tried again at once"
                ),
            }
        }
    }

    /// A refused `add-stake` used to be signed again every cycle. It now waits
    /// [`REFUSED_OP_RETRY_INTERVAL`]; a refused leave holds back that agreement
    /// only, and the exit goes on with the next one.
    #[test]
    fn refused_stake_and_leave_ops_back_off() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        let op = tracker.plan(t0, None).unwrap();
        assert_eq!(op, NodeOp::AddStake(kor("995")));
        tracker.record_refused(&op, "INVALID_REQUEST", t0);
        let soon = t0 + Duration::from_secs(30);
        assert_eq!(tracker.plan(soon, None), None, "not re-signed next cycle");
        assert_eq!(
            tracker.plan(t0 + REFUSED_OP_RETRY_INTERVAL, None),
            Some(NodeOp::AddStake(kor("995")))
        );

        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into(), "AGR-b".into()],
            ..ExitInputs::default()
        };
        let leave_a = NodeOp::LeaveAgreement("AGR-a".into());
        assert_eq!(tracker.plan(t0, Some(&exit)), Some(leave_a.clone()));
        tracker.record_refused(&leave_a, "INVALID_REQUEST", t0);
        assert_eq!(
            tracker.plan(soon, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-b".into())),
            "the next agreement, not the refused one again"
        );
        assert_eq!(
            tracker.plan(t0 + REFUSED_OP_RETRY_INTERVAL, Some(&exit)),
            Some(leave_a)
        );
    }

    /// Through the relay: a 4xx backs the top-up off, except the ones that
    /// say nothing about the op — a `409` (the nonce was taken), a `401` (the
    /// session expired), a `408` or `429` (come back later) — the same four
    /// the proofs do not count as refusals.
    #[tokio::test]
    async fn the_relay_s_refusal_backs_off_and_a_lost_nonce_does_not() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (status, backs_off) in [
            (400u16, true),
            (403, true),
            (422, true),
            (409, false),
            (401, false),
            (408, false),
            (429, false),
        ] {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "error": {"code": "NOPE", "message": "no", "status": status}
                })))
                .mount(&mock_server)
                .await;
            let client = PortalClient::try_with_auth(
                mock_server.uri(),
                std::env::temp_dir(),
                Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
                "NODE-test",
                42,
                "token",
                10,
            )
            .unwrap();
            let tracker = StakeTracker::new(StakePolicy::default());
            observed(&tracker, &entry(Some("0"), Some("0")), Instant::now());

            assert_eq!(manage_stake(&client, &tracker, None).await, None);
            assert_eq!(
                tracker.plan(Instant::now(), None).is_none(),
                backs_off,
                "{status}"
            );
        }
    }

    /// The Portal's retirement messages, and only those, say an op never ran.
    #[test]
    fn only_the_portal_s_own_retirement_messages_count_as_retired() {
        for retired in [
            "no receipt recorded by Kontor (op never executed)",
            "nonce already passed: nonce 10 is below the signer's next nonce 11 on Kontor, \
             so the op can never execute; sign it again with a fresh nonce",
            "signature no longer verifies: the stored signature does not verify against the \
             signer's current BLS key, registered after the op was signed, so the op never \
             executed; sign it again",
            // Only the token counts; the wording after it may change.
            "nonce already passed: (reworded)",
            "signature no longer verifies: (reworded)",
            "the stored op cannot be batched by this Portal (unknown op kind), so it never \
             executed (no receipt); sign a new op",
        ] {
            assert!(retired_by_portal(retired), "{retired}");
        }
        for refused in [
            "ContractErr: err(message(\"nonce mismatch\"))",
            "ContractErr: err(message(\"no receipt for this nonce\"))",
            "ContractErr: err(message(\"nonce already passed: not the Portal's\"))",
            "nonce 10 is below the signer's next nonce 11 on Kontor (old wording, no token)",
            "the stored signature does not verify against the signer's current BLS key",
            "ContractErr: insufficient balance",
            "OutOfFuel",
            "",
        ] {
            assert!(!retired_by_portal(refused), "{refused}");
        }
    }

    /// An `add-stake` whose nonce went while the bond did not move is backed
    /// off — Kontor refused it — unless the Portal's listing says Kontor never
    /// ran it: retired for a stale nonce, or listed `failed` with no receipt
    /// because a proof batched ahead of it took the nonce. The backoff would
    /// then blame Kontor for the Portal's doing, so it is lifted.
    #[test]
    fn an_add_stake_the_portal_retired_unexecuted_is_signed_again() {
        let failed = |error: &str| NodeOpRecord {
            op: "add_stake".into(),
            amount: None,
            agreement_id: None,
            nonce: 10,
            status: "failed".into(),
            error: Some(error.into()),
            txid: None,
        };
        let submitted = || NodeOpRecord {
            op: "add_stake".into(),
            amount: None,
            agreement_id: None,
            nonce: 10,
            status: "submitted".into(),
            error: None,
            txid: Some("ff".into()),
        };
        // The listing, whether the op is signed again, and whether the
        // Portal is asked again next cycle because it has not said yet.
        let cases: [(anyhow::Result<Vec<NodeOpRecord>>, bool, bool); 6] = [
            (
                Ok(vec![failed(
                    "no receipt recorded by Kontor (op never executed)",
                )]),
                true,
                false,
            ),
            (
                Ok(vec![failed(
                    "nonce already passed: nonce 10 is below the signer's next nonce 11 on \
                     Kontor, so the op can never execute; sign it again with a fresh nonce",
                )]),
                true,
                false,
            ),
            (
                Ok(vec![failed("ContractErr: insufficient balance")]),
                false,
                false,
            ),
            (Ok(vec![]), false, false),
            (Ok(vec![submitted()]), false, true),
            (Err(anyhow::anyhow!("portal down")), false, true),
        ];
        for (listing, signs_again, asked_again) in cases {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &entry(Some("0"), Some("0")), t0);
            assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));
            tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
            let mut unchanged = entry(Some("0"), Some("0"));
            unchanged.next_nonce = Some(11);
            observed(&tracker, &unchanged, t0);
            assert_eq!(
                tracker.plan(t0, None),
                None,
                "backed off until the Portal says"
            );
            assert_eq!(tracker.op_to_classify(), Some(10));

            tracker.classify_landed(10, listing, t0);
            assert_eq!(tracker.op_to_classify().is_some(), asked_again);
            assert_eq!(tracker.plan(t0, None).is_some(), signs_again);
        }
    }

    /// An `add-stake` the relay gave no answer for, whose nonce then went
    /// while the bond did not move, is backed off like any other — until the
    /// Portal's listing shows it does not hold the op: then it was never
    /// stored, another op took the nonce, and Kontor refused nothing.
    #[test]
    fn an_unsettled_add_stake_the_portal_never_stored_is_signed_again() {
        for (record, signs_again) in [
            (
                StakeTracker::record_unsettled as fn(&StakeTracker, NodeOp, u64, Instant),
                true,
            ),
            (StakeTracker::record_sent, false),
        ] {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &entry(Some("0"), Some("0")), t0);
            assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));
            record(&tracker, NodeOp::AddStake(kor("995")), 10, t0);
            let mut unchanged = entry(Some("0"), Some("0"));
            unchanged.next_nonce = Some(11);
            observed(&tracker, &unchanged, t0);
            assert_eq!(
                tracker.plan(t0, None),
                None,
                "backed off until the Portal says"
            );
            assert_eq!(tracker.op_to_classify(), Some(10));

            tracker.classify_landed(10, Ok(vec![]), t0);
            assert_eq!(tracker.op_to_classify(), None);
            assert_eq!(tracker.plan(t0, None).is_some(), signs_again);
        }
    }

    /// A leave is only counted as left once the Portal lists it `confirmed`.
    /// Until the Portal has said, the agreement is neither left again nor the
    /// bond withdrawn; one Kontor refused waits an hour, one that never ran is
    /// signed again at once.
    #[test]
    fn a_leave_counts_as_left_only_once_the_portal_confirms_it() {
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        let leave = NodeOp::LeaveAgreement("AGR-a".into());
        let landed = || {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &exiting_entry(10, "100"), t0);
            assert_eq!(tracker.plan(t0, Some(&exit)), Some(leave.clone()));
            tracker.record_sent(leave.clone(), 10, t0);
            observed(&tracker, &exiting_entry(11, "100"), t0);
            assert_eq!(tracker.op_to_classify(), Some(10));
            (tracker, t0)
        };
        let due = |t0: Instant| t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;

        // Not decided yet: nothing is sent, not even the withdrawal.
        let (tracker, t0) = landed();
        tracker.classify_landed(10, Ok(vec![leave_record(10, "submitted", None)]), t0);
        assert_eq!(tracker.op_to_classify(), Some(10), "asked again next cycle");
        assert_eq!(tracker.plan(due(t0), Some(&exit)), None);
        assert_eq!(tracker.status()["exit"]["left"], 0);

        // Confirmed: left, and the exit goes on.
        tracker.classify_landed(10, Ok(vec![leave_record(10, "confirmed", None)]), t0);
        assert_eq!(tracker.status()["exit"]["left"], 1);
        assert_eq!(
            tracker.plan(due(t0), Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );

        // Kontor refused it: not left, and tried again after the hour.
        let (tracker, t0) = landed();
        tracker.classify_landed(
            10,
            Ok(vec![leave_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"not a member\"))"),
            )]),
            t0,
        );
        assert_eq!(tracker.status()["exit"]["left"], 0);
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "backed off");
        assert_eq!(
            tracker.plan(t0 + REFUSED_OP_RETRY_INTERVAL, Some(&exit)),
            Some(leave.clone())
        );

        // Retired by the Portal before it ran, or not listed at all: signed
        // again at once.
        for listing in [
            vec![leave_record(
                10,
                "failed",
                Some("no receipt recorded by Kontor (op never executed)"),
            )],
            vec![],
        ] {
            let (tracker, t0) = landed();
            tracker.classify_landed(10, Ok(listing), t0);
            assert_eq!(tracker.plan(t0, Some(&exit)), Some(leave.clone()));
        }

        // The Portal never says: after the hard timeout the rows decide, and
        // the leave is sent again rather than the exit stalling.
        let (tracker, t0) = landed();
        tracker.classify_landed(10, Err(anyhow::anyhow!("down")), t0);
        assert_eq!(tracker.op_to_classify(), Some(10));
        tracker.classify_landed(
            10,
            Err(anyhow::anyhow!("down")),
            t0 + OP_LANDING_HARD_TIMEOUT,
        );
        assert_eq!(tracker.op_to_classify(), None);
        assert_eq!(
            tracker.plan(t0 + OP_LANDING_HARD_TIMEOUT, Some(&exit)),
            Some(leave)
        );
    }

    /// An op the Portal keeps listing as `queued` or `submitted` is waited
    /// for past the hard timeout — Portal `docs/node-portal-contract.md` §2:
    /// it has not been lost and must not be signed again — including one
    /// that goes back from `submitted` to `queued` when the Portal gives up
    /// on its batch. The timeout runs from the Portal's last word.
    #[test]
    fn an_op_the_portal_still_holds_is_waited_for_past_the_hard_timeout() {
        let listed = |status: &str| {
            Ok(vec![NodeOpRecord {
                op: "add_stake".into(),
                amount: None,
                agreement_id: None,
                nonce: 10,
                status: status.into(),
                error: None,
                txid: None,
            }])
        };
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let mut at = t0;
        for status in ["queued", "submitted", "submitted", "queued", "queued"] {
            at += OP_LANDING_CHECK_INTERVAL;
            assert_eq!(tracker.op_to_verify(at), Some(10));
            tracker.verify_in_flight(10, listed(status), at);
            observed(&tracker, &entry(Some("0"), Some("0")), at);
            assert_eq!(tracker.plan(at, None), None, "{status} at +{:?}", at - t0);
        }
        let vouched = at;
        let past = t0 + OP_LANDING_HARD_TIMEOUT + Duration::from_secs(1);
        observed(&tracker, &entry(Some("0"), Some("0")), past);
        assert_eq!(
            tracker.plan(past, None),
            None,
            "the Portal said it holds the op; the hard timeout does not apply"
        );
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);

        // No word from the Portal for the whole timeout after its last one:
        // still waited for. Silence is not the Portal saying it dropped the op.
        observed(
            &tracker,
            &entry(Some("0"), Some("0")),
            vouched + OP_LANDING_HARD_TIMEOUT,
        );
        assert_eq!(tracker.plan(vouched + OP_LANDING_HARD_TIMEOUT, None), None);
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);
    }

    /// The same op asked for from `/admin` while the daemon's copy is still
    /// in flight is refused: both would execute.
    #[test]
    fn an_operator_request_is_refused_while_the_same_op_is_in_flight() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        tracker.request(NodeOp::BeginUnstake).unwrap();
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::BeginUnstake));
        tracker.record_sent(NodeOp::BeginUnstake, 10, t0);

        let err = tracker.request(NodeOp::BeginUnstake).unwrap_err();
        assert!(err.contains("in flight"), "{err}");
        assert_eq!(tracker.status()["operator_request"], Value::Null);

        observed(&tracker, &exiting_entry(11, "100"), t0);
        tracker.request(NodeOp::WithdrawStake).unwrap();
        tracker.record_sent(NodeOp::WithdrawStake, 11, t0);
        let err = tracker.request(NodeOp::WithdrawStake).unwrap_err();
        assert!(err.contains("in flight"), "{err}");
    }

    /// A Portal that could not read whether bond cleanup is pending leaves
    /// the end of an exit undecided: the drop to zero is reported as neither
    /// a withdrawal nor a slash, and `/admin` shows the field as unknown.
    #[test]
    fn an_unknown_bond_cleanup_decides_nothing() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let mut over = entry(Some("0"), Some("0"));
        over.bond_cleanup_pending = None;
        observed(&tracker, &over, t0);
        let event = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(event.contains("could not say"), "{event}");
        assert!(!event.contains("withdrawal completed"), "{event}");
        assert_eq!(tracker.status()["bond_cleanup_pending"], Value::Null);
        assert_eq!(tracker.status()["exited"], true);
        assert_eq!(tracker.plan(t0, None), None, "nothing bonded again");

        // Unknown is not "cleanup finished" either.
        let tracker = StakeTracker::new(StakePolicy::default());
        let mut cleaning = entry(Some("0"), Some("0"));
        cleaning.bond_cleanup_pending = Some(true);
        observed(&tracker, &cleaning, t0);
        let mut unknown = entry(Some("0"), Some("0"));
        unknown.bond_cleanup_pending = None;
        observed(&tracker, &unknown, t0);
        assert_eq!(
            tracker.status()["last_event"]["message"],
            "bond cleanup pending",
            "no event for a field that was not read"
        );
    }

    /// Through the client: the failed-ops listing is consulted before the
    /// plan, and an op the Portal retired goes out again in the same cycle.
    #[tokio::test]
    async fn a_retired_add_stake_is_signed_again_through_the_relay() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // The process's first look at what the Portal still holds: nothing.
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(query_param("status", "queued|submitted"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 100, "total": 0, "node_id": "NODE-test", "ops": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 100, "total": 1, "node_id": "NODE-test",
                "ops": [{
                    "id": "a", "node_id": "NODE-test", "op": "add_stake", "amount": "995",
                    "agreement_id": null, "nonce": 10, "status": "failed",
                    "transaction_id": "T-1",
                    "error": "no receipt recorded by Kontor (op never executed)",
                    "txid": "ff", "created_at": "2026-11-03T10:00:00+00:00",
                    "updated_at": "2026-11-03T10:30:00+00:00"
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": "add_stake", "status": "queued", "nonce": 10
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = PortalClient::try_with_auth(
            mock_server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            10,
        )
        .unwrap();
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
        let mut unchanged = entry(Some("0"), Some("0"));
        unchanged.next_nonce = Some(11);
        observed(&tracker, &unchanged, t0);

        assert_eq!(
            manage_stake(&client, &tracker, None).await,
            Some(NodeOp::AddStake(kor("995")))
        );
        assert_eq!(tracker.status()["in_flight"]["op"], "add_stake");
    }

    /// A restart forgets the op in flight, not the Portal: an `add-stake` the
    /// earlier process signed may still be queued there. Before the first plan
    /// the node reads the Portal's pending ops, adopts the newest as in flight
    /// and moves its nonce counter past it — so the same top-up is not signed
    /// a second time, and not refused `409` first either.
    #[tokio::test]
    async fn a_restart_adopts_the_op_the_portal_still_holds() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .and(query_param("status", "queued|submitted"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "offset": 0, "limit": 100, "total": 2, "node_id": "NODE-test",
                "ops": [{
                    "id": "b", "node_id": "NODE-test", "op": "add_stake", "amount": "990",
                    "agreement_id": null, "nonce": 12, "status": "submitted",
                    "transaction_id": "T-1", "error": null, "txid": "ff",
                    "created_at": "2026-11-03T10:00:00+00:00",
                    "updated_at": "2026-11-03T10:30:00+00:00"
                }, {
                    "id": "a", "node_id": "NODE-test", "op": "claim_rewards", "amount": null,
                    "agreement_id": null, "nonce": 10, "status": "queued",
                    "transaction_id": null, "error": null, "txid": null,
                    "created_at": "2026-11-03T09:00:00+00:00",
                    "updated_at": "2026-11-03T09:00:00+00:00"
                }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(202))
            .expect(0)
            .mount(&mock_server)
            .await;
        // Kontor's next_nonce, where a fresh process starts its counter.
        let client = PortalClient::try_with_auth(
            mock_server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            10,
        )
        .unwrap();
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        // The balance would call for a 995 KOR top-up: a different amount
        // from the 990 still queued, so the Portal would not have answered it
        // idempotently.
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));

        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        let status = tracker.status();
        assert_eq!(status["in_flight"]["op"], "add_stake");
        assert_eq!(status["in_flight"]["amount"], "990");
        assert_eq!(status["in_flight"]["nonce"], 12);
        assert_eq!(
            client.current_nonce(),
            Some(13),
            "past every nonce the Portal holds"
        );
        assert_eq!(tracker.plan(t0, None), None);

        // Landed: the registry moves past it, and the policy decides afresh.
        let mut landed = entry(Some("990"), Some("990"));
        landed.next_nonce = Some(13);
        landed.kor_balance = Some("5".into());
        observed(&tracker, &landed, t0);
        assert_eq!(tracker.status()["in_flight"], Value::Null);
        assert_eq!(tracker.plan(t0, None), None, "nothing above the reserve");
    }

    /// A `409` says the nonce went to an op the Portal already holds — after
    /// a restart, most likely this node's own earlier `add-stake`. The listing
    /// is read and that op adopted, so the next cycle does not sign the
    /// top-up again at the next nonce and bond it twice.
    #[tokio::test]
    async fn a_conflict_adopts_the_op_holding_the_nonce() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let page = |ops: Value| json!({"offset": 0, "limit": 100, "total": 1, "node_id": "NODE-test", "ops": ops});
        // Nothing pending at startup; the queued op shows up only after the
        // 409 (it was stored between the two reads, or the first read was a
        // page behind).
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(json!([]))))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {"code": "CONFLICT", "message": "nonce 10 is held", "status": 409}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(json!([{
                "id": "a", "node_id": "NODE-test", "op": "add_stake", "amount": "990",
                "agreement_id": null, "nonce": 10, "status": "queued",
                "transaction_id": null, "error": null, "txid": null,
                "created_at": "2026-11-03T10:00:00+00:00",
                "updated_at": "2026-11-03T10:00:00+00:00"
            }]))))
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = PortalClient::try_with_auth(
            mock_server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            10,
        )
        .unwrap();
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);

        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        let status = tracker.status();
        assert_eq!(status["in_flight"]["op"], "add_stake");
        assert_eq!(status["in_flight"]["nonce"], 10);
        assert_eq!(client.current_nonce(), Some(11));
        assert_eq!(tracker.plan(t0, None), None, "waited for, not signed again");
    }

    /// Through the relay: an answer that says nothing about whether the op
    /// was stored — a 5xx, or no answer at all — leaves it in flight at the
    /// nonce it was signed with, where a refusal or a lost nonce does not.
    /// Planned again from the same snapshot, the top-up would otherwise go out
    /// a second time at the next nonce, and a Portal that had stored the first
    /// would relay both.
    #[tokio::test]
    async fn an_op_the_portal_gave_no_answer_to_stays_in_flight() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let client_for = |uri: String| {
            PortalClient::try_with_auth(
                uri,
                std::env::temp_dir(),
                Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
                "NODE-test",
                42,
                "token",
                10,
            )
            .unwrap()
        };
        let tracked = |tracker: &StakeTracker| tracker.status()["in_flight"]["nonce"].clone();

        // A 400 backs the op off, a 409 leaves it to be signed again at once.
        for (status, in_flight, plans_again) in [
            (500u16, true, false),
            (503, true, false),
            (400, false, false),
            (409, false, true),
        ] {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "error": {"code": "NOPE", "message": "no", "status": status}
                })))
                .mount(&mock_server)
                .await;
            let client = client_for(mock_server.uri());
            let tracker = StakeTracker::new(StakePolicy::default());
            observed(&tracker, &entry(Some("0"), Some("0")), Instant::now());

            assert_eq!(manage_stake(&client, &tracker, None).await, None);
            assert_eq!(
                tracked(&tracker),
                if in_flight { json!(10) } else { Value::Null },
                "{status}"
            );
            assert_eq!(
                tracker.plan(Instant::now(), None).is_some(),
                plans_again,
                "{status}"
            );
        }

        // No Portal at all: the same open question, settled the same way. The
        // Portal went away after this process read its pending ops — before
        // that read, nothing is signed at all.
        let client = client_for("http://127.0.0.1:1".to_string());
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        assert_eq!(
            tracked(&tracker),
            Value::Null,
            "nothing signed before the pending ops are read"
        );
        tracker.adopt_pending_ops(&[], t0);
        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        assert_eq!(tracked(&tracker), json!(10));
        assert_eq!(tracker.plan(t0, None), None);
        assert!(
            tracker.status()["last_event"]["message"]
                .as_str()
                .unwrap()
                .contains("no answer"),
            "{}",
            tracker.status()["last_event"]
        );

        // The listing, asked after the usual wait, settles it: gone, the
        // plan is made again (a listed op is covered by
        // `the_portal_s_listing_decides_whether_an_overdue_op_is_dropped`).
        let check = Instant::now() + OP_LANDING_CHECK_INTERVAL;
        assert_eq!(tracker.op_to_verify(check), Some(10));
        tracker.verify_in_flight(10, Ok(vec![]), check);
        assert_eq!(
            tracker.plan(check, None),
            Some(NodeOp::AddStake(kor("995")))
        );
    }

    /// A withdrawal that takes longer than [`OP_LANDING_HARD_TIMEOUT`] to
    /// execute is no longer tracked when it lands. The snapshot still shows it
    /// — an exit under way, then no bond and no withdrawal pending — and the
    /// balance it returned is not bonded again.
    #[test]
    fn a_withdrawal_that_lands_late_still_ends_the_auto_stake() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(12, "100"), t0);
        tracker.request(NodeOp::WithdrawStake).unwrap();
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::WithdrawStake));
        tracker.record_sent(NodeOp::WithdrawStake, 12, t0);

        // The Portal's listing no longer shows it (a page behind, say): the
        // op is forgotten, and executes all the same.
        let late = t0 + OP_LANDING_CHECK_INTERVAL;
        observed(&tracker, &exiting_entry(12, "100"), late);
        tracker.verify_in_flight(12, Ok(vec![]), late);
        assert_eq!(tracker.status()["in_flight"], Value::Null, "forgotten");

        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(13);
        withdrawn.kor_balance = Some("105".into());
        observed(&tracker, &withdrawn, late + Duration::from_secs(60));
        assert_eq!(
            tracker.plan(late + Duration::from_secs(60), None),
            None,
            "the returned bond is not staked again"
        );
        assert_eq!(tracker.status()["exited"], true);
    }

    /// An exiting node slashed to its last KOR looks, from the registry, like
    /// one whose withdrawal completed: no stake, no withdrawal height — Kontor
    /// clears the height when nothing is left to withdraw. Bond cleanup tells
    /// them apart, a withdrawal leaving nothing to clean up. The slash is
    /// reported as one, and the exit is over either way.
    #[test]
    fn a_slash_to_zero_during_the_exit_is_not_a_completed_withdrawal() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let mut slashed = entry(Some("0"), Some("0"));
        slashed.bond_cleanup_pending = Some(true);
        observed(&tracker, &slashed, t0);
        let event = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(event.contains("slashed"), "{event}");
        assert!(!event.contains("withdrawal completed"), "{event}");
        assert_eq!(
            tracker.status()["exited"],
            true,
            "nothing is left to withdraw, and nothing is bonded again"
        );
        assert_eq!(tracker.plan(t0, None), None);

        // The real thing, for contrast.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(
            tracker.status()["last_event"]["message"],
            "withdrawal completed"
        );
        assert_eq!(tracker.status()["exited"], true);
    }

    /// An empty bond on a node that was never exiting is a new node: it stakes.
    #[test]
    fn an_empty_bond_without_an_exit_is_not_a_withdrawal() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));
        assert_eq!(tracker.status()["exited"], false);
    }

    /// Without the operator's unstake there is no exit, whatever the rows say.
    #[test]
    fn no_exit_without_an_unstake() {
        let tracker = StakeTracker::new(StakePolicy {
            auto_stake: false,
            ..StakePolicy::default()
        });
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        assert!(!tracker.exiting());
        assert_eq!(tracker.plan(t0, Some(&exit)), None);
    }

    #[tokio::test]
    async fn exit_inputs_reads_memberships_and_open_challenges_from_the_rows() {
        use crate::testutils::{setup_in_memory_db, AgreementFixture};
        use sea_orm::{ActiveModelTrait, Set};

        let db = setup_in_memory_db().await;
        for (id, status, nodes) in [
            (
                "AGR-live",
                "confirmed",
                json!([{"node_id": "NODE-me", "status": "valid"}]),
            ),
            ("AGR-bare", "confirmed", json!(["NODE-me"])),
            (
                "AGR-open",
                "confirmed",
                json!([{"node_id": "NODE-me", "status": "valid"}]),
            ),
            (
                "AGR-failed-join",
                "confirmed",
                json!([{"node_id": "NODE-me", "status": "failed"}]),
            ),
            (
                "AGR-left",
                "confirmed",
                json!([{"node_id": "NODE-me", "status": "left"}]),
            ),
            (
                "AGR-invalidated",
                "confirmed",
                json!([{"node_id": "NODE-me", "status": "invalid"}]),
            ),
            (
                "AGR-not-yet",
                "ready",
                json!([{"node_id": "NODE-me", "status": "valid"}]),
            ),
            (
                "AGR-failed",
                "failed",
                json!([{"node_id": "NODE-me", "status": "valid"}]),
            ),
            (
                "AGR-other",
                "confirmed",
                json!([{"node_id": "NODE-other", "status": "valid"}]),
            ),
        ] {
            AgreementFixture {
                status: status.into(),
                nodes,
                ..AgreementFixture::new(id, format!("F-{id}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }
        let settled_long_ago = (Utc::now() - chrono::Duration::hours(2)).fixed_offset();
        let just_now = Utc::now().fixed_offset();
        for (id, agreement, status, updated_at) in [
            ("c1", "AGR-open", "active", just_now),
            ("c2", "AGR-live", "proved", just_now),
            ("c3", "AGR-live", "resolved", just_now),
            ("c4", "AGR-bare", "failed", settled_long_ago),
            ("c5", "AGR-bare", "failed", just_now),
        ] {
            crate::entities::challenges::ActiveModel {
                challenge_id: Set(id.into()),
                agreement_id: Set(agreement.into()),
                block_height: Set(1),
                challenge_count: Set(1),
                seed: Set("00".into()),
                prover_id: Set("42".into()),
                deadline_height: Set(10),
                status: Set(status.into()),
                proof: Set(None),
                bls_signature: Set(None),
                created_at: Set(chrono::Utc::now().fixed_offset()),
                updated_at: Set(updated_at),
            }
            .insert(&db)
            .await
            .unwrap();
        }

        let exit = exit_inputs(&db, "NODE-me").await.unwrap();
        assert_eq!(
            exit.memberships,
            vec!["AGR-bare", "AGR-live", "AGR-open"],
            "a failed, invalidated or left row is not a membership to leave"
        );
        assert_eq!(exit.deferred, vec!["AGR-open"]);
        assert_eq!(
            exit.unresolved_challenges, 3,
            "active, proved-but-unsettled, and failed while Kontor may still have its penalty \
             to settle; one failed hours ago is settled by now"
        );
    }

    /// The rows only learn that a membership is over from the Portal's detail
    /// endpoint: the node-filtered listing reconciliation uses drops a
    /// membership once it is no longer `valid`. Re-reading them before the
    /// exit acts is what keeps a restarted node from paying for a leave an
    /// earlier process already made.
    #[tokio::test]
    async fn refreshing_memberships_learns_which_ones_the_portal_has_closed() {
        use crate::testutils::{setup_in_memory_db, AgreementFixture};
        use sea_orm::ActiveModelTrait;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let detail = |id: &str, status: &str, membership: &str| {
            json!({
                "agreement_id": id,
                "user_id": "user_1",
                "file_id": format!("F-{id}"),
                "filename": "test.bin",
                "mime_type": "application/octet-stream",
                "original_size": 123,
                "nodes": [{"node_id": "NODE-test", "status": membership}],
                "transaction_id": null,
                "status": status,
                "created_at": "2024-01-01T00:00:00Z"
            })
        };
        for (id, membership) in [("AGR-gone", "left"), ("AGR-kept", "valid")] {
            Mock::given(method("GET"))
                .and(path(format!("/api/agreements/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(detail(
                    id,
                    "confirmed",
                    membership,
                )))
                .expect(1)
                .mount(&mock_server)
                .await;
        }
        // Not on chain yet, and not asked about: there is nothing to leave.
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-ready"))
            .respond_with(ResponseTemplate::new(200).set_body_json(detail(
                "AGR-ready",
                "ready",
                "valid",
            )))
            .expect(0)
            .mount(&mock_server)
            .await;

        let db = setup_in_memory_db().await;
        for (id, status) in [
            ("AGR-gone", "confirmed"),
            ("AGR-kept", "confirmed"),
            ("AGR-ready", "ready"),
        ] {
            AgreementFixture {
                status: status.into(),
                nodes: json!([{"node_id": "NODE-test", "status": "valid"}]),
                ..AgreementFixture::new(id, format!("F-{id}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }
        let client = PortalClient::try_with_auth(
            mock_server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            10,
        )
        .unwrap();

        assert_eq!(
            exit_inputs(&db, "NODE-test").await.unwrap().memberships,
            vec!["AGR-gone", "AGR-kept"],
            "stale rows: the leave of AGR-gone would be paid for again"
        );
        refresh_memberships(&client, &db, "NODE-test")
            .await
            .unwrap();
        assert_eq!(
            exit_inputs(&db, "NODE-test").await.unwrap().memberships,
            vec!["AGR-kept"]
        );

        let tracker = StakeTracker::new(StakePolicy::default());
        assert!(tracker.memberships_need_refresh(), "once per process");
        tracker.memberships_refreshed();
        assert!(!tracker.memberships_need_refresh());
    }
    fn client_at(server: &wiremock::MockServer, nonce: u64) -> PortalClient {
        PortalClient::try_with_auth(
            server.uri(),
            std::env::temp_dir(),
            Arc::new(crate::crypto::BlsKeyPair::generate().unwrap()),
            "NODE-test",
            42,
            "token",
            nonce,
        )
        .unwrap()
    }

    fn ops_page(ops: Value) -> Value {
        json!({"offset": 0, "limit": 100, "total": 1, "node_id": "NODE-test", "ops": ops})
    }

    fn queued_add_stake(amount: &str, nonce: u64) -> Value {
        json!({
            "id": "a", "node_id": "NODE-test", "op": "add_stake", "amount": amount,
            "agreement_id": null, "nonce": nonce, "status": "queued",
            "transaction_id": null, "error": null, "txid": null,
            "created_at": "2026-11-03T10:00:00+00:00",
            "updated_at": "2026-11-03T10:00:00+00:00"
        })
    }

    /// A `429` (or a `401`, a `408`) on the first listing is no answer: the
    /// Portal may hold the previous process's `add-stake`. It used to count
    /// as "nothing to adopt", and the top-up was signed a second time.
    /// Nothing is signed until the listing has been read.
    #[tokio::test]
    async fn a_listing_the_portal_did_not_answer_is_asked_again_before_anything_is_signed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for status in [401, 408, 429] {
            let mock_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(1)
                .expect(1)
                .mount(&mock_server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(ResponseTemplate::new(202))
                .expect(0)
                .mount(&mock_server)
                .await;
            let client = client_at(&mock_server, 10);
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &entry(Some("0"), Some("0")), t0);

            assert_eq!(manage_stake(&client, &tracker, None).await, None);
            assert!(
                !tracker.pending_ops_checked(),
                "{status} is not a listing: the question stays open"
            );
            assert_eq!(tracker.status()["in_flight"], Value::Null);

            // The next cycle asks again, reads the queued op, and waits for it.
            Mock::given(method("GET"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(ops_page(json!([queued_add_stake("990", 10)]))),
                )
                .expect(1)
                .mount(&mock_server)
                .await;
            assert_eq!(manage_stake(&client, &tracker, None).await, None);
            assert!(tracker.pending_ops_checked());
            assert_eq!(tracker.status()["in_flight"]["amount"], "990");
            assert_eq!(client.current_nonce(), Some(11));
        }
    }

    /// A Portal without the listing (`404`, `405`: it predates the relay)
    /// holds nothing to adopt, and the question is settled.
    #[tokio::test]
    async fn a_portal_without_the_listing_has_nothing_to_adopt() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for status in [404, 405] {
            let mock_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/nodes/NODE-test/ops"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&mock_server)
                .await;
            let client = client_at(&mock_server, 10);
            let tracker = StakeTracker::new(StakePolicy::default());
            assert!(adopt_pending_ops(&client, &tracker).await);
            assert!(tracker.pending_ops_checked());
        }
    }

    /// After a `409` the Portal holds an op the tracker does not know. If
    /// the listing cannot be read right then, it is read at the start of the
    /// next cycle, before anything is signed — it used to be skipped for the
    /// rest of the process, and the same top-up went out at the next nonce.
    #[tokio::test]
    async fn a_conflict_whose_listing_cannot_be_read_is_settled_before_the_next_op() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops_page(json!([]))))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": {"code": "CONFLICT", "message": "nonce 10 is held", "status": 409}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .expect(2)
            .mount(&mock_server)
            .await;
        let client = client_at(&mock_server, 10);
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);

        // The 409, then a listing that cannot be read.
        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        assert!(!tracker.pending_ops_checked());
        // Next cycle: still unreadable, so nothing is signed (the POST mock
        // allows exactly one request).
        assert_eq!(manage_stake(&client, &tracker, None).await, None);

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(ops_page(json!([queued_add_stake("990", 10)]))),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        assert_eq!(manage_stake(&client, &tracker, None).await, None);
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);
        assert_eq!(tracker.plan(t0, None), None, "waited for, not signed again");
    }
    fn signer_entry_json(next_nonce: u64, balance: &str, stake: &str) -> Value {
        json!({
            "signer_id": 42, "x_only_pubkey": "ab", "bls_pubkey": null,
            "next_nonce": next_nonce, "kor_balance": balance,
            "stake": stake, "stake_reserved": "0", "stake_available": stake,
            "stake_withdrawal_height": null, "bond_cleanup_pending": false,
            "reward_balance": "0"
        })
    }

    /// The tracker outlives an activation, the client does not. Onboarded
    /// again in the same process, the node used to keep "listing already
    /// read" from the first activation: an `add-stake` the stopped daemon had
    /// sent — stored by the Portal, its answer never read — was neither
    /// adopted nor known, and the new daemon signed the top-up again. Each
    /// activation now reads the listing again, and starts the new client's
    /// counter past the nonces the tracker still waits for.
    #[tokio::test]
    async fn a_new_activation_reads_the_listing_again_and_keeps_its_nonces() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(signer_entry_json(10, "1000", "0")),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(ops_page(json!([queued_add_stake("990", 12)]))),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(202))
            .expect(0)
            .mount(&mock_server)
            .await;

        // The first activation read the listing, and has a join in flight.
        let tracker = Arc::new(StakeTracker::new(StakePolicy::default()));
        let t0 = Instant::now();
        tracker.adopt_pending_ops(&[], t0);
        tracker.record_join("AGR-1", kor("1"), 14, t0);
        assert!(tracker.pending_ops_checked());

        // The second starts a client at Kontor's next_nonce.
        let client = client_at(&mock_server, 10);
        let db = crate::testutils::setup_in_memory_db().await;
        bootstrap_stake(&client, &db, &tracker, &mut Vec::new())
            .await
            .unwrap();
        let status = tracker.status();
        assert_eq!(status["in_flight"]["op"], "add_stake");
        assert_eq!(status["in_flight"]["amount"], "990");
        assert_eq!(
            client.current_nonce(),
            Some(15),
            "past the join the tracker waits for and the op the Portal holds"
        );
    }
    /// The Portal reconciles a block some time after Kontor executes it, so
    /// the next leave routinely lands while the first is still unclassified.
    /// The tracker kept one landed op only: the second overwrote the first,
    /// which was then neither left nor waited for, and was signed again.
    #[test]
    fn every_landed_op_waits_for_the_portal_s_word_not_only_the_last() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into(), "AGR-b".into()],
            ..ExitInputs::default()
        };
        let leave = |id: &str| NodeOp::LeaveAgreement(id.into());

        assert_eq!(tracker.plan(t0, Some(&exit)), Some(leave("AGR-a")));
        tracker.record_sent(leave("AGR-a"), 10, t0);
        observed(&tracker, &exiting_entry(11, "100"), t0);
        // Executed on Kontor; the Portal has not reconciled the block yet.
        tracker.classify_landed(10, Ok(vec![leave_record(10, "submitted", None)]), t0);
        assert_eq!(tracker.ops_to_classify(), vec![10]);

        assert_eq!(tracker.plan(t0, Some(&exit)), Some(leave("AGR-b")));
        tracker.record_sent(leave("AGR-b"), 11, t0);
        observed(&tracker, &exiting_entry(12, "100"), t0);
        assert_eq!(tracker.ops_to_classify(), vec![10, 11], "both asked about");
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            None,
            "AGR-a is neither left nor left again while the Portal has not said"
        );

        let listing = || {
            Ok(vec![
                leave_record(11, "confirmed", None),
                leave_record(10, "confirmed", None),
            ])
        };
        tracker.classify_landed(10, listing(), t0);
        tracker.classify_landed(11, listing(), t0);
        assert_eq!(tracker.ops_to_classify(), Vec::<u64>::new());
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            None,
            "both left; the delay has not run yet"
        );
        assert_eq!(tracker.status()["exit"]["left"], 2);
        assert_eq!(tracker.status()["exit"]["memberships_left"], json!([]));
    }
    /// After a slash to zero Kontor's bond cleanup deactivates every
    /// membership of the node, and the Portal's rows keep saying `valid`. A
    /// node that later exits sends a leave for each, and Kontor answers that
    /// there is nothing to leave. That used to count as a refusal, retried
    /// every hour for ever, with the withdrawal waiting behind it. It is the
    /// outcome the exit wanted: the agreement counts as left.
    #[test]
    fn a_leave_kontor_refuses_for_lack_of_a_membership_counts_as_left() {
        for error in [
            "ContractErr: err(message(\"node 42 not in agreement AGR-a\"))",
            "ContractErr: err(message(\"agreement not found: AGR-a\"))",
        ] {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &exiting_entry(10, "100"), t0);
            let exit = ExitInputs {
                memberships: vec!["AGR-a".into()],
                ..ExitInputs::default()
            };
            tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
            observed(&tracker, &exiting_entry(11, "100"), t0);
            tracker.classify_landed(10, Ok(vec![leave_record(10, "failed", Some(error))]), t0);

            let due = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
            assert_eq!(
                tracker.plan(due, Some(&exit)),
                Some(NodeOp::WithdrawStake),
                "{error}: nothing left to leave, the withdrawal goes"
            );
            assert_eq!(tracker.status()["exit"]["left"], 1);
        }

        // Any other refusal by Kontor still waits its hour, and still holds
        // the withdrawal back: the membership stands.
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
        observed(&tracker, &exiting_entry(11, "100"), t0);
        tracker.classify_landed(
            10,
            Ok(vec![leave_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"agreement reward cleanup in progress\"))"),
            )]),
            t0,
        );
        let due = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
        assert_eq!(
            tracker.plan(due, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into())),
            "the hour has passed: tried again, not withdrawn"
        );
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "backed off meanwhile");
        // The error of another agreement's leave says nothing about this one.
        assert!(!no_membership_to_leave(
            "ContractErr: err(message(\"node 42 not in agreement AGR-b\"))",
            "AGR-a"
        ));
    }
    /// The Portal's message for a `submitted` op whose transaction row it no
    /// longer has (Portal `docs/node-portal-contract.md` §2).
    const ORPHANED: &str = "the Portal transaction that carried the op no longer exists, so \
        whether it executed cannot be checked; verify the signer's state on Kontor before \
        signing a new op";

    fn add_stake_record(nonce: u64, status: &str, error: Option<&str>) -> NodeOpRecord {
        listed_op("add_stake", nonce, status, error)
    }

    #[test]
    fn the_portal_s_lost_transaction_message_is_neither_a_retirement_nor_a_refusal() {
        assert!(orphaned_by_portal(ORPHANED));
        assert!(!retired_by_portal(ORPHANED));
        assert!(retired_by_portal(
            "the stored op cannot be batched by this Portal (unknown op kind), so it never \
             executed (no receipt); sign a new op"
        ));
        assert!(!orphaned_by_portal(
            "ContractErr: err(message(\"the Portal transaction that carried the op no longer \
             exists\"))"
        ));
        assert!(!orphaned_by_portal(PORTAL_NO_RECEIPT));
    }

    /// The Portal lost the transaction an op was batched in, and lists the
    /// op `failed` without knowing whether it ran. That transaction may still
    /// confirm. The op used to be dropped and signed again at once — both
    /// could execute. It now stays in flight until its nonce is consumed, and
    /// is given up only if that has not happened after the hard timeout.
    #[test]
    fn an_op_the_portal_lost_track_of_stays_in_flight_until_its_nonce_decides() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        let orphaned = || Ok(vec![add_stake_record(10, "failed", Some(ORPHANED))]);
        tracker.verify_in_flight(10, orphaned(), check);
        assert_eq!(tracker.plan(check, None), None, "it may still execute");
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);

        // It did execute: the nonce went and the bond rose. Nothing more.
        let mut landed = entry(Some("995"), Some("995"));
        landed.next_nonce = Some(11);
        landed.kor_balance = Some("5".into());
        observed(&tracker, &landed, check);
        assert_eq!(tracker.status()["in_flight"], Value::Null);
        assert_eq!(tracker.plan(check, None), None);

        // One whose nonce is never consumed is given up after the timeout,
        // counted from the Portal's verdict.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
        tracker.verify_in_flight(10, orphaned(), check);
        let almost = check + OP_LANDING_HARD_TIMEOUT - Duration::from_secs(1);
        tracker.verify_in_flight(10, orphaned(), almost);
        assert_eq!(tracker.plan(almost, None), None);
        let over = check + OP_LANDING_HARD_TIMEOUT;
        tracker.verify_in_flight(10, orphaned(), over);
        assert_eq!(tracker.plan(over, None), Some(NodeOp::AddStake(kor("995"))));
    }

    /// Its nonce consumed and the bond unmoved, an op the Portal lost track
    /// of is over either way. It is not a refusal by Kontor: no hour's wait.
    #[test]
    fn a_landed_op_the_portal_lost_track_of_is_decided_again_at_once() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
        let mut consumed = entry(Some("0"), Some("0"));
        consumed.next_nonce = Some(11);
        observed(&tracker, &consumed, t0);
        assert_eq!(tracker.plan(t0, None), None, "the hour's wait, for now");

        tracker.classify_landed(
            10,
            Ok(vec![add_stake_record(10, "failed", Some(ORPHANED))]),
            t0,
        );
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));

        // A leave the Portal lost track of is signed again too: had it run,
        // the second one is answered "not in agreement", which counts as left.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
        observed(&tracker, &exiting_entry(11, "100"), t0);
        tracker.classify_landed(10, Ok(vec![leave_record(10, "failed", Some(ORPHANED))]), t0);
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into()))
        );
    }

    /// The Portal's listing can report an op `failed` before the registry
    /// read shows its nonce consumed. It used to be dropped there and then,
    /// whatever the reason: an `add-stake` Kontor had refused was signed
    /// again on the same cycle, and a leave Kontor had answered "not in
    /// agreement" was not counted as left. Why it failed now decides, exactly
    /// as for an op whose nonce went first.
    #[test]
    fn an_op_the_listing_reports_failed_is_settled_by_why_it_failed() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);
        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        let refused = || {
            Ok(vec![add_stake_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"insufficient funds\"))"),
            )])
        };
        tracker.verify_in_flight(10, refused(), check);
        assert_eq!(tracker.status()["in_flight"], Value::Null);
        assert_eq!(tracker.ops_to_classify(), vec![10]);
        tracker.classify_landed(10, refused(), check);
        assert_eq!(
            tracker.plan(check, None),
            None,
            "refused by Kontor: an hour"
        );
        assert_eq!(
            tracker.plan(check + REFUSED_OP_RETRY_INTERVAL, None),
            Some(NodeOp::AddStake(kor("995")))
        );

        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 10, t0);
        let gone = || {
            Ok(vec![leave_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"node 42 not in agreement AGR-a\"))"),
            )])
        };
        tracker.verify_in_flight(10, gone(), check);
        tracker.classify_landed(10, gone(), check);
        let due = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
        assert_eq!(tracker.plan(due, Some(&exit)), Some(NodeOp::WithdrawStake));
    }
    /// The Portal reads a signer's nonce and its bond in two requests. A read
    /// can show the bond already raised under the old nonce; the next shows
    /// the nonce consumed and the bond "unchanged" since the previous read.
    /// Compared with the previous read, that was an add-stake that "executed
    /// without raising the bond", and the next top-up waited an hour. The
    /// bond is compared with what it was when the op was planned.
    #[test]
    fn a_top_up_is_measured_from_the_bond_it_was_planned_from() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        // Bond raised, nonce not yet: the op is still in flight.
        let mut torn = entry(Some("1095"), Some("1095"));
        torn.kor_balance = Some("5".into());
        observed(&tracker, &torn, t0);
        assert_eq!(tracker.status()["in_flight"]["nonce"], 10);

        // Nonce consumed, bond as on the previous read.
        let mut landed = torn.clone();
        landed.next_nonce = Some(11);
        observed(&tracker, &landed, t0);
        assert_eq!(tracker.ops_to_classify(), Vec::<u64>::new(), "it ran");
        let event = tracker.status()["last_event"]["message"].to_string();
        assert!(!event.contains("without raising"), "{event}");

        // New funds are bonded at once, not an hour later.
        landed.kor_balance = Some("505".into());
        observed(&tracker, &landed, t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("500"))));
    }

    /// An add-stake that ran while a slash took more than it added leaves
    /// the bond below where it started. The Portal's `confirmed` says it ran:
    /// the hour's wait is lifted.
    #[test]
    fn a_confirmed_top_up_is_not_backed_off_when_the_bond_fell_for_another_reason() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut before = entry(Some("100"), Some("100"));
        before.kor_balance = Some("15".into());
        observed(&tracker, &before, t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("10"))));
        tracker.record_sent(NodeOp::AddStake(kor("10")), 10, t0);

        let mut after = entry(Some("80"), Some("80"));
        after.next_nonce = Some(11);
        after.kor_balance = Some("505".into());
        observed(&tracker, &after, t0);
        assert_eq!(tracker.plan(t0, None), None, "looks refused, for now");

        tracker.classify_landed(10, Ok(vec![add_stake_record(10, "confirmed", None)]), t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("500"))));
    }

    /// An op the Portal still lists as `submitted` although Kontor has
    /// consumed its nonce has executed already: the listing is a block
    /// behind. Adopted as in flight, it "landed" on the next read without the
    /// bond moving, and the next top-up waited an hour for nothing.
    #[test]
    fn an_op_whose_nonce_is_already_consumed_is_not_adopted() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut read = entry(Some("990"), Some("990"));
        read.next_nonce = Some(13);
        observed(&tracker, &read, t0);

        let mut record = add_stake_record(12, "submitted", None);
        record.amount = Some("990".into());
        assert_eq!(tracker.adopt_pending_ops(&[record.clone()], t0), None);
        assert_eq!(tracker.status()["in_flight"], Value::Null);
        assert!(tracker.pending_ops_checked());

        // One at the next nonce is still to run, and is adopted.
        record.nonce = 13;
        assert_eq!(
            tracker.adopt_pending_ops(&[record], t0),
            Some((NodeOp::AddStake(kor("990")), 13))
        );
    }

    /// An adopted op has no starting point to measure from. When its nonce
    /// goes the Portal is asked how it ended, and the next top-up waits for
    /// the answer rather than being signed on a guess.
    #[test]
    fn an_adopted_top_up_is_settled_by_the_portal_s_listing() {
        let adopted = || {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            observed(&tracker, &entry(Some("0"), Some("0")), t0);
            let mut record = add_stake_record(10, "queued", None);
            record.amount = Some("990".into());
            tracker.adopt_pending_ops(&[record], t0);
            let mut consumed = entry(Some("0"), Some("0"));
            consumed.next_nonce = Some(11);
            observed(&tracker, &consumed, t0);
            assert_eq!(tracker.ops_to_classify(), vec![10]);
            assert_eq!(tracker.plan(t0, None), None, "not signed on a guess");
            (tracker, t0)
        };

        // Retired by the Portal before Kontor ran it: signed again at once.
        let (tracker, t0) = adopted();
        tracker.classify_landed(
            10,
            Ok(vec![add_stake_record(
                10,
                "failed",
                Some(PORTAL_NO_RECEIPT),
            )]),
            t0,
        );
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));

        // Refused by Kontor: the hour a refusal earns.
        let (tracker, t0) = adopted();
        tracker.classify_landed(
            10,
            Ok(vec![add_stake_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"bond cleanup pending\"))"),
            )]),
            t0,
        );
        assert_eq!(tracker.plan(t0, None), None);
        assert_eq!(
            tracker.plan(t0 + REFUSED_OP_RETRY_INTERVAL, None),
            Some(NodeOp::AddStake(kor("995")))
        );
    }
    /// A `withdraw-stake` Kontor refused leaves the bond where it was. If the
    /// bond shrank on the read that showed the withdrawal's nonce consumed,
    /// that was a slash — and it went unreported, because any drop on a read
    /// where a withdrawal landed was put down to the withdrawal.
    #[test]
    fn a_slash_on_the_read_a_refused_withdrawal_lands_is_reported() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(12, "100"), t0);
        tracker.request(NodeOp::WithdrawStake).unwrap();
        tracker.record_sent(NodeOp::WithdrawStake, 12, t0);

        // Refused (an obligation was outstanding), and 30 KOR slashed.
        observed(&tracker, &exiting_entry(13, "70"), t0);
        let event = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(event.contains("slashed"), "{event}");
        assert!(event.contains("30"), "{event}");
        assert_eq!(tracker.status()["exited"], false);

        // One that returned the whole bond is still a withdrawal.
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &exiting_entry(12, "100"), t0);
        tracker.request(NodeOp::WithdrawStake).unwrap();
        tracker.record_sent(NodeOp::WithdrawStake, 12, t0);
        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(13);
        observed(&tracker, &withdrawn, t0);
        let event = tracker.status()["last_event"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(event, "withdrawal completed");
    }
    fn unstake_record(nonce: u64, status: &str, error: Option<&str>) -> NodeOpRecord {
        listed_op("begin_unstake", nonce, status, error)
    }

    /// The operator's `begin-unstake` consumed its nonce and no withdrawal is
    /// pending. Nothing plans an unstake again, and the op used to vanish
    /// without a word: joins resumed and the operator believed the exit had
    /// begun. The Portal's listing now says how it ended. Retired before
    /// Kontor ran it (a proof took its nonce), it is put back as the
    /// operator's request and signed again; and until the listing has
    /// answered, no join is made.
    #[test]
    fn an_unstake_that_never_ran_is_signed_again_and_joins_stay_closed_meanwhile() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut bonded = entry(Some("100"), Some("100"));
        bonded.kor_balance = Some("5".into());
        observed(&tracker, &bonded, t0);
        tracker.request(NodeOp::BeginUnstake).unwrap();
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::BeginUnstake));
        tracker.record_sent(NodeOp::BeginUnstake, 10, t0);

        // Nonce consumed, no withdrawal height.
        let mut consumed = bonded.clone();
        consumed.next_nonce = Some(11);
        observed(&tracker, &consumed, t0);
        let event = tracker.status()["last_event"]["message"].to_string();
        assert!(event.contains("without starting the withdrawal"), "{event}");
        assert_eq!(tracker.ops_to_classify(), vec![10]);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::Leaving),
            "undecided: no join in between"
        );
        assert_eq!(tracker.plan(t0, None), None);

        tracker.classify_landed(
            10,
            Ok(vec![unstake_record(10, "failed", Some(PORTAL_NO_RECEIPT))]),
            t0,
        );
        assert_eq!(tracker.status()["operator_request"], "begin_unstake");
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::BeginUnstake));
    }

    /// Refused by Kontor, the unstake is not signed again — it would meet the
    /// same answer — and the operator is told why. Joins resume.
    #[test]
    fn an_unstake_kontor_refused_is_reported_to_the_operator() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut bonded = entry(Some("100"), Some("100"));
        bonded.kor_balance = Some("5".into());
        observed(&tracker, &bonded, t0);
        tracker.request(NodeOp::BeginUnstake).unwrap();
        tracker.record_sent(NodeOp::BeginUnstake, 10, t0);
        let mut consumed = bonded.clone();
        consumed.next_nonce = Some(11);
        observed(&tracker, &consumed, t0);

        tracker.classify_landed(
            10,
            Ok(vec![unstake_record(
                10,
                "failed",
                Some("ContractErr: err(message(\"withdrawal already requested\"))"),
            )]),
            t0,
        );
        let event = tracker.status()["last_event"]["message"].to_string();
        assert!(event.contains("begin_unstake refused by Kontor"), "{event}");
        assert!(event.contains("withdrawal already requested"), "{event}");
        assert_eq!(tracker.status()["operator_request"], Value::Null);
        assert_eq!(tracker.plan(t0, None), None);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Join {
                collateral: Some(kor("1"))
            }
        );
    }

    /// An unstake, or a withdrawal made by hand, that the Portal dropped
    /// before relaying it is the operator's request again. The policy plans
    /// neither on its own, so "deciding again" used to mean forgetting it.
    #[test]
    fn an_operator_s_op_the_portal_dropped_is_requested_again() {
        for op in [NodeOp::BeginUnstake, NodeOp::WithdrawStake] {
            let tracker = StakeTracker::new(StakePolicy::default());
            let t0 = Instant::now();
            let read = if op == NodeOp::WithdrawStake {
                exiting_entry(10, "100")
            } else {
                let mut bonded = entry(Some("100"), Some("100"));
                bonded.kor_balance = Some("5".into());
                bonded
            };
            observed(&tracker, &read, t0);
            tracker.request(op.clone()).unwrap();
            tracker.record_sent(op.clone(), 10, t0);
            assert_eq!(tracker.status()["operator_request"], Value::Null);

            let check = t0 + OP_LANDING_CHECK_INTERVAL;
            tracker.verify_in_flight(10, Ok(vec![]), check);
            assert_eq!(tracker.status()["operator_request"], op.name());
            assert_eq!(tracker.plan(check, None), Some(op));
        }

        // A withdrawal the exit planned on its own is planned again by the
        // exit when it is due, not turned into a request.
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        tracker.record_sent(NodeOp::WithdrawStake, 10, t0);
        tracker.verify_in_flight(10, Ok(vec![]), t0 + OP_LANDING_CHECK_INTERVAL);
        assert_eq!(tracker.status()["operator_request"], Value::Null);
    }
    /// An empty bond is what a slash to zero leaves. While the Portal cannot
    /// say whether bond cleanup is pending, an `add-stake` is not sent into
    /// it: Kontor would refuse it, for the price of its gas, every hour.
    #[test]
    fn no_top_up_on_an_empty_bond_while_cleanup_is_unknown() {
        let policy = StakePolicy::default();
        let mut unknown = snapshot("1000", "0");
        unknown.bond_cleanup_pending = None;
        assert_eq!(top_up_amount(&policy, &unknown), None);

        // Known not to be pending, it goes; and a bond that still holds
        // something cannot be in cleanup, whatever the field says.
        unknown.bond_cleanup_pending = Some(false);
        assert_eq!(top_up_amount(&policy, &unknown), Some(kor("995")));
        let mut bonded = snapshot("1000", "10");
        bonded.bond_cleanup_pending = None;
        assert_eq!(top_up_amount(&policy, &bonded), Some(kor("995")));

        // Through the tracker: a fresh read with the field unread plans
        // nothing, the next one that reads it does.
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut read = entry(Some("0"), Some("0"));
        read.bond_cleanup_pending = None;
        observed(&tracker, &read, t0);
        assert_eq!(tracker.plan(t0, None), None);
        read.bond_cleanup_pending = Some(false);
        observed(&tracker, &read, t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("995"))));
    }
    /// The Portal reads the reservation from another contract than the bond.
    /// When that one view fails it sends `stake_reserved` and
    /// `stake_available` as `null` — and the node used to drop the whole
    /// snapshot: no top-up, no claim, the exit paused, and `/admin` answering
    /// "stake not reported yet", for as long as that view kept failing. Only
    /// joins need the unreserved part, and only joins wait for it.
    #[test]
    fn a_bond_whose_unreserved_part_is_not_reported_only_closes_joins() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        let mut read = entry(Some("10"), None);
        read.reward_balance = Some("3".into());
        observed(&tracker, &read, t0);

        let status = tracker.status();
        assert_eq!(status["reported"], true);
        assert_eq!(status["stake"], "10");
        assert_eq!(status["available"], Value::Null);
        assert!(tracker.snapshot().is_some(), "/admin can act on it");
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown)
        );
        assert_eq!(
            tracker.plan(t0, None),
            Some(NodeOp::AddStake(kor("995"))),
            "the top-up does not read the reservation"
        );

        // Nor does the exit.
        let tracker = StakeTracker::new(StakePolicy::default());
        let mut exiting = exiting_entry(10, "100");
        exiting.stake_available = None;
        observed(&tracker, &exiting, t0);
        assert!(tracker.exiting());
        let exit = ExitInputs {
            memberships: vec!["AGR-a".into()],
            ..ExitInputs::default()
        };
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into()))
        );
    }
    /// A staking-aware Portal that cannot read the bond from Kontor sends
    /// `"stake": null`; one predating staking sends no such key. Both used to
    /// deserialize to the same thing, so a first read that failed at the
    /// Portal passed for an old Portal: the node joined unmetered, on a bond
    /// nobody had read.
    #[test]
    fn a_null_stake_is_a_portal_that_knows_staking_not_an_old_one() {
        let signer = |stake: Option<Value>| {
            let mut entry = json!({
                "signer_id": 42, "x_only_pubkey": "ab", "bls_pubkey": null,
                "next_nonce": 3, "kor_balance": "10"
            });
            if let Some(stake) = stake {
                entry["stake"] = stake;
                entry["stake_reserved"] = Value::Null;
                entry["stake_available"] = Value::Null;
                entry["stake_withdrawal_height"] = Value::Null;
                entry["bond_cleanup_pending"] = Value::Null;
                entry["reward_balance"] = Value::Null;
            }
            serde_json::from_value::<RegistryEntry>(entry).unwrap()
        };
        let t0 = Instant::now();

        // Every view failed at the Portal: all six fields null.
        let unread = signer(Some(Value::Null));
        assert_eq!(unread.stake.as_deref(), Some(STAKE_UNREAD));
        assert_eq!(StakeSnapshot::from_entry(&unread), None);
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &unread, t0);
        assert_eq!(tracker.status()["portal_reports_stake"], true);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown),
            "not joined blind on a first read that failed"
        );
        assert_eq!(tracker.plan(t0, None), None);

        // No key at all: the pre-staking behaviour.
        let old = signer(None);
        assert_eq!(old.stake, None);
        let tracker = StakeTracker::new(StakePolicy::default());
        observed(&tracker, &old, t0);
        assert_eq!(tracker.status()["portal_reports_stake"], false);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Join {
                collateral: Some(kor("1"))
            }
        );

        // A value still reads as a value.
        assert_eq!(signer(Some(json!("995"))).stake.as_deref(), Some("995"));
    }
    /// One agreement the Portal cannot serve used to fail the whole refresh,
    /// every cycle, and the exit waited behind it. The others are refreshed,
    /// and that row stands until it can be read.
    #[tokio::test]
    async fn one_unreadable_membership_does_not_hold_the_others_back() {
        use crate::testutils::{setup_in_memory_db, AgreementFixture};
        use sea_orm::ActiveModelTrait;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-gone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "agreement_id": "AGR-gone",
                "user_id": "user_1",
                "file_id": "F-AGR-gone",
                "filename": "test.bin",
                "mime_type": "application/octet-stream",
                "original_size": 123,
                "nodes": [{"node_id": "NODE-test", "status": "left"}],
                "transaction_id": null,
                "status": "confirmed",
                "created_at": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let db = setup_in_memory_db().await;
        // `AGR-broken` sorts first: it used to end the loop before `AGR-gone`.
        for id in ["AGR-broken", "AGR-gone"] {
            AgreementFixture {
                status: "confirmed".into(),
                nodes: json!([{"node_id": "NODE-test", "status": "valid"}]),
                ..AgreementFixture::new(id, format!("F-{id}"))
            }
            .into_active_model()
            .insert(&db)
            .await
            .unwrap();
        }
        let client = client_at(&mock_server, 10);

        refresh_memberships(&client, &db, "NODE-test")
            .await
            .expect("an unreadable agreement is not a failed refresh");
        assert_eq!(
            exit_inputs(&db, "NODE-test").await.unwrap().memberships,
            vec!["AGR-broken"],
            "AGR-gone was refreshed; AGR-broken stands as it was"
        );
    }
    fn agreement_detail(id: &str, status: &str, membership: Option<&str>) -> Value {
        let nodes: Vec<Value> = membership
            .map(|status| json!({"node_id": "NODE-test", "status": status}))
            .into_iter()
            .collect();
        json!({
            "agreement_id": id,
            "user_id": "user_1",
            "file_id": format!("F-{id}"),
            "filename": "test.bin",
            "mime_type": "application/octet-stream",
            "original_size": 123,
            "nodes": nodes,
            "transaction_id": null,
            "status": status,
            "created_at": "2024-01-01T00:00:00Z"
        })
    }

    /// A join's collateral used to go back to the budget six hours after it
    /// was sent, whatever the Portal said. The Portal holds a join for as long
    /// as the batch it is in waits to be signed — a day, by default — so the
    /// same stake was then committed to a second join, and Kontor refused
    /// whichever came last. The collateral is now held until the nonce is
    /// consumed or the Portal's rows say the join will not execute: an
    /// agreement that left the ready listing is looked up by its detail.
    #[tokio::test]
    async fn a_join_the_portal_still_holds_keeps_its_collateral_however_long() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        for (id, status, membership) in [
            ("AGR-batched", "pending", Some("valid")),
            ("AGR-retired", "pending", Some("invalid")),
            ("AGR-failed", "failed", Some("valid")),
            ("AGR-rowless", "ready", None),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/api/agreements/{id}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(agreement_detail(id, status, membership)),
                )
                .mount(&mock_server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-unknown"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agreements/AGR-unreadable"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;
        let client = client_at(&mock_server, 10);

        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("100"), Some("100")), t0);
        for id in [
            "AGR-batched",
            "AGR-retired",
            "AGR-failed",
            "AGR-rowless",
            "AGR-unknown",
            "AGR-unreadable",
        ] {
            tracker.record_join(id, kor("10"), 10, t0);
        }
        assert_eq!(
            tracker.joins_to_verify(t0 + Duration::from_secs(60)),
            Vec::<String>::new(),
            "too early to ask"
        );

        // Half an hour on, the Portal's rows are read.
        let check = t0 + OP_LANDING_CHECK_INTERVAL;
        settle_overdue_joins(&client, &tracker, check).await;
        let mut held = tracker.pending_join_agreements();
        held.sort();
        assert_eq!(held, vec!["AGR-batched", "AGR-unreadable"]);

        // A day later the batch is still unsigned, and the join still held.
        let mut at = check;
        while at < t0 + Duration::from_secs(30 * 60 * 60) {
            at += OP_LANDING_CHECK_INTERVAL;
            observed(&tracker, &entry(Some("100"), Some("100")), at);
            settle_overdue_joins(&client, &tracker, at).await;
        }
        let mut held = tracker.pending_join_agreements();
        held.sort();
        assert_eq!(
            held,
            vec!["AGR-batched", "AGR-unreadable"],
            "after 30 hours"
        );
        assert_eq!(
            tracker.join_budget(at).decide(false, Some(Some("90"))),
            JoinDecision::Skip(SkipReason::InsufficientCollateral),
            "20 of the 100 are still committed"
        );

        // One the Portal cannot be asked about for two days is given up; one
        // it vouches for never is.
        let late = t0 + JOIN_COMMITMENT_BACKSTOP;
        settle_overdue_joins(&client, &tracker, late).await;
        assert_eq!(tracker.pending_join_agreements(), vec!["AGR-batched"]);

        // Executed: the nonce releases it, as before.
        let mut landed = entry(Some("100"), Some("90"));
        landed.next_nonce = Some(11);
        observed(&tracker, &landed, late);
        assert!(tracker.pending_join_agreements().is_empty());
    }
    /// A node whose bond came back bonds nothing more on its own. That lived
    /// in memory only: restarted unattended — a crash, a host reboot — with
    /// auto-stake on, it bonded the whole returned balance again, and the
    /// operator was two weeks from withdrawing it once more. The exit is now
    /// recorded in the database, read before anything is planned, and kept
    /// until the operator resumes staking.
    #[tokio::test]
    async fn a_finished_exit_survives_a_restart_until_staking_is_resumed() {
        use crate::entities::prelude::NodeState;
        use crate::testutils::setup_in_memory_db;
        use sea_orm::EntityTrait;

        let db = setup_in_memory_db().await;
        let t0 = Instant::now();
        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = Some(13);
        withdrawn.kor_balance = Some("1005".into());

        // The process that saw the exit through.
        let first = StakeTracker::default();
        restore_withdrawal_start(&db, &first, t0).await.unwrap();
        observed(&first, &exiting_entry(12, "1000"), t0);
        persist_withdrawal_start(&db, &first).await.unwrap();
        observed(&first, &withdrawn, t0);
        assert_eq!(first.status()["exited"], true);
        persist_withdrawal_start(&db, &first).await.unwrap();
        assert!(NodeState::find_by_id(EXITED_AT)
            .one(&db)
            .await
            .unwrap()
            .is_some());

        // The next one: 1005 KOR liquid, auto-stake on, nothing bonded.
        let second = StakeTracker::default();
        observed(&second, &withdrawn, t0);
        assert_eq!(
            second.plan(t0, None),
            None,
            "nothing is bonded before the record has been read"
        );
        restore_withdrawal_start(&db, &second, t0).await.unwrap();
        observed(&second, &withdrawn, t0);
        assert_eq!(second.status()["exited"], true);
        assert_eq!(second.plan(t0, None), None, "the exit stands");
        assert_eq!(second.exited_to_persist(), None, "already on record");

        // The operator resumes: the policy bonds again, and the record goes.
        assert!(
            StakeTracker::default().resume_staking().is_err(),
            "not exited"
        );
        second.resume_staking().unwrap();
        assert_eq!(second.plan(t0, None), Some(NodeOp::AddStake(kor("1000"))));
        persist_withdrawal_start(&db, &second).await.unwrap();
        assert!(NodeState::find_by_id(EXITED_AT)
            .one(&db)
            .await
            .unwrap()
            .is_none());

        // And a third process stakes like any other.
        let third = StakeTracker::default();
        restore_withdrawal_start(&db, &third, t0).await.unwrap();
        observed(&third, &withdrawn, t0);
        assert_eq!(third.status()["exited"], false);
        assert_eq!(third.plan(t0, None), Some(NodeOp::AddStake(kor("1000"))));
    }

    /// A record of an exit on a node that has a stake bonded and no
    /// withdrawal pending is older than that stake: it no longer holds, and
    /// is cleared.
    #[test]
    fn a_recorded_exit_older_than_the_stake_is_dropped() {
        let t0 = Instant::now();
        let mut bonded = entry(Some("100"), Some("100"));
        bonded.kor_balance = Some("105".into());

        let tracker = StakeTracker::default();
        tracker.restore_exited(true);
        assert_eq!(tracker.status()["exited"], true);
        observed(&tracker, &bonded, t0);
        assert_eq!(tracker.status()["exited"], false);
        assert_eq!(
            tracker.exited_to_persist(),
            Some(false),
            "the row is cleared"
        );
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::AddStake(kor("100"))));

        // Read first, restored after.
        let later = StakeTracker::default();
        observed(&later, &bonded, t0);
        later.restore_exited(true);
        assert_eq!(later.status()["exited"], false);
        assert_eq!(later.exited_to_persist(), Some(false));
    }
    fn memberships(count: usize) -> ExitInputs {
        ExitInputs {
            memberships: (0..count).map(|i| format!("AGR-{i:04}")).collect(),
            ..ExitInputs::default()
        }
    }

    /// The exit used to keep one leave in flight: the next was signed only
    /// once the last had its nonce consumed, one per block at best. A node
    /// with a few thousand memberships could not leave them within Kontor's
    /// 2028-block delay, and kept proving — and risking slashes — for as many
    /// blocks as it had memberships. Leaves now go out while others are in
    /// flight, up to a bound, and nothing else does.
    #[test]
    fn the_exit_keeps_several_leaves_in_flight_and_nothing_else() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = memberships(MAX_LEAVES_IN_FLIGHT + 2);

        let mut nonce = 10;
        let mut sent = Vec::new();
        while let Some(op) = tracker.plan(t0, Some(&exit)) {
            let NodeOp::LeaveAgreement(id) = &op else {
                panic!("only leaves while leaves are in flight: {op:?}");
            };
            assert!(!sent.contains(id), "{id} is left once");
            sent.push(id.clone());
            tracker.record_sent(op, nonce, t0);
            nonce += 1;
        }
        assert_eq!(sent.len(), MAX_LEAVES_IN_FLIGHT, "bounded");
        assert_eq!(tracker.status()["in_flight_count"], MAX_LEAVES_IN_FLIGHT);

        // Half of them execute: the next ones go out, the same ones do not.
        let half = (MAX_LEAVES_IN_FLIGHT / 2) as u64;
        observed(&tracker, &exiting_entry(10 + half, "100"), t0);
        let listing: Vec<NodeOpRecord> = (10..10 + half)
            .map(|nonce| leave_record(nonce, "confirmed", None))
            .collect();
        for landed in tracker.ops_to_classify() {
            tracker.classify_landed(landed, Ok(listing.clone()), t0);
        }
        assert_eq!(tracker.status()["exit"]["left"], half);
        let next = tracker.plan(t0, Some(&exit)).unwrap();
        assert!(
            matches!(&next, NodeOp::LeaveAgreement(id) if !sent.contains(id)),
            "{next:?}"
        );

        // No withdrawal while a leave is still out, however late it is.
        let due = t0 + ASSUMED_BLOCK_TIME * WITHDRAWAL_DELAY_BLOCKS as u32;
        let done = ExitInputs::default();
        assert_eq!(tracker.plan(due, Some(&done)), None);
    }

    /// The operator's request goes next and alone: with leaves in flight no
    /// further leave is signed, and the request waits for them to land.
    #[test]
    fn an_operator_request_waits_for_the_leaves_in_flight_and_stops_new_ones() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = memberships(3);
        let first = tracker.plan(t0, Some(&exit)).unwrap();
        tracker.record_sent(first, 10, t0);

        tracker.request(NodeOp::WithdrawStake).unwrap();
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            None,
            "no leave behind a request"
        );
        observed(&tracker, &exiting_entry(11, "100"), t0);
        assert_eq!(tracker.plan(t0, Some(&exit)), Some(NodeOp::WithdrawStake));
    }

    /// Through the relay: one cycle signs several leaves, each at its own
    /// nonce, and stops at the cycle's bound.
    #[tokio::test]
    async fn a_cycle_of_the_exit_sends_several_leaves() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ops_page(json!([]))))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/NODE-test/ops"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({
                "op": "leave_agreement", "status": "queued"
            })))
            .expect(MAX_LEAVES_PER_CYCLE as u64)
            .mount(&mock_server)
            .await;
        let client = client_at(&mock_server, 10);
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let exit = memberships(MAX_LEAVES_PER_CYCLE + 3);

        let first = manage_stake(&client, &tracker, Some(&exit)).await;
        assert_eq!(first, Some(NodeOp::LeaveAgreement("AGR-0000".into())));
        assert_eq!(tracker.status()["in_flight_count"], MAX_LEAVES_PER_CYCLE);
        assert_eq!(
            client.current_nonce(),
            Some(10 + MAX_LEAVES_PER_CYCLE as u64),
            "one nonce each"
        );
    }

    /// A restart during the exit finds several leaves still held by the
    /// Portal. Every one is adopted — only the newest used to be — so none is
    /// signed a second time.
    #[test]
    fn every_op_the_portal_holds_is_adopted_not_only_the_newest() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &exiting_entry(10, "100"), t0);
        let held: Vec<NodeOpRecord> = [(10, "AGR-0000"), (11, "AGR-0001")]
            .into_iter()
            .map(|(nonce, id)| {
                let mut record = leave_record(nonce, "queued", None);
                record.agreement_id = Some(id.into());
                record
            })
            .collect();
        assert_eq!(
            tracker.adopt_pending_ops(&held, t0),
            Some((NodeOp::LeaveAgreement("AGR-0001".into()), 11))
        );
        assert_eq!(tracker.status()["in_flight_count"], 2);
        assert_eq!(tracker.highest_tracked_nonce(), Some(11));

        let exit = memberships(3);
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-0002".into())),
            "the two the Portal holds are not signed again"
        );
        // Adopting the same listing again changes nothing.
        assert_eq!(tracker.adopt_pending_ops(&held, t0), None);
        assert_eq!(tracker.status()["in_flight_count"], 2);
    }
}
