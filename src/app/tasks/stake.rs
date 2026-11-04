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
//!   its agreements one op per cycle and, when none is left, withdraws the bond
//!   (see [`ExitInputs`]).
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
//! burning gas each block. What the in-flight rule prevents is the other
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
//! `failed`. A listing that cannot be read leaves it in flight, up to
//! [`OP_LANDING_HARD_TIMEOUT`]. Giving an op up too early is the expensive
//! mistake here: the same `add-stake` signed again with a fresh nonce makes
//! both execute, and the bond overshoots its target. The same listing settles
//! an op whose answer never came — the request timed out, or the Portal
//! answered with a 5xx: the Portal may well hold it, so it is kept in flight
//! like one it accepted, not signed again.
//!
//! # Why the op goes out last
//!
//! The daemon sends its stake op at the end of the cycle, after joins and
//! proofs, so it holds the cycle's highest nonce. Should two ops ever collide
//! on a nonce, the Portal keeps the one it composes first and drops the other;
//! a dropped proof is a slash, a dropped `add-stake` is a retry. Losing is cheap
//! for stake ops, and this ordering keeps it that way.
//!
//! # Old Portals
//!
//! A Portal predating staking sends none of the signer stake fields (Portal
//! `docs/node-portal-contract.md` §3). That is not "zero stake": the node then
//! keeps its pre-staking behaviour — joins everything, signs no stake op. Once
//! a Portal *has* reported a stake, a cycle where the entry cannot be read
//! joins nothing rather than joining blind.

use crate::app::tasks::getnewagreements::ReadyListing;
use crate::clients::http_helpers::status_and_code;
use crate::clients::kontor_op::DEFAULT_GAS_LIMIT;
use crate::clients::kor::Kor;
use crate::clients::portal::{NodeOp, NodeOpRecord, RegistryEntry, UnsettledOp};
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

/// How long an accepted op stays in flight at the outside, whatever the Portal
/// says or fails to say about it. A Portal that lists an op as queued for this
/// long, or cannot be asked for this long, has lost it for all the node can
/// tell; it is then decided again. A join's committed collateral is held for
/// the same length at most (see [`settle_pending_joins`]).
pub const OP_LANDING_HARD_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);

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
    /// What new joins can still reserve.
    pub available: Kor,
    /// Non-null once `begin-unstake` has executed.
    pub withdrawal_height: Option<u64>,
    pub bond_cleanup_pending: bool,
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
    /// falls back to `stake − stake_reserved` when only those two are sent; an
    /// entry with neither is treated as not reporting a stake at all, because
    /// joining against a stake whose reservations are unknown is joining blind.
    #[must_use]
    pub fn from_entry(entry: &RegistryEntry) -> Option<Self> {
        let stake = parse_field("stake", entry.stake.as_deref())?;
        let reserved = parse_field("stake_reserved", entry.stake_reserved.as_deref());
        let available = parse_field("stake_available", entry.stake_available.as_deref())
            .or_else(|| reserved.map(|reserved| stake.saturating_sub(reserved)))?;

        Some(Self {
            kor_balance: parse_field("kor_balance", entry.kor_balance.as_deref()),
            stake,
            reserved,
            available,
            withdrawal_height: entry.stake_withdrawal_height,
            bond_cleanup_pending: entry.bond_cleanup_pending.unwrap_or(false),
            reward_balance: parse_field("reward_balance", entry.reward_balance.as_deref()),
            next_nonce: entry.next_nonce,
        })
    }

    /// Why this bond cannot take on a new agreement at all, if it cannot.
    fn join_blocker(&self) -> Option<SkipReason> {
        if self.bond_cleanup_pending {
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
#[must_use]
pub fn top_up_amount(policy: &StakePolicy, snapshot: &StakeSnapshot) -> Option<Kor> {
    if snapshot.bond_cleanup_pending || snapshot.withdrawal_height.is_some() {
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

/// An op the relay accepted and Kontor has not executed yet.
#[derive(Clone, Debug)]
struct InFlight {
    op: NodeOp,
    nonce: u64,
    sent: Instant,
    sent_at: DateTime<Utc>,
    /// When the Portal's listing was last asked about it.
    checked: Option<Instant>,
}

/// A join sent but not yet executed: its collateral is not in `stake_reserved`
/// yet, so it is held back from the budget until the nonce says it is.
#[derive(Clone, Debug)]
struct PendingJoin {
    agreement_id: String,
    collateral: Kor,
    nonce: u64,
    sent: Instant,
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
    in_flight: Option<InFlight>,
    pending_joins: Vec<PendingJoin>,
    last_claim: Option<Instant>,
    /// When the Portal last refused an `add-stake` (`None` key) or a
    /// `leave-agreement` (its agreement).
    refused: HashMap<RefusedOp, Instant>,
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
    /// The bond came back: the operator left the network. Nothing more is
    /// bonded automatically, whatever auto-stake says.
    exited: bool,
    /// The exit as of the last plan, for `/admin`.
    exit: Option<ExitInputs>,
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
    /// Challenges not resolved yet (`active`, or proved and waiting). Kontor
    /// refuses `withdraw-stake` while any exists.
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
    #[must_use]
    pub fn withdrawal_start_to_persist(&self) -> Option<Option<DateTime<Utc>>> {
        let state = self.lock();
        let wanted = state.withdrawal.map(|timer| timer.started_at);
        (wanted != state.persisted_withdrawal_start).then_some(wanted)
    }

    /// The database now holds `started_at` as the start of the delay.
    pub fn withdrawal_start_persisted(&self, started_at: Option<DateTime<Utc>>) {
        self.lock().persisted_withdrawal_start = started_at;
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
    /// Retires in-flight work whose nonce Kontor has consumed (or that has
    /// waited past [`OP_LANDING_HARD_TIMEOUT`]), and says out loud when the stake
    /// shrank or bond cleanup started — the two things an operator must not
    /// learn from a dashboard a week later.
    pub fn observe(&self, entry: Option<&RegistryEntry>, now: Instant) {
        let snapshot = entry.and_then(StakeSnapshot::from_entry);
        let mut state = self.lock();

        // A `stake` field, readable or not, is a Portal that knows about
        // staking: an entry with the stake but not what is free of it must
        // close this cycle's joins, not pass for an old Portal.
        let reports_stake = entry.is_some_and(|entry| entry.stake.is_some());
        if reports_stake {
            state.portal_reports_stake = true;
        }
        let Some(snapshot) = snapshot else {
            if reports_stake {
                warn!(
                    "the Portal's signer entry reports a stake but not how much of it is \
                     unreserved; joins are paused this cycle"
                );
            } else if entry.is_some() && state.portal_reports_stake {
                warn!("the Portal's signer entry no longer reports a stake; joins are paused");
            }
            state.snapshot = None;
            return;
        };

        let exited_before = state.exited;
        let mut landed = None;
        if let Some(op) = state.in_flight.take() {
            if snapshot.next_nonce > op.nonce {
                info!(
                    op = op.op.name(),
                    nonce = op.nonce,
                    "the {} op has executed on Kontor",
                    op.op.name()
                );
                landed = Some(op.op);
            } else if now.duration_since(op.sent) >= OP_LANDING_HARD_TIMEOUT {
                warn!(
                    op = op.op.name(),
                    nonce = op.nonce,
                    "the {} op is still not reflected after {} hours; giving it up for lost \
                     and deciding again",
                    op.op.name(),
                    OP_LANDING_HARD_TIMEOUT.as_secs() / 3600
                );
            } else {
                state.in_flight = Some(op);
            }
        }

        match &landed {
            Some(NodeOp::LeaveAgreement(agreement_id)) => {
                info!("left agreement {agreement_id}");
                state.left.insert(agreement_id.clone());
            }
            Some(op @ NodeOp::AddStake(amount))
                if state
                    .last_known
                    .as_ref()
                    .is_some_and(|previous| snapshot.stake <= previous.stake) =>
            {
                // Its nonce went, its KOR did not: Kontor refused it for a
                // reason the snapshot and the Portal's pre-check did not see,
                // or another op took the nonce. The same op signed again next
                // cycle meets the same answer, and each attempt costs gas, so
                // it waits as long as one the Portal refused.
                warn!(
                    "add-stake of {amount} KOR executed without raising the bond; not signing \
                     it again for {} hour",
                    REFUSED_OP_RETRY_INTERVAL.as_secs() / 3600
                );
                state.refused.insert(refused_key(op), now);
                state.last_event = Some((
                    Utc::now(),
                    format!("add_stake {amount} KOR executed without raising the bond"),
                ));
            }
            Some(NodeOp::WithdrawStake) if !snapshot.stake.is_zero() => {
                // Executed, and the bond is still there: too early, or an
                // obligation the node's own rows did not show (a leave that
                // failed on chain, say). Forget which leaves "worked" so they
                // are sent again, and retry later.
                warn!(
                    "withdraw-stake executed without returning the bond; leaves will be resent \
                     and the withdrawal retried in {} hours",
                    WITHDRAW_RETRY_INTERVAL.as_secs() / 3600
                );
                state.left.clear();
                state.memberships_refreshed = false;
            }
            Some(NodeOp::WithdrawStake) => state.exited = true,
            _ => {}
        }
        // The snapshot says so too, whether or not the withdrawal is still
        // tracked in flight — one given up as lost has been forgotten by then
        // (see `verify_in_flight`), and auto-stake would re-bond
        // the whole bond it just returned. An exit under way at the last read,
        // and now no bond and no withdrawal pending: the bond came back.
        let was_exiting = state.withdrawal.is_some()
            || state
                .last_known
                .as_ref()
                .is_some_and(|previous| previous.withdrawal_height.is_some());
        if was_exiting && snapshot.stake.is_zero() && snapshot.withdrawal_height.is_none() {
            state.exited = true;
        }
        if state.exited && !exited_before {
            warn!(
                "the bond has been withdrawn: this node bonds nothing more on its own. Set \
                 KONTOR_STORAGE_AUTO_STAKE=false before restarting it, or it will stake again"
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
        // or until its row says it never will (`settle_pending_joins`), with a
        // long time limit behind both for a join the Portal lost without a
        // trace.
        state.pending_joins.retain(|join| {
            snapshot.next_nonce <= join.nonce
                && now.duration_since(join.sent) < OP_LANDING_HARD_TIMEOUT
        });

        if let Some(previous) = &state.last_known {
            let event = describe_transition(previous, &snapshot, landed);
            if let Some(event) = event {
                state.last_event = Some((Utc::now(), event));
            }
        } else if snapshot.bond_cleanup_pending {
            error!(
                "bond cleanup is pending: this node's stake was slashed to zero. It cannot join \
                 or add stake until Kontor finishes unwinding its memberships"
            );
            state.last_event = Some((Utc::now(), "bond cleanup pending".to_string()));
        }

        state.last_known = Some(snapshot.clone());
        state.snapshot = Some(snapshot);
        state.observed_at = Some(Utc::now());
    }

    /// The nonce of the in-flight op the Portal should be asked about this
    /// cycle, if there is one that has waited [`OP_LANDING_CHECK_INTERVAL`]
    /// since it was sent or last asked about.
    #[must_use]
    pub fn op_to_verify(&self, now: Instant) -> Option<u64> {
        let state = self.lock();
        let op = state.in_flight.as_ref()?;
        let since = op.checked.unwrap_or(op.sent);
        (now.duration_since(since) >= OP_LANDING_CHECK_INTERVAL).then_some(op.nonce)
    }

    /// What the Portal's listing of this node's ops says about the in-flight
    /// op at `nonce` (see [`Self::op_to_verify`]).
    ///
    /// Still `queued` or `submitted`: it is waiting for a batch, or in one that
    /// is not confirmed yet, and stays in flight. `confirmed`: it has executed
    /// and the registry read is behind; it stays in flight for the nonce to
    /// say so. `failed`, or missing from the listing: the Portal will never
    /// relay it, so it is given up and the next plan decides again. A listing
    /// that could not be read says nothing, and nothing changes until the next
    /// check or [`OP_LANDING_HARD_TIMEOUT`].
    pub fn verify_in_flight(
        &self,
        nonce: u64,
        listing: anyhow::Result<Vec<NodeOpRecord>>,
        now: Instant,
    ) {
        let mut state = self.lock();
        let Some(op) = state.in_flight.as_mut().filter(|op| op.nonce == nonce) else {
            return;
        };
        op.checked = Some(now);
        let name = op.op.name();
        let listed = match listing {
            Ok(ops) => ops.into_iter().find(|listed| listed.nonce == nonce),
            Err(err) => {
                warn!(
                    "could not ask the Portal about the {name} op at nonce {nonce}; keeping it in \
                     flight: {err:#}"
                );
                return;
            }
        };
        if let Some(other) = listed.as_ref().filter(|listed| listed.op != name) {
            // Another op of this node holds the nonce — the relay's `409`
            // after the fact. Ours was never stored.
            warn!(
                "the Portal holds a {} op, not the {name} op, at nonce {nonce}; the {name} op \
                 was not relayed and is decided again",
                other.op
            );
            state.in_flight = None;
            state.last_event = Some((
                Utc::now(),
                format!("{name} lost nonce {nonce} to a {} op", other.op),
            ));
            return;
        }
        let dropped = match listed.as_ref().map(|listed| listed.status.as_str()) {
            Some("queued" | "submitted") => {
                info!(
                    "the {name} op at nonce {nonce} is still {} at the Portal after {} minutes; \
                     waiting",
                    listed.as_ref().map_or("", |listed| listed.status.as_str()),
                    now.duration_since(op.sent).as_secs() / 60
                );
                return;
            }
            Some("confirmed") => {
                debug!(
                    "the {name} op at nonce {nonce} is confirmed at the Portal; waiting for the \
                     registry to reflect it"
                );
                return;
            }
            Some("failed") => {
                warn!(
                    "the Portal reports the {name} op at nonce {nonce} as failed: {}; deciding \
                     again",
                    listed
                        .as_ref()
                        .and_then(|listed| listed.error.as_deref())
                        .unwrap_or("no error given")
                );
                format!("{name} failed at the Portal (nonce {nonce})")
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
        state.in_flight = None;
        state.last_event = Some((Utc::now(), dropped));
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

    /// The op this cycle should send, if any. At most one: the next waits
    /// until this one has landed.
    ///
    /// `exit` is the daemon's view of its memberships, passed while the node is
    /// [`exiting`](Self::exiting). The exit was started by the operator and is
    /// carried through whatever auto-stake says: leave every membership whose
    /// challenges are settled, one per cycle, then withdraw once none is left
    /// and the delay has (by the node's reckoning) passed.
    #[must_use]
    pub fn plan(&self, now: Instant, exit: Option<&ExitInputs>) -> Option<NodeOp> {
        let mut state = self.lock();
        state.exit = exit.cloned();
        let state = &*state;
        let snapshot = state.snapshot.as_ref()?;
        if state.in_flight.is_some() {
            return None;
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

        if !state.exited {
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
        self.track(op, nonce, now, event);
    }

    /// `op` was signed at `nonce` and sent, and no answer came back that says
    /// whether the Portal kept it (see [`UnsettledOp`]). It is tracked exactly
    /// like one the relay accepted: its nonce is consumed either way, and if
    /// the Portal did store it, signing it again would execute it twice. The
    /// Portal's listing settles it after [`OP_LANDING_CHECK_INTERVAL`] (see
    /// [`Self::verify_in_flight`]) — gone, the plan is made again.
    pub fn record_unsettled(&self, op: NodeOp, nonce: u64, now: Instant) {
        let event = format!("{}; the Portal gave no answer", describe_sent(&op, nonce));
        self.track(op, nonce, now, event);
    }

    fn track(&self, op: NodeOp, nonce: u64, now: Instant, event: String) {
        let mut state = self.lock();
        match op {
            NodeOp::ClaimRewards => state.last_claim = Some(now),
            NodeOp::WithdrawStake => state.last_withdraw = Some(now),
            _ => {}
        }
        if state.operator_request.as_ref() == Some(&op) {
            state.operator_request = None;
        }
        state.last_event = Some((Utc::now(), event));
        state.in_flight = Some(InFlight {
            op,
            nonce,
            sent: now,
            sent_at: Utc::now(),
            checked: None,
        });
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
    /// If `op` is not one an operator may request, or another request is
    /// already waiting.
    pub fn request(&self, op: NodeOp) -> Result<(), &'static str> {
        if !matches!(op, NodeOp::BeginUnstake | NodeOp::WithdrawStake) {
            return Err("only an unstake or a withdrawal can be requested");
        }
        let mut state = self.lock();
        if state.operator_request.is_some() {
            return Err("another request is already waiting for the next cycle");
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
        // not only from the block it executes in.
        let leaving = matches!(state.operator_request, Some(NodeOp::BeginUnstake))
            || state
                .in_flight
                .as_ref()
                .is_some_and(|op| op.op == NodeOp::BeginUnstake);

        let mode = match (&state.snapshot, &state.joins_paused) {
            (None, _) if !state.portal_reports_stake => BudgetMode::Unmetered,
            (None, _) => BudgetMode::Closed(SkipReason::StakeUnknown),
            (Some(_), _) if leaving => BudgetMode::Closed(SkipReason::Leaving),
            (Some(_), Some((_, code))) => {
                BudgetMode::Closed(SkipReason::RecentlyRefused(code.clone()))
            }
            (Some(snapshot), None) => match snapshot.join_blocker() {
                Some(reason) => BudgetMode::Closed(reason),
                None => {
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
                        remaining: snapshot.available.saturating_sub(held),
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
            sent: now,
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
            "available": state.snapshot.as_ref().map(|s| s.available),
            "withdrawal_height": state.snapshot.as_ref().and_then(|s| s.withdrawal_height),
            "bond_cleanup_pending": state.snapshot.as_ref().map(|s| s.bond_cleanup_pending),
            "reward_balance": state.snapshot.as_ref().and_then(|s| s.reward_balance),
            "policy": {
                "auto_stake": policy.auto_stake,
                "gas_reserve": policy.gas_reserve,
                "stake_target": policy.stake_target,
                "claim_threshold": policy.claim_threshold,
            },
            "in_flight": state.in_flight.as_ref().map(|op| json!({
                "op": op.op.name(),
                "amount": op.op.amount(),
                "nonce": op.nonce,
                "sent_at": op.sent_at.to_rfc3339(),
            })),
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

fn describe_sent(op: &NodeOp, nonce: u64) -> String {
    match (op.amount(), op.agreement_id()) {
        (Some(amount), _) => format!("{} {amount} KOR sent (nonce {nonce})", op.name()),
        (None, Some(agreement_id)) => {
            format!("{} {agreement_id} sent (nonce {nonce})", op.name())
        }
        (None, None) => format!("{} sent (nonce {nonce})", op.name()),
    }
}

/// The next step of the exit, if one is due.
fn next_exit_op(state: &TrackerState, exit: &ExitInputs, now: Instant) -> Option<NodeOp> {
    if let Some(agreement_id) = exit.memberships.iter().find(|id| {
        !state.left.contains(*id)
            && !exit.deferred.contains(id)
            && !refused_recently(state, &NodeOp::LeaveAgreement((*id).clone()), now)
    }) {
        return Some(NodeOp::LeaveAgreement(agreement_id.clone()));
    }
    let all_left = exit.memberships.iter().all(|id| state.left.contains(id));
    (all_left && exit.unresolved_challenges == 0 && withdraw_due(state, now))
        .then_some(NodeOp::WithdrawStake)
}

/// The delay has passed by the node's reckoning, and the last automatic
/// attempt is far enough back.
fn withdraw_due(state: &TrackerState, now: Instant) -> bool {
    let Some(timer) = state.withdrawal else {
        return false;
    };
    timer.elapsed(now) >= withdrawal_delay()
        && state
            .last_withdraw
            .is_none_or(|last| now.duration_since(last) >= WITHDRAW_RETRY_INTERVAL)
}

/// Log, and return for the status page, what changed between two reads that
/// the operator has to know about.
fn describe_transition(
    previous: &StakeSnapshot,
    current: &StakeSnapshot,
    landed: Option<NodeOp>,
) -> Option<String> {
    let mut event = None;

    // A bond that went to zero while a withdrawal was pending is the
    // withdrawal completing — whether or not its op is still tracked in
    // flight, which one that landed after the in-flight expiry is not.
    let withdrawn = landed == Some(NodeOp::WithdrawStake)
        || (current.stake.is_zero() && previous.withdrawal_height.is_some());
    if current.stake < previous.stake && !withdrawn {
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

    if current.bond_cleanup_pending && !previous.bond_cleanup_pending {
        error!(
            "bond cleanup is pending: this node's stake was slashed to zero. It cannot join or \
             add stake until Kontor finishes unwinding its memberships"
        );
        event = Some("bond cleanup pending".to_string());
    } else if previous.bond_cleanup_pending && !current.bond_cleanup_pending {
        info!("bond cleanup has finished; the node can add stake and join again");
        event = Some("bond cleanup finished".to_string());
    }

    match (previous.withdrawal_height, current.withdrawal_height) {
        (None, Some(height)) => {
            warn!("withdrawal requested: joins stop, and the stake can be withdrawn from height {height} once no agreement holds it");
            event = Some(format!("withdrawal requested, unlocks at height {height}"));
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
/// and waiting for the verdict.
const UNRESOLVED: [&str; 3] = ["active", "proved", "submitted"];

/// The `node_state` key under which the start of the withdrawal delay is kept,
/// as an RFC 3339 timestamp.
pub const WITHDRAWAL_STARTED_AT: &str = "stake_withdrawal_started_at";

/// Read the start of the withdrawal delay an earlier process recorded, if any,
/// into the tracker. Once per process, before the first cycle's read is acted
/// on.
///
/// # Errors
/// If the row cannot be read; the tracker then still counts from this process
/// and the next cycle tries again.
pub async fn restore_withdrawal_start(
    database: &DatabaseConnection,
    tracker: &StakeTracker,
    now: Instant,
) -> anyhow::Result<()> {
    use crate::entities::prelude::NodeState;
    use sea_orm::EntityTrait;

    let row = NodeState::find_by_id(WITHDRAWAL_STARTED_AT)
        .one(database)
        .await
        .context("reading the start of the withdrawal delay")?;
    let started_at = match row {
        Some(row) => Some(
            DateTime::parse_from_rfc3339(&row.value)
                .with_context(|| format!("unreadable {WITHDRAWAL_STARTED_AT}: {}", row.value))?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    tracker.restore_withdrawal_start(started_at, now);
    Ok(())
}

/// Record the start of the withdrawal delay as the tracker counts it, or clear
/// the record once the withdrawal is over. A no-op while the database already
/// says the same.
///
/// # Errors
/// If the row cannot be written; the next cycle tries again.
pub async fn persist_withdrawal_start(
    database: &DatabaseConnection,
    tracker: &StakeTracker,
) -> anyhow::Result<()> {
    use crate::entities::node_state;
    use crate::entities::prelude::NodeState;
    use sea_orm::{ActiveValue, EntityTrait};

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
/// [`NO_MEMBERSHIP`], or the agreement is no longer `ready`/`pending` by its
/// local row. Behind both, [`StakeTracker::observe`] still releases a join
/// after [`OP_LANDING_HARD_TIMEOUT`].
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
    let mut unlisted = Vec::new();
    for agreement_id in pending {
        match listing.get(&agreement_id) {
            Some(listed) => {
                let mine: Vec<&str> = listed
                    .nodes
                    .iter()
                    .filter(|node| node.node_id == node_id)
                    .map(|node| node.status.as_str())
                    .collect();
                if !mine.is_empty() && mine.iter().all(|status| NO_MEMBERSHIP.contains(status)) {
                    settled.push(agreement_id);
                }
            }
            None => unlisted.push(agreement_id),
        }
    }
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

/// Bring the rows of the memberships the exit acts on up to date with the
/// Portal.
///
/// Reconciliation lists the agreements this node *validly* belongs to
/// (`GET /api/agreements?nodes=`), so once the Portal marks a membership
/// `left` — a confirmed leave — or `invalid` or `failed`, the agreement drops
/// out of that listing and the local row keeps saying `valid`. Before the
/// exit's first step in a process, and again whenever it has to resend its
/// leaves, each membership the rows still show is re-read one by one, and its
/// `nodes` and `status` rewritten. A leave is then never paid for a membership
/// that is already gone.
///
/// # Errors
/// If the rows cannot be read or written, or any agreement cannot be fetched;
/// the exit then waits a cycle rather than act on stale rows.
pub async fn refresh_memberships(
    client: &PortalClient,
    database: &DatabaseConnection,
    node_id: &str,
) -> anyhow::Result<()> {
    use crate::entities::agreements;
    use crate::entities::prelude::Agreements;
    use sea_orm::{ActiveValue, EntityTrait};

    let rows = Agreements::find().all(database).await?;
    for row in rows
        .into_iter()
        .filter(|agreement| !NOT_ON_CHAIN.contains(&agreement.status.as_str()))
        .filter(|agreement| is_live_member(&agreement.nodes, node_id))
    {
        let remote = client
            .get_agreement(&row.agreement_id)
            .await
            .with_context(|| format!("re-reading membership {}", row.agreement_id))?;
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
    let unresolved_challenges = challenges
        .iter()
        .filter(|challenge| UNRESOLVED.contains(&challenge.status.as_str()))
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

/// Apply the policy for this cycle: send at most one stake or claim op.
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
    verify_overdue_op(client, tracker, Instant::now()).await;
    let op = tracker.plan(Instant::now(), exit)?;
    send(client, tracker, op).await
}

/// Ask the Portal about an in-flight op that has waited long enough to be
/// asked about (see [`StakeTracker::verify_in_flight`]).
async fn verify_overdue_op(client: &PortalClient, tracker: &StakeTracker, now: Instant) {
    if let Some(nonce) = tracker.op_to_verify(now) {
        let listing = client.list_node_ops(&[]).await;
        tracker.verify_in_flight(nonce, listing, now);
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
                // nonce, which stays consumed, and the next cycle signs a
                // fresh one.
                Some((409, _)) => {
                    warn!("{} lost its nonce to another op: {err:#}", op.name());
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
/// # Errors
/// Only if the progress line cannot be written.
pub async fn bootstrap_stake(
    client: &PortalClient,
    tracker: &Arc<StakeTracker>,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    let entry = match client.resync_from_registry().await {
        Ok(entry) => entry,
        Err(err) => {
            warn!("could not read the stake at startup; the first cycle will retry: {err:#}");
            return Ok(());
        }
    };
    tracker.observe(Some(&entry), Instant::now());

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
    writeln!(
        writer,
        "✓ Stake: {} KOR bonded, {} KOR unreserved",
        snapshot.stake, snapshot.available
    )?;
    if snapshot.bond_cleanup_pending {
        writeln!(
            writer,
            "⚠ Bond cleanup pending: the stake was slashed to zero; no joins until it finishes"
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
            x_only_pubkey: "ab".into(),
            bls_pubkey: None,
            next_nonce: 10,
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
            available: kor(stake),
            withdrawal_height: None,
            bond_cleanup_pending: false,
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
        // A stake with nothing saying how much of it is free: not enough to
        // join against.
        assert_eq!(StakeSnapshot::from_entry(&entry(Some("10"), None)), None);
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
        assert_eq!(tracker.status()["reported"], false);
        assert_eq!(
            tracker.join_budget(t0).decide(false, Some(Some("1"))),
            JoinDecision::Skip(SkipReason::StakeUnknown)
        );
        assert_eq!(tracker.plan(t0, None), None, "nothing to decide from");

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
        assert_eq!(snapshot.available, kor("69.5"));
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
        cleaning.bond_cleanup_pending = true;
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
        landed.next_nonce = 11;
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
        consumed.next_nonce = 12;
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
        partial.next_nonce = 11;
        partial.kor_balance = Some("500".into());
        observed(&tracker, &partial, soon);
        assert_eq!(tracker.plan(soon, None), Some(NodeOp::AddStake(kor("495"))));
    }

    fn listed_op(op: &str, nonce: u64, status: &str, error: Option<&str>) -> NodeOpRecord {
        NodeOpRecord {
            op: op.into(),
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
                Some("nonce 11 is below the signer's next nonce"),
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

    /// Whatever the Portal says or cannot say, an op is not waited for
    /// beyond the hard timeout.
    #[test]
    fn an_op_that_never_lands_expires_at_the_hard_timeout() {
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
        tracker.record_sent(NodeOp::AddStake(kor("995")), 10, t0);

        let late = t0 + OP_LANDING_HARD_TIMEOUT - Duration::from_secs(1);
        observed(&tracker, &entry(Some("0"), Some("0")), late);
        assert_eq!(tracker.plan(late, None), None);

        let later = t0 + OP_LANDING_HARD_TIMEOUT;
        observed(&tracker, &entry(Some("0"), Some("0")), later);
        assert_eq!(
            tracker.plan(later, None),
            Some(NodeOp::AddStake(kor("995")))
        );
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
        e.next_nonce = 11;
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
        observed(&tracker, &entry(Some("10"), Some("10")), t0);
        assert_eq!(tracker.plan(t0, None), Some(NodeOp::WithdrawStake));
        tracker.record_sent(NodeOp::WithdrawStake, 10, t0);
        assert!(tracker.request(NodeOp::BeginUnstake).is_ok());
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
        landed.next_nonce = 11;
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
    async fn pending_joins_are_released_by_their_rows_or_the_hard_timeout() {
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

        let hour = t0 + Duration::from_secs(60 * 60);
        observed(&tracker, &entry(Some("100"), Some("100")), hour);
        assert_eq!(tracker.pending_join_agreements().len(), 2, "still held");
        observed(
            &tracker,
            &entry(Some("100"), Some("100")),
            t0 + OP_LANDING_HARD_TIMEOUT,
        );
        assert!(tracker.pending_join_agreements().is_empty());
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
        withdrawn.next_nonce = 11;
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
        e.next_nonce = next_nonce;
        e.kor_balance = Some("5".into());
        e.stake_withdrawal_height = Some(5000);
        e
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
        assert_eq!(tracker.plan(t0, Some(&exit)), None, "AGR-a still deferred");

        exit.deferred.clear();
        exit.unresolved_challenges = 0;
        assert_eq!(
            tracker.plan(t0, Some(&exit)),
            Some(NodeOp::LeaveAgreement("AGR-a".into()))
        );
        tracker.record_sent(NodeOp::LeaveAgreement("AGR-a".into()), 11, t0);
        observed(&tracker, &exiting_entry(12, "100"), t0);

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
        withdrawn.next_nonce = 13;
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
        withdrawn.next_nonce = 11;
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
        assert_eq!(tracker.plan(later, Some(&exit)), None, "retry interval");
        assert_eq!(
            tracker.plan(later + WITHDRAW_RETRY_INTERVAL, Some(&exit)),
            Some(NodeOp::WithdrawStake)
        );
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

        // No Portal at all: the same open question, settled the same way.
        let client = client_for("http://127.0.0.1:1".to_string());
        let tracker = StakeTracker::new(StakePolicy::default());
        let t0 = Instant::now();
        observed(&tracker, &entry(Some("0"), Some("0")), t0);
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

        let late = t0 + OP_LANDING_HARD_TIMEOUT + Duration::from_secs(60);
        observed(&tracker, &exiting_entry(12, "100"), late);
        assert_eq!(tracker.status()["in_flight"], Value::Null, "forgotten");

        let mut withdrawn = entry(Some("0"), Some("0"));
        withdrawn.next_nonce = 13;
        withdrawn.kor_balance = Some("105".into());
        observed(&tracker, &withdrawn, late + Duration::from_secs(60));
        assert_eq!(
            tracker.plan(late + Duration::from_secs(60), None),
            None,
            "the returned bond is not staked again"
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
        for (id, agreement, status) in [
            ("c1", "AGR-open", "active"),
            ("c2", "AGR-live", "proved"),
            ("c3", "AGR-live", "resolved"),
            ("c4", "AGR-bare", "failed"),
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
                updated_at: Set(chrono::Utc::now().fixed_offset()),
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
            exit.unresolved_challenges, 2,
            "active and proved-but-unsettled"
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
}
