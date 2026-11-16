//! KOR balance check and faucet request, at startup and from the daemon.
//!
//! After onboarding completes, ensures a node that has never been funded gets
//! some KOR. If the registry shows no liquid balance *and* no bonded stake,
//! this module calls the public Portal faucet endpoint and polls the registry
//! until a balance appears on-chain. If the faucet is unavailable, it logs a
//! warning and continues to poll, waiting for a manual transfer.
//!
//! An empty liquid balance alone does not mean unfunded: once auto-stake has
//! bonded everything above the gas reserve and the reserve has gone on fees,
//! liquid `0` is a staked node's normal state. Asking the faucet then, on every
//! restart, would be one request per restart — and on a `502`/`503` the poll
//! would keep the daemon from starting while the node's challenges expire. So
//! a node with a bonded stake is not funded again, and one whose stake the
//! Portal does not report asks the faucet once but never waits for it.
//!
//! A balance the Portal could not read (`null`, Portal
//! `docs/node-portal-contract.md` §3) is not an empty one, and startup does
//! not ask the faucet on it. Startup is not the only chance, though: the
//! daemon hands every registry entry it reads to [`fund_if_unfunded`], which
//! asks as soon as a read shows an empty balance and no stake — a new node
//! whose first read failed is funded by a later one.
//!
//! One [`Faucet`] is shared by startup and the daemon, and it remembers when
//! it last asked: the faucet is a transfer on chain, a block or more in the
//! making, so a second request while the first may still be in flight —
//! after a client-side timeout, on an activation retry — would be a second
//! transfer. It is asked again only after [`FAUCET_RETRY_INTERVAL`].
//!
//! The amount is configurable (`KONTOR_STORAGE_FAUCET_AMOUNT_KOR`, 1000 by
//! default) because staking changed what "funded" means: the KOR is no longer
//! only gas, it is the collateral every join reserves. The Portal caps the
//! request; a node asking for more than a given Portal allows is told the cap
//! and asks again for exactly that, rather than failing onboarding over it.

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::kor::Kor;
use crate::clients::portal::{FaucetResponse, RegistryEntry};
use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

#[cfg(not(test))]
const KOR_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Shorter interval in unit tests so polling scenarios finish quickly.
#[cfg(test)]
const KOR_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long a faucet request stands before the node asks again.
///
/// The faucet answers with a broadcast, not a balance: the transfer still has
/// to be mined and indexed, and a request whose answer was lost may have been
/// broadcast all the same. An hour is several blocks — long enough that a
/// transfer on its way has landed, short enough that a node whose request
/// went nowhere is not left unfunded for long.
pub const FAUCET_RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How many times startup reads a balance the Portal reports as unknown
/// before starting without it.
const UNKNOWN_BALANCE_READS: u32 = 3;

/// What this node asks the faucet for, and when it last did.
///
/// One per process, shared by every activation and by the daemon, so that
/// neither an activation retry nor a daemon cycle repeats a request another
/// of them has just made.
#[derive(Debug)]
pub struct Faucet {
    amount: Kor,
    last_asked: Mutex<Option<Instant>>,
}

impl Faucet {
    #[must_use]
    pub fn new(amount: Kor) -> Self {
        Self {
            amount,
            last_asked: Mutex::new(None),
        }
    }

    /// Whether a request may go out now: none has yet, or the last one is
    /// older than [`FAUCET_RETRY_INTERVAL`].
    fn may_ask(&self, now: Instant) -> bool {
        self.last_asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|asked| now.duration_since(asked) >= FAUCET_RETRY_INTERVAL)
    }

    fn asked(&self, now: Instant) {
        *self
            .last_asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(now);
    }

    /// The last request is known to have sent nothing: the next one need not
    /// wait.
    fn forget(&self) {
        *self
            .last_asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Ask for the configured amount (or the Portal's cap, if lower), keeping
    /// track of the request.
    ///
    /// The request is on record before it goes out, so that whatever becomes
    /// of the answer — a timeout included — the next caller knows one may be
    /// in flight. It is struck off again only when the failure shows nothing
    /// was sent (see [`nothing_was_sent`]).
    async fn ask(
        &self,
        client: &PortalClient,
        recipient: &str,
        writer: &mut impl Write,
    ) -> Result<FaucetResponse> {
        self.asked(Instant::now());
        let result = request_within_cap(client, recipient, self.amount, writer).await;
        if result.as_ref().is_err_and(nothing_was_sent) {
            self.forget();
        }
        result
    }
}

/// Whether a failed faucet request certainly broadcast nothing.
///
/// A `4xx` is the Portal refusing the request before composing anything, and
/// a connection that was never established carried no request at all. Anything
/// else — a timeout, a `5xx`, an answer that cannot be read — leaves open
/// whether the Portal broadcast the transfer before the failure.
fn nothing_was_sent(err: &anyhow::Error) -> bool {
    if let Some(status) = err.downcast_ref::<HttpStatusError>() {
        return status.status.is_client_error();
    }
    err.downcast_ref::<reqwest::Error>()
        .is_some_and(reqwest::Error::is_connect)
}

/// Returns true when the registry entry's `kor_balance` indicates no KOR
/// (missing, unparsable, or zero).
///
/// Read with [`Kor::parse`], exactly, like every other amount the Portal
/// sends (Portal `docs/node-portal-contract.md` §1) — never through `f64`. A
/// Portal that renders the balance with more than the 18 fractional digits
/// the grammar allows is read to 18: the question here is only whether any
/// KOR is there at all, and dust past the 18th digit does not change it.
fn kor_balance_is_empty(balance: &Option<String>) -> bool {
    parse_balance(balance).is_none_or(Kor::is_zero)
}

/// The balance as the Portal reported it, `None` when it reported none or one
/// that cannot be read.
fn parse_balance(balance: &Option<String>) -> Option<Kor> {
    let raw = balance.as_deref()?.trim();
    Kor::parse(raw)
        .or_else(|err| match raw.split_once('.') {
            Some((whole, frac)) if frac.len() > crate::clients::kor::KOR_DECIMALS => Kor::parse(
                &format!("{whole}.{}", &frac[..crate::clients::kor::KOR_DECIMALS]),
            ),
            _ => Err(err),
        })
        .ok()
}

/// What the registry entry says about whether this node was ever funded,
/// once its liquid balance is known to be empty.
#[derive(Debug, PartialEq, Eq)]
enum Funding {
    /// No stake either, and no exit or cleanup under way: a new node.
    Unfunded,
    /// A bonded stake: funded, its KOR is in the bond.
    Staked(Kor),
    /// The Portal does not report the stake (absent, `null`, unreadable), or
    /// the node is in bond cleanup: it may well be an onboarded node, so its
    /// startup must not wait on the faucet.
    Unknown,
}

fn funding(entry: &RegistryEntry) -> Funding {
    let Some(stake) = entry.stake.as_deref().and_then(|raw| Kor::parse(raw).ok()) else {
        return Funding::Unknown;
    };
    if !stake.is_zero() {
        Funding::Staked(stake)
    } else if entry.bond_cleanup_pending == Some(true) || entry.stake_withdrawal_height.is_some() {
        Funding::Unknown
    } else {
        Funding::Unfunded
    }
}

/// Ensure a node that was never funded has KOR before continuing.
///
/// 1. Fetches the registry entry for `signer_id`.
/// 2. If `kor_balance` is `null` — the Portal could not read it (Portal
///    `docs/node-portal-contract.md` §3: unknown, not zero) — reads it again,
///    [`UNKNOWN_BALANCE_READS`] times in all, then returns without asking the
///    faucet: a node that may well be funded is not funded again. The daemon
///    asks later, once a read shows an empty balance and no stake (see
///    [`fund_if_unfunded`]).
/// 3. If `kor_balance` is already positive, or the node has a bonded stake,
///    returns immediately.
/// 4. If the stake is unknown (see [`Funding::Unknown`]), asks the faucet once
///    and returns without waiting; a faucet error is only a warning.
/// 5. Otherwise — no balance, no stake: a new node — calls the Portal faucet,
///    unless it was asked less than [`FAUCET_RETRY_INTERVAL`] ago:
///    - Success: logs the broadcast txids and polls until the balance appears.
///    - 502/503, a timeout, an unreadable answer: warns and polls anyway — the
///      transfer may be on its way, or a manual one may come.
///    - A refusal (4xx) or a connection that could not be made: propagated.
pub async fn ensure_kor_balance(
    client: &PortalClient,
    signer_id: u64,
    faucet: &Faucet,
    writer: &mut impl Write,
) -> Result<()> {
    let mut entry = client.get_registry_entry(signer_id).await?;
    for _ in 1..UNKNOWN_BALANCE_READS {
        if entry.kor_balance.is_some() {
            break;
        }
        tokio::time::sleep(KOR_POLL_INTERVAL).await;
        match client.get_registry_entry(signer_id).await {
            Ok(again) => entry = again,
            Err(e) => tracing::warn!("could not read the registry entry again: {e:#}"),
        }
    }

    if entry.kor_balance.is_none() {
        writeln!(
            writer,
            "⚠ KOR balance: the Portal could not read it ({UNKNOWN_BALANCE_READS} attempts); \
             starting without asking the faucet. The daemon asks once a read shows an empty \
             balance and no stake"
        )?;
        return Ok(());
    }

    if !kor_balance_is_empty(&entry.kor_balance) {
        let balance = entry.kor_balance.as_deref().unwrap_or("0");
        writeln!(writer, "✓ KOR balance: {balance}")?;
        return Ok(());
    }

    let Some(recipient) = entry.x_only_pubkey.as_deref() else {
        writeln!(
            writer,
            "⚠ KOR balance: 0, and the registry entry carries no x-only key to fund; not asking \
             the faucet"
        )?;
        return Ok(());
    };

    let amount = faucet.amount;
    match funding(&entry) {
        Funding::Staked(stake) => {
            writeln!(
                writer,
                "✓ KOR balance: 0 liquid, {stake} KOR bonded; not asking the faucet"
            )?;
            return Ok(());
        }
        Funding::Unknown => {
            if !faucet.may_ask(Instant::now()) {
                writeln!(
                    writer,
                    "KOR balance: 0, stake not known; the faucet was asked a moment ago, not \
                     asking again"
                )?;
                return Ok(());
            }
            writeln!(
                writer,
                "KOR balance: 0, stake not known → requesting {amount} KOR from the faucet, \
                 without waiting for it…"
            )?;
            match faucet.ask(client, recipient, writer).await {
                Ok(resp) => writeln!(
                    writer,
                    "✓ Faucet broadcast: commit={} reveal={}",
                    resp.commit_txid, resp.reveal_txid
                )?,
                Err(e) => {
                    tracing::warn!("faucet request failed; starting without it: {e:#}");
                    writeln!(writer, "⚠ Faucet request failed; starting without it")?;
                }
            }
            return Ok(());
        }
        Funding::Unfunded => {}
    }

    if faucet.may_ask(Instant::now()) {
        writeln!(
            writer,
            "KOR balance: 0 → requesting {amount} KOR from the faucet…"
        )?;
        match faucet.ask(client, recipient, writer).await {
            Ok(resp) => {
                writeln!(
                    writer,
                    "✓ Faucet broadcast: commit={} reveal={}",
                    resp.commit_txid, resp.reveal_txid
                )?;
            }
            Err(e) if nothing_was_sent(&e) => return Err(e),
            Err(e) => {
                let status = e
                    .downcast_ref::<HttpStatusError>()
                    .map(|s| s.status.as_u16());
                match status {
                    Some(502) | Some(503) => {
                        writeln!(
                            writer,
                            "⚠ Faucet unavailable; waiting for a manual KOR transfer…"
                        )?;
                    }
                    _ => {
                        tracing::warn!(
                            "the faucet request got no usable answer; its transfer may still \
                             have been broadcast: {e:#}"
                        );
                        writeln!(
                            writer,
                            "⚠ Faucet request unanswered; waiting for its transfer, or a manual \
                             one…"
                        )?;
                    }
                }
            }
        }
    } else {
        writeln!(
            writer,
            "KOR balance: 0 → the faucet was already asked; waiting for that transfer…"
        )?;
    }

    poll_until_balance(client, signer_id, recipient, faucet, writer).await
}

/// Ask the faucet for a node the daemon finds unfunded, without waiting.
///
/// Called every cycle with the registry entry the cycle read. It asks when
/// that entry shows a *known* empty balance and a *known* empty stake — a new
/// node — with no exit or bond cleanup under way, and the faucet has not been
/// asked within [`FAUCET_RETRY_INTERVAL`]. That covers the node whose balance
/// the Portal could not read at startup, and the one whose first request went
/// nowhere. Returns whether a request went out.
///
/// Never an error: a faucet that cannot be reached is tried again later, and
/// nothing else in the cycle depends on it.
pub async fn fund_if_unfunded(
    client: &PortalClient,
    entry: &RegistryEntry,
    faucet: &Faucet,
    exiting: bool,
) -> bool {
    if exiting
        || !parse_balance(&entry.kor_balance).is_some_and(Kor::is_zero)
        || funding(entry) != Funding::Unfunded
        || !faucet.may_ask(Instant::now())
    {
        return false;
    }
    let Some(recipient) = entry.x_only_pubkey.as_deref() else {
        return false;
    };
    tracing::info!(
        "No KOR and no stake: requesting {} KOR from the faucet",
        faucet.amount
    );
    match faucet.ask(client, recipient, &mut std::io::sink()).await {
        Ok(resp) => tracing::info!(
            commit = %resp.commit_txid,
            reveal = %resp.reveal_txid,
            "the faucet broadcast the transfer; it is staked once it lands"
        ),
        Err(e) => tracing::warn!("the faucet request failed; asking again in a later cycle: {e:#}"),
    }
    true
}

/// Ask the faucet for `amount`, and once more for the Portal's cap if it says
/// `amount` is above it.
///
/// The Portal answers an oversized request with `400 INVALID_REQUEST` and
/// `amount must be in (0, <cap>], got …` — both the fixed 10 KOR of older
/// Portals and the configurable `PORTAL_FAUCET_MAX_AMOUNT_KOR` of newer ones.
/// Any other 400 is returned as is.
async fn request_within_cap(
    client: &PortalClient,
    recipient: &str,
    amount: Kor,
    writer: &mut impl Write,
) -> Result<FaucetResponse> {
    let err = match client
        .request_faucet(recipient, amount.to_f64_lossy())
        .await
    {
        Ok(resp) => return Ok(resp),
        Err(err) => err,
    };
    let cap = err
        .downcast_ref::<HttpStatusError>()
        .filter(|status| status.status.as_u16() == 400)
        .and_then(|status| status.api_message())
        .and_then(|message| faucet_cap(&message))
        .filter(|cap| *cap < amount);
    let Some(cap) = cap else {
        return Err(err);
    };
    writeln!(
        writer,
        "⚠ This Portal's faucet gives at most {cap} KOR; requesting that instead"
    )?;
    client.request_faucet(recipient, cap.to_f64_lossy()).await
}

/// The cap out of the Portal's `amount must be in (0, <cap>], got …`.
fn faucet_cap(message: &str) -> Option<Kor> {
    let rest = message.split_once("amount must be in (0, ")?.1;
    let cap = rest.split_once(']')?.0;
    Kor::parse_positive(cap).ok()
}

/// Wait for a balance to appear, asking the faucet again each time
/// [`FAUCET_RETRY_INTERVAL`] has passed without one.
async fn poll_until_balance(
    client: &PortalClient,
    signer_id: u64,
    recipient: &str,
    faucet: &Faucet,
    writer: &mut impl Write,
) -> Result<()> {
    write!(writer, "Waiting for KOR balance")?;
    writer.flush()?;
    loop {
        tokio::time::sleep(KOR_POLL_INTERVAL).await;
        // Transient HTTP errors must not kill the process: if main exits, the
        // container is restarted, onboarding sees `kor_balance: 0`, and a
        // brand-new faucet broadcast is fired. A single network hiccup then
        // turns into a runaway loop that floods the Portal with TXs.
        match client.get_registry_entry(signer_id).await {
            Ok(entry) => {
                if !kor_balance_is_empty(&entry.kor_balance) {
                    let balance = entry.kor_balance.as_deref().unwrap_or("0");
                    writeln!(writer)?;
                    writeln!(writer, "✓ KOR balance: {balance}")?;
                    return Ok(());
                }
                write!(writer, ".")?;
                writer.flush()?;
            }
            Err(e) => {
                tracing::warn!("Transient error while polling KOR balance: {e:#}");
                write!(writer, "!")?;
                writer.flush()?;
            }
        }
        // Still nothing an interval after the last request: whatever it
        // broadcast, if anything, did not arrive. A refusal here is only
        // logged — the wait goes on, for the next request or a manual
        // transfer.
        if faucet.may_ask(Instant::now()) {
            match faucet.ask(client, recipient, &mut std::io::sink()).await {
                Ok(resp) => tracing::info!(
                    commit = %resp.commit_txid,
                    reveal = %resp.reveal_txid,
                    "asked the faucet again: the previous request brought no balance"
                ),
                Err(e) => {
                    // Asked and refused: wait out the interval all the same,
                    // rather than ask on every poll.
                    faucet.asked(Instant::now());
                    tracing::warn!("asking the faucet again failed: {e:#}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The entry of a node that holds no stake: what a new node looks like.
    fn registry_entry_json(kor_balance: Option<&str>) -> serde_json::Value {
        json!({
            "signer_id": 42,
            "x_only_pubkey": "abc123",
            "bls_pubkey": "def456",
            "next_nonce": 7,
            "kor_balance": kor_balance,
            "user_id": null,
            "stake": "0",
            "stake_available": "0",
        })
    }

    async fn mount_faucet(mock_server: &MockServer, status: u16, times: u64) {
        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "commit_txid": "c", "reveal_txid": "r", "recipient": "abc123", "amount": 10.0,
                "code": "FAUCET_UNAVAILABLE", "message": "down",
            })))
            .expect(times)
            .mount(mock_server)
            .await;
    }

    /// After staking, liquid 0 is normal. A restart used to ask the faucet
    /// again — and on a 503 wait for it forever, the daemon not started.
    #[tokio::test]
    async fn ensure_kor_balance_does_not_fund_a_staked_node() {
        let mock_server = MockServer::start().await;
        let mut entry = registry_entry_json(Some("0"));
        entry["stake"] = json!("995");
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(entry))
            .expect(1)
            .mount(&mock_server)
            .await;
        mount_faucet(&mock_server, 503, 0).await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("995 KOR bonded"), "{output}");
    }

    /// A stake the Portal does not report — an old Portal, an unreadable value,
    /// a node in bond cleanup — may hide an onboarded node: the faucet is asked
    /// once, and startup does not wait for it, even when it is down.
    #[tokio::test]
    async fn ensure_kor_balance_never_waits_when_the_stake_is_unknown() {
        for (stake, cleanup, faucet) in [
            (json!(null), false, 503u16),
            (json!("garbage"), false, 200),
            (json!("0"), true, 502),
        ] {
            let mock_server = MockServer::start().await;
            let mut entry = registry_entry_json(Some("0"));
            entry["stake"] = stake.clone();
            entry["bond_cleanup_pending"] = json!(cleanup);
            Mock::given(method("GET"))
                .and(path("/api/signers/42"))
                .respond_with(ResponseTemplate::new(200).set_body_json(entry))
                .expect(1)
                .mount(&mock_server)
                .await;
            mount_faucet(&mock_server, faucet, 1).await;

            let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
            let mut buffer = Vec::new();
            ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
                .await
                .unwrap_or_else(|e| panic!("{stake} {cleanup}: {e:#}"));
            let output = String::from_utf8(buffer).unwrap();
            assert!(output.contains("without waiting"), "{output}");
            assert!(!output.contains("Waiting for KOR balance"), "{output}");
        }
    }

    /// A `kor_balance` the Portal could not read is not an empty one: it is
    /// read again a few times, and if it stays unknown the faucet is not
    /// asked and startup does not wait.
    #[tokio::test]
    async fn ensure_kor_balance_does_not_fund_a_node_whose_balance_is_unknown() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
            .expect(u64::from(UNKNOWN_BALANCE_READS))
            .mount(&mock_server)
            .await;
        mount_faucet(&mock_server, 200, 0).await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("could not read it"), "{output}");
        assert!(
            output.contains("The daemon asks once a read shows an empty balance"),
            "{output}"
        );
        assert!(!output.contains("faucet…"), "{output}");
        assert!(!output.contains("Waiting for KOR balance"), "{output}");
    }

    /// One unreadable balance at startup does not leave a new node unfunded:
    /// the next read shows the empty balance, and the faucet is asked.
    #[tokio::test]
    async fn ensure_kor_balance_reads_an_unknown_balance_again_before_giving_up() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        mount_faucet(&mock_server, 200, 1).await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("1000"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("from the faucet"), "{output}");
        assert!(output.contains("✓ KOR balance: 1000"), "{output}");
    }

    fn entry(value: serde_json::Value) -> RegistryEntry {
        serde_json::from_value(value).unwrap()
    }

    /// The daemon's half: a node the Portal reports with a known empty
    /// balance and a known empty stake — what a new node looks like once the
    /// Portal can read it — is funded by the cycle that sees it, once.
    #[tokio::test]
    async fn the_daemon_funds_a_node_it_reads_as_new_and_only_once() {
        let mock_server = MockServer::start().await;
        mount_faucet(&mock_server, 200, 1).await;
        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let faucet = Faucet::new(Kor::whole(1000));
        let new_node = entry(registry_entry_json(Some("0")));

        assert!(fund_if_unfunded(&client, &new_node, &faucet, false).await);
        // The next cycles read the same entry until the transfer lands.
        assert!(!fund_if_unfunded(&client, &new_node, &faucet, false).await);
        assert!(!fund_if_unfunded(&client, &new_node, &faucet, false).await);
    }

    /// Nothing but a known empty balance with a known empty stake is a new
    /// node: an unknown balance, an unknown stake, a bond, a cleanup, an exit
    /// — none of them is funded from the daemon.
    #[tokio::test]
    async fn the_daemon_funds_only_a_node_known_to_be_empty() {
        let mock_server = MockServer::start().await;
        mount_faucet(&mock_server, 200, 0).await;
        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let faucet = Faucet::new(Kor::whole(1000));

        let unknown_balance = entry(registry_entry_json(None));
        let unreadable_balance = entry(registry_entry_json(Some("garbage")));
        let funded = entry(registry_entry_json(Some("3")));
        let mut staked = registry_entry_json(Some("0"));
        staked["stake"] = json!("995");
        let mut unknown_stake = registry_entry_json(Some("0"));
        unknown_stake["stake"] = json!(null);
        let mut cleanup = registry_entry_json(Some("0"));
        cleanup["bond_cleanup_pending"] = json!(true);
        let mut withdrawing = registry_entry_json(Some("0"));
        withdrawing["stake_withdrawal_height"] = json!(900_000);
        let mut keyless = registry_entry_json(Some("0"));
        keyless["x_only_pubkey"] = json!(null);

        for (what, value) in [
            ("unknown balance", unknown_balance),
            ("unreadable balance", unreadable_balance),
            ("funded", funded),
            ("staked", entry(staked)),
            ("unknown stake", entry(unknown_stake)),
            ("bond cleanup", entry(cleanup)),
            ("withdrawing", entry(withdrawing)),
            ("no x-only key", entry(keyless)),
        ] {
            assert!(
                !fund_if_unfunded(&client, &value, &faucet, false).await,
                "{what} must not be funded"
            );
        }
        let new_node = entry(registry_entry_json(Some("0")));
        assert!(
            !fund_if_unfunded(&client, &new_node, &faucet, true).await,
            "an exiting node must not be funded"
        );
    }

    /// A request the Portal refused sent nothing, so the next cycle may ask
    /// again; one that failed any other way may have been broadcast, and
    /// stands for the retry interval.
    #[tokio::test]
    async fn the_daemon_asks_again_at_once_only_after_a_refusal() {
        let new_node = entry(registry_entry_json(Some("0")));

        let refusing = MockServer::start().await;
        mount_faucet(&refusing, 429, 2).await;
        let client = PortalClient::try_new(refusing.uri(), std::env::temp_dir()).unwrap();
        let faucet = Faucet::new(Kor::whole(1000));
        assert!(fund_if_unfunded(&client, &new_node, &faucet, false).await);
        assert!(fund_if_unfunded(&client, &new_node, &faucet, false).await);

        let failing = MockServer::start().await;
        mount_faucet(&failing, 500, 1).await;
        let client = PortalClient::try_new(failing.uri(), std::env::temp_dir()).unwrap();
        let faucet = Faucet::new(Kor::whole(1000));
        assert!(fund_if_unfunded(&client, &new_node, &faucet, false).await);
        assert!(!fund_if_unfunded(&client, &new_node, &faucet, false).await);
    }

    #[test]
    fn the_faucet_may_be_asked_again_after_the_retry_interval() {
        let faucet = Faucet::new(Kor::whole(1000));
        let start = Instant::now();
        assert!(faucet.may_ask(start));
        faucet.asked(start);
        assert!(!faucet.may_ask(start + FAUCET_RETRY_INTERVAL - Duration::from_secs(1)));
        assert!(faucet.may_ask(start + FAUCET_RETRY_INTERVAL));
        faucet.asked(start);
        faucet.forget();
        assert!(faucet.may_ask(start));
    }

    /// A faucet request whose answer never came may still have been
    /// broadcast. The activation retry that follows used to ask again, every
    /// time, each one a new transfer; it now waits for the first.
    #[tokio::test]
    async fn an_unanswered_faucet_request_is_not_repeated_by_the_next_activation() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(3)
            .mount(&mock_server)
            .await;
        // A 500: the Portal failed somewhere after taking the request.
        mount_faucet(&mock_server, 500, 1).await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("1000"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let faucet = Faucet::new(Kor::whole(1000));

        // First activation: asks, gets no usable answer, and waits.
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &faucet, &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("Faucet request unanswered"), "{output}");
        assert!(output.contains("✓ KOR balance: 1000"), "{output}");

        // A second activation in the same process, the balance not there yet.
        let second = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(2)
            .mount(&second)
            .await;
        mount_faucet(&second, 200, 0).await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("1000"))),
            )
            .mount(&second)
            .await;
        let client = PortalClient::try_new(second.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &faucet, &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("already asked"), "{output}");
    }

    #[test]
    fn only_a_refusal_or_a_failed_connection_is_known_to_have_sent_nothing() {
        let status = |code: u16| {
            anyhow::Error::new(HttpStatusError {
                status: reqwest::StatusCode::from_u16(code).unwrap(),
                body: String::new(),
                context: "request faucet".to_string(),
            })
        };
        assert!(nothing_was_sent(&status(400)));
        assert!(nothing_was_sent(&status(429)));
        assert!(!nothing_was_sent(&status(500)));
        assert!(!nothing_was_sent(&status(502)));
        assert!(!nothing_was_sent(&status(503)));
        assert!(!nothing_was_sent(&anyhow::anyhow!("timed out")));
    }

    #[test]
    fn kor_balance_is_empty_handles_all_cases() {
        assert!(kor_balance_is_empty(&None));
        assert!(kor_balance_is_empty(&Some("".to_string())));
        assert!(kor_balance_is_empty(&Some("0".to_string())));
        assert!(kor_balance_is_empty(&Some("0.0".to_string())));
        assert!(kor_balance_is_empty(&Some("-1".to_string())));
        assert!(kor_balance_is_empty(&Some("not-a-number".to_string())));
        assert!(!kor_balance_is_empty(&Some("1".to_string())));
        assert!(!kor_balance_is_empty(&Some("0.5".to_string())));
        assert!(!kor_balance_is_empty(&Some("10.0".to_string())));
        // Exact, not through a float: a balance of one unit is a balance.
        assert!(!kor_balance_is_empty(&Some(
            "0.000000000000000001".to_string()
        )));
        // A Portal rendering past the 18th digit is read to the 18th.
        assert!(!kor_balance_is_empty(&Some(
            "0.0000000000000000015".to_string()
        )));
        assert!(kor_balance_is_empty(&Some(
            "0.0000000000000000005".to_string()
        )));
    }

    #[tokio::test]
    async fn ensure_kor_balance_skips_when_balance_present() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("5.0"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();

        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("✓ KOR balance: 5.0"),
            "expected balance line, got: {output}"
        );
        assert!(
            !output.contains("from the faucet"),
            "should not call faucet when balance present: {output}"
        );

        let requests = mock_server.received_requests().await.unwrap();
        assert!(
            requests.iter().all(|r| !r.url.path().contains("/faucet")),
            "no faucet request should be sent"
        );
    }

    #[tokio::test]
    async fn ensure_kor_balance_calls_faucet_then_polls() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "commit_txid": "c0ffee",
                "reveal_txid": "decaf0",
                "recipient": "abc123",
                "amount": 10.0,
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("10.0"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();

        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("from the faucet"), "got: {output}");
        assert!(
            output.contains("commit=c0ffee reveal=decaf0"),
            "got: {output}"
        );
        assert!(output.contains("✓ KOR balance: 10.0"), "got: {output}");
    }

    #[tokio::test]
    async fn ensure_kor_balance_handles_faucet_unavailable() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "code": "FAUCET_UNAVAILABLE",
                "message": "Portal launched without --auto-sign",
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("3.0"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();

        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("Faucet unavailable"),
            "expected warning, got: {output}"
        );
        assert!(output.contains("✓ KOR balance: 3.0"), "got: {output}");
    }

    #[tokio::test]
    async fn ensure_kor_balance_handles_faucet_failed() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .respond_with(ResponseTemplate::new(502).set_body_json(json!({
                "code": "FAUCET_FAILED",
                "message": "broadcast failed",
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("7.0"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();

        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("Faucet unavailable"),
            "expected warning, got: {output}"
        );
        assert!(output.contains("✓ KOR balance: 7.0"), "got: {output}");
    }

    #[tokio::test]
    async fn ensure_kor_balance_propagates_other_faucet_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "code": "INVALID_REQUEST",
                "message": "bad payload",
            })))
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();

        let err = ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("status 400"),
            "expected 400 propagated, got: {err}"
        );
    }

    #[test]
    fn faucet_cap_reads_the_portal_message() {
        assert_eq!(
            faucet_cap("amount must be in (0, 10], got 1000"),
            Some(Kor::whole(10))
        );
        assert_eq!(
            faucet_cap("amount must be in (0, 250.5], got 1000"),
            Some(Kor::parse("250.5").unwrap())
        );
        assert_eq!(faucet_cap("recipient must be 64 hex characters"), None);
        assert_eq!(faucet_cap("amount must be in (0, oops], got 1"), None);
    }

    /// The configured amount goes out as the request's number.
    #[tokio::test]
    async fn ensure_kor_balance_requests_the_configured_amount() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .and(wiremock::matchers::body_json(json!({
                "recipient": "abc123",
                "amount": 250.5
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "commit_txid": "c", "reveal_txid": "r", "recipient": "abc123", "amount": 250.5,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("250.5"))),
            )
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(
            &client,
            42,
            &Faucet::new(Kor::parse("250.5").unwrap()),
            &mut buffer,
        )
        .await
        .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("requesting 250.5 KOR"), "{output}");
    }

    /// A Portal that caps lower than the node asks is asked again for its cap,
    /// instead of failing onboarding — the old 10 KOR Portal is one.
    #[tokio::test]
    async fn ensure_kor_balance_falls_back_to_the_portal_cap() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("0"))))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .and(wiremock::matchers::body_partial_json(
                json!({"amount": 1000.0}),
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "amount must be in (0, 10], got 1000",
                    "status": 400
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/faucet"))
            .and(wiremock::matchers::body_partial_json(
                json!({"amount": 10.0}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "commit_txid": "c", "reveal_txid": "r", "recipient": "abc123", "amount": 10.0,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(Some("10"))))
            .mount(&mock_server)
            .await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, &Faucet::new(Kor::whole(1000)), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("gives at most 10 KOR"), "{output}");
        assert!(output.contains("✓ KOR balance: 10"), "{output}");
    }
}
