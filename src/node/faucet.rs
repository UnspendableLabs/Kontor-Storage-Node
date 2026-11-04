//! KOR balance check and faucet request at startup.
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
//! The amount is configurable (`KONTOR_STORAGE_FAUCET_AMOUNT_KOR`, 1000 by
//! default) because staking changed what "funded" means: the KOR is no longer
//! only gas, it is the collateral every join reserves. The Portal caps the
//! request; a node asking for more than a given Portal allows is told the cap
//! and asks again for exactly that, rather than failing onboarding over it.

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::kor::Kor;
use crate::clients::portal::RegistryEntry;
use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::time::Duration;

#[cfg(not(test))]
const KOR_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Shorter interval in unit tests so polling scenarios finish quickly.
#[cfg(test)]
const KOR_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Returns true when the registry entry's `kor_balance` indicates no KOR
/// (missing, unparsable, or non-positive).
fn kor_balance_is_empty(balance: &Option<String>) -> bool {
    match balance {
        None => true,
        Some(s) => s.parse::<f64>().unwrap_or(0.0) <= 0.0,
    }
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
///    `docs/node-portal-contract.md` §3: unknown, not zero) — returns without
///    asking the faucet: a node that may well be funded is not funded again.
/// 3. If `kor_balance` is already positive, or the node has a bonded stake,
///    returns immediately.
/// 4. If the stake is unknown (see [`Funding::Unknown`]), asks the faucet once
///    and returns without waiting; a faucet error is only a warning.
/// 5. Otherwise — no balance, no stake: a new node — calls the Portal faucet:
///    - Success: logs the broadcast txids and polls until the balance appears.
///    - 502/503: warns and polls anyway (e.g. waiting for a manual transfer).
///    - Other errors: propagated.
pub async fn ensure_kor_balance(
    client: &PortalClient,
    signer_id: u64,
    amount: Kor,
    writer: &mut impl Write,
) -> Result<()> {
    let entry = client.get_registry_entry(signer_id).await?;

    if entry.kor_balance.is_none() {
        writeln!(
            writer,
            "⚠ KOR balance: not reported by the Portal this time; not asking the faucet. The \
             daemon reads it again each cycle"
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

    match funding(&entry) {
        Funding::Staked(stake) => {
            writeln!(
                writer,
                "✓ KOR balance: 0 liquid, {stake} KOR bonded; not asking the faucet"
            )?;
            return Ok(());
        }
        Funding::Unknown => {
            writeln!(
                writer,
                "KOR balance: 0, stake not known → requesting {amount} KOR from the faucet, \
                 without waiting for it…"
            )?;
            match request_within_cap(client, recipient, amount, writer).await {
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

    writeln!(
        writer,
        "KOR balance: 0 → requesting {amount} KOR from the faucet…"
    )?;
    match request_within_cap(client, recipient, amount, writer).await {
        Ok(resp) => {
            writeln!(
                writer,
                "✓ Faucet broadcast: commit={} reveal={}",
                resp.commit_txid, resp.reveal_txid
            )?;
        }
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
                _ => return Err(e),
            }
        }
    }

    poll_until_balance(client, signer_id, writer).await
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
) -> Result<crate::clients::portal::FaucetResponse> {
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

async fn poll_until_balance(
    client: &PortalClient,
    signer_id: u64,
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
        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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
            ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
                .await
                .unwrap_or_else(|e| panic!("{stake} {cleanup}: {e:#}"));
            let output = String::from_utf8(buffer).unwrap();
            assert!(output.contains("without waiting"), "{output}");
            assert!(!output.contains("Waiting for KOR balance"), "{output}");
        }
    }

    /// A `kor_balance` the Portal could not read is not an empty one: the
    /// faucet is not asked, and startup does not wait.
    #[tokio::test]
    async fn ensure_kor_balance_does_not_fund_a_node_whose_balance_is_unknown() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
            .expect(1)
            .mount(&mock_server)
            .await;
        mount_faucet(&mock_server, 200, 0).await;

        let client = PortalClient::try_new(mock_server.uri(), std::env::temp_dir()).unwrap();
        let mut buffer = Vec::new();
        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("not reported"), "{output}");
        assert!(!output.contains("faucet…"), "{output}");
        assert!(!output.contains("Waiting for KOR balance"), "{output}");
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

        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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

        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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

        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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

        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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

        let err = ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
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
        ensure_kor_balance(&client, 42, Kor::parse("250.5").unwrap(), &mut buffer)
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
        ensure_kor_balance(&client, 42, Kor::whole(1000), &mut buffer)
            .await
            .unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("gives at most 10 KOR"), "{output}");
        assert!(output.contains("✓ KOR balance: 10"), "{output}");
    }
}
