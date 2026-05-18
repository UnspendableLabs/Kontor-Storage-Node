//! KOR balance check and faucet request at startup.
//!
//! After onboarding completes, ensures the node's signer has a positive KOR
//! balance. If the registry shows no balance, this module calls the public
//! Portal faucet endpoint and polls the registry until a balance appears
//! on-chain. If the faucet is unavailable, it logs a warning and continues to
//! poll, waiting for a manual transfer.

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::time::Duration;

#[cfg(not(test))]
const KOR_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Shorter interval in unit tests so polling scenarios finish quickly.
#[cfg(test)]
const KOR_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Amount of KOR requested from the faucet (Portal caps at 10.0).
const FAUCET_AMOUNT: f64 = 10.0;

/// Returns true when the registry entry's `kor_balance` indicates no KOR
/// (missing, unparsable, or non-positive).
fn kor_balance_is_empty(balance: &Option<String>) -> bool {
    match balance {
        None => true,
        Some(s) => s.parse::<f64>().unwrap_or(0.0) <= 0.0,
    }
}

/// Ensure the node's signer has a positive KOR balance before continuing.
///
/// 1. Fetches the registry entry for `signer_id`.
/// 2. If `kor_balance` is already positive, returns immediately.
/// 3. Otherwise calls the Portal faucet:
///    - Success: logs the broadcast txids and polls until the balance appears.
///    - 502/503: warns and polls anyway (e.g. waiting for a manual transfer).
///    - Other errors: propagated.
pub async fn ensure_kor_balance(
    client: &PortalClient,
    signer_id: u64,
    writer: &mut impl Write,
) -> Result<()> {
    let entry = client.get_registry_entry(signer_id).await?;

    if !kor_balance_is_empty(&entry.kor_balance) {
        let balance = entry.kor_balance.as_deref().unwrap_or("0");
        writeln!(writer, "✓ KOR balance: {balance}")?;
        return Ok(());
    }

    writeln!(writer, "KOR balance: 0 → requesting faucet…")?;
    match client
        .request_faucet(&entry.x_only_pubkey, FAUCET_AMOUNT)
        .await
    {
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
                        "⚠ Faucet indisponible, en attente d'un transfert KOR manuel…"
                    )?;
                }
                _ => return Err(e),
            }
        }
    }

    poll_until_balance(client, signer_id, writer).await
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

    fn registry_entry_json(kor_balance: Option<&str>) -> serde_json::Value {
        json!({
            "signer_id": 42,
            "x_only_pubkey": "abc123",
            "bls_pubkey": "def456",
            "next_nonce": 7,
            "kor_balance": kor_balance,
            "user_id": null,
        })
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

        ensure_kor_balance(&client, 42, &mut buffer).await.unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("✓ KOR balance: 5.0"),
            "expected balance line, got: {output}"
        );
        assert!(
            !output.contains("requesting faucet"),
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
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
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

        ensure_kor_balance(&client, 42, &mut buffer).await.unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("requesting faucet"), "got: {output}");
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
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
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

        ensure_kor_balance(&client, 42, &mut buffer).await.unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("Faucet indisponible"),
            "expected warning, got: {output}"
        );
        assert!(output.contains("✓ KOR balance: 3.0"), "got: {output}");
    }

    #[tokio::test]
    async fn ensure_kor_balance_handles_faucet_failed() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
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

        ensure_kor_balance(&client, 42, &mut buffer).await.unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("Faucet indisponible"),
            "expected warning, got: {output}"
        );
        assert!(output.contains("✓ KOR balance: 7.0"), "got: {output}");
    }

    #[tokio::test]
    async fn ensure_kor_balance_propagates_other_faucet_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(registry_entry_json(None)))
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

        let err = ensure_kor_balance(&client, 42, &mut buffer)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("status 400"),
            "expected 400 propagated, got: {err}"
        );
    }
}
