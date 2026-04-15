//! Node onboarding module.
//!
//! Handles BLS key loading/import, node identity lookup, Portal authentication,
//! and registry nonce retrieval.

pub mod key_management;

use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub use key_management::{get_password_reader, PasswordReader};

#[cfg(test)]
pub use key_management::BLS_PASSWORD_ENV;

#[cfg(test)]
pub use key_management::MockPasswordReader;

#[cfg(not(test))]
const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Shorter interval in unit tests so polling scenarios finish quickly.
#[cfg(test)]
const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Result of the onboarding process.
#[derive(Debug)]
pub struct OnboardingResult {
    /// The BLS keypair for signing requests.
    pub keypair: crate::crypto::BlsKeyPair,
    /// The node ID returned by Portal lookup.
    pub node_id: String,
    /// The signer ID from the registry.
    pub signer_id: u64,
    /// JWT token for authenticated API requests.
    pub token: String,
    /// Next nonce for registry transactions.
    pub next_nonce: u64,
}

/// Configuration for the onboarding process.
#[derive(Debug, Clone, Default)]
pub struct OnboardingConfig {
    /// Path to the BLS key file. If None, uses the default location.
    pub bls_key_path: Option<PathBuf>,
}

/// Perform the node onboarding process.
///
/// This function:
/// 1. Loads or imports the BLS keypair from disk / Horizon Wallet
/// 2. Looks up the node identity on Portal by BLS public key
/// 3. Authenticates via challenge/response to obtain a JWT
/// 4. Fetches the current registry nonce
///
/// Uses the appropriate password reader based on environment (BLS_PASSWORD env var or terminal).
pub async fn perform_onboarding(
    client: &PortalClient,
    config: &OnboardingConfig,
    writer: &mut impl Write,
) -> Result<OnboardingResult> {
    let password_reader = get_password_reader();
    perform_onboarding_with_reader(client, config, writer, password_reader.as_ref()).await
}

/// Perform the node onboarding process with a custom password reader.
/// This variant is useful for testing.
pub async fn perform_onboarding_with_reader(
    client: &PortalClient,
    config: &OnboardingConfig,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<OnboardingResult> {
    // Step 1: Load or import BLS keypair
    let key_path = key_management::get_key_path(config)?;
    let keypair = key_management::ensure_bls_keypair(&key_path, writer, password_reader).await?;
    let bls_pubkey = keypair.public_key_hex();
    writeln!(writer, "✓ BLS key loaded")?;

    // Step 2: Look up node by BLS public key
    writeln!(writer, "Looking up node identity...")?;
    let mut waiting = false;
    let (node_id, signer_id) = loop {
        let lookup = client.lookup_node(&bls_pubkey).await?;
        if let Some(sid) = lookup.signer_id {
            if waiting {
                writeln!(writer)?;
            }
            writeln!(
                writer,
                "✓ Node {} found (signer_id: {})",
                lookup.node_id, sid
            )?;
            break (lookup.node_id, sid);
        }
        if !waiting {
            writeln!(
                writer,
                "Node {} found but RegisterBlsKey transaction not yet confirmed.",
                lookup.node_id
            )?;
            write!(writer, "Waiting for on-chain confirmation")?;
            waiting = true;
        } else {
            write!(writer, ".")?;
        }
        writer.flush().ok();
        tokio::time::sleep(REGISTRATION_POLL_INTERVAL).await;
    };

    // Step 3: Login (challenge/response)
    writeln!(writer, "Authenticating with Portal...")?;
    let challenge = client.login_challenge(&node_id).await?;
    // Horizon Portal verifies with `request.challenge.as_bytes()` (hex string UTF-8), not decoded bytes.
    let signature = keypair.sign_http_message(challenge.challenge.as_bytes())?;
    let login = client
        .login_submit(&node_id, &challenge.challenge, &signature, Some(0))
        .await?;
    writeln!(writer, "✓ Authenticated as {}", login.user_id)?;

    // Step 4: Fetch current nonce
    let registry = client.get_registry_entry(signer_id).await?;
    writeln!(writer, "✓ Registry nonce: {}", registry.next_nonce)?;

    Ok(OnboardingResult {
        keypair,
        node_id,
        signer_id,
        token: login.token,
        next_nonce: registry.next_nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsKeyPair;
    use serde_json::json;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mount_all_mocks_except_lookup(
        mock_server: &MockServer,
        node_id: &str,
        public_key: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "jwt-test-token",
                "user_id": node_id,
                "role": "node",
                "expires_in": 86400
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/registry/entry/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abc123",
                "bls_pubkey": public_key,
                "next_nonce": 7
            })))
            .mount(mock_server)
            .await;
    }

    async fn mount_all_mocks(mock_server: &MockServer, node_id: &str, public_key: &str) {
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": node_id,
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(mock_server)
            .await;

        mount_all_mocks_except_lookup(mock_server, node_id, public_key).await;
    }

    #[tokio::test]
    async fn onboarding_succeeds_full_flow() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        mount_all_mocks(&mock_server, "node-test123", &public_key).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap();

        assert_eq!(result.keypair.public_key_hex(), public_key);
        assert_eq!(result.node_id, "node-test123");
        assert_eq!(result.signer_id, 42);
        assert_eq!(result.token, "jwt-test-token");
        assert_eq!(result.next_nonce, 7);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("BLS key loaded"));
        assert!(output.contains("Node node-test123 found"));
        assert!(output.contains("Authenticated as node-test123"));
        assert!(output.contains("Registry nonce: 7"));
    }

    #[tokio::test]
    async fn onboarding_fails_when_lookup_returns_404() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": "node not found"
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 404"),
            "expected 404 error, got: {err}"
        );
    }

    #[tokio::test]
    async fn onboarding_succeeds_after_signer_id_pending() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // First mounted mock wins for equal priority: two pending lookups, then the default mock.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-pending",
                "signer_id": null,
                "bls_public_key": public_key
            })))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-pending",
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        mount_all_mocks_except_lookup(&mock_server, "node-pending", &public_key).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap();

        assert_eq!(result.node_id, "node-pending");
        assert_eq!(result.signer_id, 42);

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("RegisterBlsKey transaction not yet confirmed"),
            "expected pending message, got: {output}"
        );
        assert!(output.contains('.'), "expected progress dots while waiting");
        assert!(
            output.contains("Node node-pending found (signer_id: 42)"),
            "expected success line after poll, got: {output}"
        );
    }

    #[tokio::test]
    async fn onboarding_fails_when_login_returns_error() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Lookup succeeds
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-test123",
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        // Login challenge succeeds
        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(&mock_server)
            .await;

        // Login submit fails
        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid signature"
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 401"),
            "expected 401 error, got: {err}"
        );
    }

    #[test]
    fn onboarding_config_default_has_no_bls_key_path() {
        let config = OnboardingConfig::default();
        assert!(config.bls_key_path.is_none());
    }

    #[test]
    fn onboarding_result_debug_impl() {
        let keypair = BlsKeyPair::generate().unwrap();
        let result = OnboardingResult {
            keypair,
            node_id: "node-debug".to_string(),
            signer_id: 42,
            token: "test-token".to_string(),
            next_nonce: 0,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("OnboardingResult"));
    }
}
