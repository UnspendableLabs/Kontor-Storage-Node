//! Node onboarding module.
//!
//! Handles the verification of the node's registration status with Horizon Market
//! and manages BLS key generation and verification.

pub mod key_management;
pub mod registration;
pub mod verification;

use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

pub use key_management::{get_password_reader, PasswordReader};

#[cfg(test)]
pub use key_management::BLS_PASSWORD_ENV;
pub use registration::{check_node_exists, verify_bls_registration};
pub use verification::verify_bls_key_match;

#[cfg(test)]
pub use key_management::MockPasswordReader;

/// Result of the onboarding process.
#[derive(Debug)]
pub struct OnboardingResult {
    /// The BLS keypair for signing requests.
    pub keypair: crate::crypto::BlsKeyPair,
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
/// 1. Checks if the node exists in Horizon Market via Portal API
/// 2. If the node doesn't exist, exits with an error
/// 3. If the node exists without BLS key, generates one and waits for user registration
/// 4. If the node exists with BLS key, verifies it matches the local key
///
/// Uses the appropriate password reader based on environment (BLS_PASSWORD env var or terminal).
pub async fn perform_onboarding(
    client: &PortalClient,
    node_id: &str,
    config: &OnboardingConfig,
    writer: &mut impl Write,
) -> Result<OnboardingResult> {
    let password_reader = get_password_reader();
    perform_onboarding_with_reader(client, node_id, config, writer, password_reader.as_ref()).await
}

/// Perform the node onboarding process with a custom password reader.
/// This variant is useful for testing.
pub async fn perform_onboarding_with_reader(
    client: &PortalClient,
    node_id: &str,
    config: &OnboardingConfig,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<OnboardingResult> {
    writeln!(writer, "Checking node registration status...")?;

    let node_info = check_node_exists(client, node_id).await?;
    writeln!(writer, "✓ Node {} found in Horizon Market", node_id)?;

    let key_path = key_management::get_key_path(config)?;
    let keypair = key_management::ensure_bls_keypair(&key_path, writer, password_reader).await?;
    let local_public_key = keypair.public_key_hex();

    // Treat empty string as None (no BLS key configured)
    let remote_bls_key = node_info.bls_public_key.as_ref().filter(|k| !k.is_empty());

    match remote_bls_key {
        Some(remote_key) => {
            // Node has a BLS key configured on Horizon Market
            verify_bls_key_match(&local_public_key, remote_key)?;
            writeln!(writer, "✓ BLS public key verified")?;
            Ok(OnboardingResult { keypair })
        }
        None => {
            // Node exists but no BLS key configured yet
            writeln!(writer)?;
            writeln!(
                writer,
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )?;
            writeln!(writer, "Your BLS public key:")?;
            writeln!(writer)?;
            writeln!(writer, "  {}", local_public_key)?;
            writeln!(writer)?;
            writeln!(
                writer,
                "Please go to https://horizon.market/profile?show=node-storage"
            )?;
            writeln!(writer, "and register this BLS public key for your node.")?;
            writeln!(
                writer,
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )?;
            writeln!(writer)?;
            writeln!(
                writer,
                "Press Enter once you have registered your BLS key..."
            )?;
            writer.flush().ok();

            // Wait for user to press Enter
            password_reader.wait_for_enter()?;

            writeln!(writer, "Verifying BLS key registration...")?;

            verify_bls_registration(client, node_id, &local_public_key).await?;

            writeln!(writer, "✓ BLS public key registered and verified")?;
            Ok(OnboardingResult { keypair })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsKeyPair;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_key_filename() -> String {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("test_bls_key_{id}.enc")
    }

    #[tokio::test]
    async fn onboarding_fails_when_node_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-notfound/check"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {
                    "code": "NODE_NOT_FOUND",
                    "message": "node not found",
                    "status": 404
                }
            })))
            .mount(&mock_server)
            .await;

        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("storage");
        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig::default();
        let mut buffer = Vec::new();

        let err = perform_onboarding(&client, "NODE-notfound", &config, &mut buffer)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("not found in Horizon Market"));
    }

    #[tokio::test]
    async fn onboarding_succeeds_with_matching_bls_key() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate and save a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Mock portal to return the matching key
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-test",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result =
            perform_onboarding_with_reader(&client, "NODE-test", &config, &mut buffer, &reader)
                .await
                .unwrap();

        assert_eq!(result.keypair.public_key_hex(), public_key);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("BLS public key verified"));
    }

    #[tokio::test]
    async fn onboarding_fails_with_mismatched_bls_key() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate and save a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Mock portal to return a DIFFERENT key
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-test/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-test",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": "differentkey123456789abcdef"
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err =
            perform_onboarding_with_reader(&client, "NODE-test", &config, &mut buffer, &reader)
                .await
                .unwrap_err();

        assert!(err.to_string().contains("BLS public key mismatch"));
    }

    #[tokio::test]
    async fn onboarding_generates_new_key_and_waits_for_registration() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // We need to pre-generate a keypair so we know its public key for the mock
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Track call count to simulate: first call no key, second call has key registered
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();
        let pk_clone = public_key.clone();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-newkey/check"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call: node exists but no BLS key (triggers "press Enter" flow)
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-newkey",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": null
                    }))
                } else {
                    // Second call (after Enter): key is now registered
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-newkey",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": pk_clone.clone()
                    }))
                }
            })
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig {
            bls_key_path: Some(key_path.clone()),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result =
            perform_onboarding_with_reader(&client, "NODE-newkey", &config, &mut buffer, &reader)
                .await
                .unwrap();

        assert_eq!(result.keypair.public_key_hex(), public_key);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("horizon.market/profile?show=node-storage"));
        assert!(output.contains("Press Enter"));
        assert!(output.contains("BLS public key registered and verified"));
    }

    #[tokio::test]
    async fn onboarding_fails_if_key_not_registered_after_enter() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Always return no BLS key
        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-nokey/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "NODE-nokey",
                "address": "bc1qtest",
                "xpubkey": "xpub123",
                "bls_public_key": null
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err =
            perform_onboarding_with_reader(&client, "NODE-nokey", &config, &mut buffer, &reader)
                .await
                .unwrap_err();

        assert!(err
            .to_string()
            .contains("BLS key not found on Horizon Market"));
    }

    #[tokio::test]
    async fn onboarding_treats_empty_bls_key_as_none() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Track call count
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();
        let pk_clone = public_key.clone();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-empty/check"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call: empty string BLS key (should be treated as None)
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-empty",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": ""
                    }))
                } else {
                    // Second call: key is now registered
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-empty",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": pk_clone.clone()
                    }))
                }
            })
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);

        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        perform_onboarding_with_reader(&client, "NODE-empty", &config, &mut buffer, &reader)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        // Should have gone through the "Press Enter" flow since empty string is treated as None
        assert!(output.contains("Press Enter"));
        assert!(output.contains("BLS public key registered and verified"));
    }

    #[test]
    fn onboarding_config_default_has_no_bls_key_path() {
        let config = OnboardingConfig::default();
        assert!(config.bls_key_path.is_none());
    }

    #[test]
    fn onboarding_result_debug_impl() {
        // This just ensures the Debug derive is exercised
        let keypair = BlsKeyPair::generate().unwrap();
        let result = OnboardingResult { keypair };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("OnboardingResult"));
    }
}
