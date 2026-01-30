//! Node onboarding module.
//!
//! Handles the verification of the node's registration status with Horizon Market
//! and manages BLS key generation and verification.

use crate::bls::{BlsKeyPair, BLS_KEY_FILENAME};
use crate::clients::{NodeCheckResult, NodeInfo, PortalClient};
use crate::database::default_app_dir;
use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable name for providing the BLS password non-interactively.
/// This is useful for automation, testing, and scripted deployments.
pub const BLS_PASSWORD_ENV: &str = "BLS_PASSWORD";

/// Trait for reading passwords and interactive input from the user.
/// This abstraction enables testing without interactive input.
pub trait PasswordReader {
    /// Read a password (for existing key).
    fn read_password(&self) -> Result<String>;

    /// Read and confirm a new password.
    /// Returns an error if passwords don't match or validation fails.
    fn read_new_password(&self, writer: &mut dyn Write) -> Result<String>;

    /// Wait for the user to press Enter.
    fn wait_for_enter(&self) -> Result<()>;
}

/// Default implementation that reads from the terminal using rpassword.
/// This struct is excluded from coverage because it requires interactive terminal input.
// LCOV_EXCL_START
pub struct TerminalPasswordReader;

impl PasswordReader for TerminalPasswordReader {
    fn read_password(&self) -> Result<String> {
        rpassword::prompt_password("Password: ")
            .map_err(|e| anyhow!("failed to read password: {e}"))
    }

    fn read_new_password(&self, writer: &mut dyn Write) -> Result<String> {
        loop {
            let password = rpassword::prompt_password("Enter password: ")
                .map_err(|e| anyhow!("failed to read password: {e}"))?;

            if password.is_empty() {
                writeln!(writer, "Password cannot be empty. Please try again.")?;
                continue;
            }

            if password.len() < 8 {
                writeln!(
                    writer,
                    "Password must be at least 8 characters. Please try again."
                )?;
                continue;
            }

            let confirm = rpassword::prompt_password("Confirm password: ")
                .map_err(|e| anyhow!("failed to read password confirmation: {e}"))?;

            if password != confirm {
                writeln!(writer, "Passwords do not match. Please try again.")?;
                continue;
            }

            return Ok(password);
        }
    }

    fn wait_for_enter(&self) -> Result<()> {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("failed to read input: {e}"))?;
        Ok(())
    }
}
// LCOV_EXCL_STOP

/// Password reader that reads from the BLS_PASSWORD environment variable.
/// Useful for automation, CI/CD, and testing.
pub struct EnvPasswordReader;

impl PasswordReader for EnvPasswordReader {
    fn read_password(&self) -> Result<String> {
        std::env::var(BLS_PASSWORD_ENV).map_err(|_| {
            anyhow!(
                "{} environment variable is required in non-interactive mode",
                BLS_PASSWORD_ENV
            )
        })
    }

    fn read_new_password(&self, _writer: &mut dyn Write) -> Result<String> {
        let password = std::env::var(BLS_PASSWORD_ENV).map_err(|_| {
            anyhow!(
                "{} environment variable is required in non-interactive mode",
                BLS_PASSWORD_ENV
            )
        })?;

        // Validate password requirements
        if password.is_empty() {
            return Err(anyhow!("password cannot be empty"));
        }
        if password.len() < 8 {
            return Err(anyhow!("password must be at least 8 characters"));
        }

        Ok(password)
    }

    fn wait_for_enter(&self) -> Result<()> {
        // In non-interactive mode, we don't wait for user input
        Ok(())
    }
}

/// Returns the appropriate password reader based on environment.
/// Uses EnvPasswordReader if BLS_PASSWORD is set, otherwise TerminalPasswordReader.
pub fn get_password_reader() -> Box<dyn PasswordReader> {
    if std::env::var(BLS_PASSWORD_ENV).is_ok() {
        Box::new(EnvPasswordReader)
    } else {
        Box::new(TerminalPasswordReader) // LCOV_EXCL_LINE
    }
}

/// Result of the onboarding process.
#[derive(Debug)]
pub struct OnboardingResult {
    /// The BLS keypair for signing requests.
    pub keypair: BlsKeyPair,
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

    let key_path = get_key_path(config)?;
    let keypair = ensure_bls_keypair(&key_path, writer, password_reader).await?;
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

/// Check if the node exists in Horizon Market.
async fn check_node_exists(client: &PortalClient, node_id: &str) -> Result<NodeInfo> {
    match client.check_node(node_id).await? {
        NodeCheckResult::Found(info) => Ok(info),
        NodeCheckResult::NotFound => Err(anyhow!(
            "Node {} not found in Horizon Market.\n\n\
                Please register as a Storage Node at:\n\
                https://horizon.market\n\n\
                After completing registration, you will receive a Node ID that you can use\n\
                to configure this application.",
            node_id
        )),
    }
}

/// Get the path to the BLS key file.
fn get_key_path(config: &OnboardingConfig) -> Result<PathBuf> {
    if let Some(ref path) = config.bls_key_path {
        return Ok(path.clone());
    }
    let app_dir = default_app_dir().ok_or_else(|| {
        anyhow!("unable to determine application data directory for storing BLS keys")
    })?;
    Ok(app_dir.join(BLS_KEY_FILENAME))
}

/// Ensure a BLS keypair exists, either by loading it or generating a new one.
async fn ensure_bls_keypair(
    key_path: &Path,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<BlsKeyPair> {
    if BlsKeyPair::key_file_exists(key_path).await {
        writeln!(
            writer,
            "Found existing BLS key, please enter your password:"
        )?;
        let password = password_reader.read_password()?;
        BlsKeyPair::load_encrypted(key_path, &password).await
    } else {
        writeln!(writer, "No BLS key found. Generating a new keypair...")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "Please enter a password to protect your BLS private key."
        )?;
        writeln!(
            writer,
            "This password will be required each time you start the application."
        )?;
        writeln!(writer)?;

        // We need a mutable writer for the password reader's validation messages
        let password = password_reader.read_new_password(writer)?;
        let keypair = BlsKeyPair::generate()?;
        keypair.save_encrypted(key_path, &password).await?;

        writeln!(
            writer,
            "✓ BLS keypair generated and saved to {}",
            key_path.display()
        )?;
        Ok(keypair)
    }
}

/// Normalize a hex-encoded key by removing optional 0x prefix and converting to lowercase.
fn normalize_hex_key(key: &str) -> String {
    key.strip_prefix("0x")
        .or_else(|| key.strip_prefix("0X"))
        .unwrap_or(key)
        .to_lowercase()
}

/// Verify that the local BLS public key matches the one registered on Horizon Market.
fn verify_bls_key_match(local_key: &str, remote_key: &str) -> Result<()> {
    // Normalize both keys (remove 0x prefix if present, lowercase)
    let local_normalized = normalize_hex_key(local_key);
    let remote_normalized = normalize_hex_key(remote_key);

    if local_normalized != remote_normalized {
        Err(anyhow!(
            "BLS public key mismatch!\n\n\
            Your local BLS public key:\n  {}\n\n\
            BLS public key registered on Horizon Market:\n  {}\n\n\
            This could happen if:\n\
            - You are running the node on a different machine\n\
            - Your local key file was replaced or corrupted\n\
            - A different key was registered on Horizon Market\n\n\
            To resolve this, you can either:\n\
            1. Update your BLS key on https://horizon.market/profile?show=node-storage\n\
            2. Or delete your local key file and restart to generate a new one",
            local_key,
            remote_key
        ))
    } else {
        Ok(())
    }
}

/// Verify that the BLS key has been registered on Horizon Market.
async fn verify_bls_registration(
    client: &PortalClient,
    node_id: &str,
    expected_key: &str,
) -> Result<NodeInfo> {
    match client.check_node(node_id).await? {
        NodeCheckResult::Found(info) => {
            let remote_key = info
                .bls_public_key
                .as_ref()
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "BLS key not found on Horizon Market.\n\n\
                        Please make sure you have registered your BLS public key at:\n\
                        https://horizon.market/profile?show=node-storage\n\n\
                        Then restart the application to try again."
                    )
                })?;
            verify_bls_key_match(expected_key, remote_key)?;
            Ok(info)
        }
        NodeCheckResult::NotFound => {
            Err(anyhow!("Node {} was removed from Horizon Market", node_id))
        }
    }
}

/// Mock password reader for testing.
/// Returns a pre-configured password without any user interaction.
#[cfg(test)]
pub struct MockPasswordReader {
    password: String,
}

#[cfg(test)]
impl MockPasswordReader {
    /// Create a new mock password reader with the given password.
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }
}

#[cfg(test)]
impl PasswordReader for MockPasswordReader {
    fn read_password(&self) -> Result<String> {
        Ok(self.password.clone())
    }

    fn read_new_password(&self, _writer: &mut dyn Write) -> Result<String> {
        Ok(self.password.clone())
    }

    fn wait_for_enter(&self) -> Result<()> {
        // In tests, we don't wait for user input
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::BlsKeyPair;
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

    #[test]
    fn normalize_hex_key_removes_0x_prefix() {
        assert_eq!(normalize_hex_key("0xabcdef"), "abcdef");
        assert_eq!(normalize_hex_key("0Xabcdef"), "abcdef");
    }

    #[test]
    fn normalize_hex_key_lowercases() {
        assert_eq!(normalize_hex_key("ABCDEF"), "abcdef");
        assert_eq!(normalize_hex_key("0xABCDEF"), "abcdef");
    }

    #[test]
    fn normalize_hex_key_handles_no_prefix() {
        assert_eq!(normalize_hex_key("abcdef"), "abcdef");
    }

    #[test]
    fn verify_bls_key_match_succeeds_for_matching_keys() {
        let key = "abcdef123456";
        assert!(verify_bls_key_match(key, key).is_ok());
    }

    #[test]
    fn verify_bls_key_match_is_case_insensitive() {
        let lower = "abcdef123456";
        let upper = "ABCDEF123456";
        assert!(verify_bls_key_match(lower, upper).is_ok());
    }

    #[test]
    fn verify_bls_key_match_handles_0x_prefix() {
        let with_prefix = "0xabcdef123456";
        let without_prefix = "abcdef123456";
        assert!(verify_bls_key_match(with_prefix, without_prefix).is_ok());
        assert!(verify_bls_key_match(without_prefix, with_prefix).is_ok());
    }

    #[test]
    fn verify_bls_key_match_handles_mixed_case_and_prefix() {
        let key1 = "0xABCDEF123456";
        let key2 = "abcdef123456";
        assert!(verify_bls_key_match(key1, key2).is_ok());
    }

    #[test]
    fn verify_bls_key_match_fails_for_different_keys() {
        let key1 = "abcdef123456";
        let key2 = "different789";
        let err = verify_bls_key_match(key1, key2).unwrap_err();
        assert!(err.to_string().contains("BLS public key mismatch"));
    }

    #[test]
    fn get_key_path_returns_custom_path_when_configured() {
        let custom_path = PathBuf::from("/custom/path/key.enc");
        let config = OnboardingConfig {
            bls_key_path: Some(custom_path.clone()),
        };
        assert_eq!(get_key_path(&config).unwrap(), custom_path);
    }

    #[test]
    fn get_key_path_returns_default_path_when_not_configured() {
        let config = OnboardingConfig::default();
        // This test may fail if run in an environment without a data directory
        if let Ok(path) = get_key_path(&config) {
            assert!(path.to_string_lossy().contains(BLS_KEY_FILENAME));
        }
    }

    #[test]
    fn mock_password_reader_returns_configured_password() {
        let reader = MockPasswordReader::new("testpassword123");
        assert_eq!(reader.read_password().unwrap(), "testpassword123");
    }

    #[test]
    fn mock_password_reader_returns_same_for_new_password() {
        let reader = MockPasswordReader::new("testpassword123");
        let mut buffer = Vec::new();
        assert_eq!(
            reader.read_new_password(&mut buffer).unwrap(),
            "testpassword123"
        );
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_validates_password_length() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "short");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("at least 8 characters"));
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_validates_non_empty() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn get_password_reader_returns_env_reader_when_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "testpassword123");
        let reader = get_password_reader();
        assert_eq!(reader.read_password().unwrap(), "testpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
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
    #[serial_test::serial]
    fn env_password_reader_read_password_succeeds_when_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "validpassword123");
        let reader = EnvPasswordReader;
        let result = reader.read_password();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "validpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_password_fails_when_not_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        let reader = EnvPasswordReader;
        let err = reader.read_password().unwrap_err();
        assert!(err.to_string().contains("environment variable is required"));
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_new_password_succeeds_with_valid_password() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "validpassword123");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let result = reader.read_new_password(&mut buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "validpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_new_password_fails_when_not_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("environment variable is required"));
    }

    #[test]
    fn env_password_reader_wait_for_enter_succeeds() {
        let reader = EnvPasswordReader;
        let result = reader.wait_for_enter();
        assert!(result.is_ok());
    }

    #[test]
    fn mock_password_reader_wait_for_enter_succeeds() {
        let reader = MockPasswordReader::new("testpassword");
        let result = reader.wait_for_enter();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn onboarding_generates_new_key_when_none_exists() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Don't pre-create a key - we want to test the generation path
        let password = "testpassword123";

        // We need to use a two-phase approach:
        // 1. First call: node exists but no BLS key
        // 2. After key generation and "Enter" press: key is registered
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();
        let public_key = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let pk_clone = public_key.clone();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-newgen/check"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call: node exists but no BLS key
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-newgen",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": null
                    }))
                } else {
                    // Second call: we need to return a matching key
                    // Since we can't know the key in advance, we'll use a placeholder
                    // and verify the flow works
                    let pk = pk_clone.lock().unwrap();
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-newgen",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": pk.clone()
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

        // We need a custom reader that stores the generated public key
        // For this test, let's first run the onboarding and capture what key it generates
        // Then we verify the key was created
        let _result =
            perform_onboarding_with_reader(&client, "NODE-newgen", &config, &mut buffer, &reader)
                .await;

        // The first run will fail because the mock returns empty public key on second call
        // But that's OK - we want to verify the key generation path was executed
        // Let's check the output contains the generation messages
        let output = String::from_utf8(buffer.clone()).unwrap();
        assert!(
            output.contains("No BLS key found"),
            "expected 'No BLS key found' in output: {output}"
        );
        assert!(
            output.contains("Generating a new keypair"),
            "expected 'Generating a new keypair' in output: {output}"
        );
        assert!(
            output.contains("BLS keypair generated and saved"),
            "expected 'BLS keypair generated and saved' in output: {output}"
        );

        // Verify the key file was actually created
        assert!(
            BlsKeyPair::key_file_exists(&key_path).await,
            "BLS key file should have been created"
        );

        // Verify we can load the generated key
        let loaded_keypair = BlsKeyPair::load_encrypted(&key_path, password)
            .await
            .unwrap();
        assert!(
            !loaded_keypair.public_key_hex().is_empty(),
            "loaded keypair should have a public key"
        );

        // Now update the mock's expected public key and run again
        *public_key.lock().unwrap() = loaded_keypair.public_key_hex();

        // Reset call count for the second attempt
        call_count.store(0, Ordering::SeqCst);

        let mut buffer2 = Vec::new();
        // This time the key already exists, so it will load it
        let result2 =
            perform_onboarding_with_reader(&client, "NODE-newgen", &config, &mut buffer2, &reader)
                .await;

        // This should still fail on first call (no BLS key) then succeed on second
        // Actually the mock now returns the matching key, so it should work
        if let Err(e) = &result2 {
            // It's expected to fail with "BLS key not found" if the mock wasn't updated
            // But with our fix it should work
            panic!("unexpected error: {e}");
        }

        assert!(result2.is_ok(), "second onboarding should succeed");
    }

    #[tokio::test]
    async fn verify_bls_registration_fails_when_node_removed() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Track call count to simulate: first call exists, second call NotFound
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-removed/check"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call: node exists but no BLS key (triggers "press Enter" flow)
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-removed",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": null
                    }))
                } else {
                    // Second call (after Enter): node was removed!
                    ResponseTemplate::new(404).set_body_json(json!({
                        "error": {
                            "code": "NODE_NOT_FOUND",
                            "message": "node not found",
                            "status": 404
                        }
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

        let err =
            perform_onboarding_with_reader(&client, "NODE-removed", &config, &mut buffer, &reader)
                .await
                .unwrap_err();

        assert!(
            err.to_string().contains("was removed from Horizon Market"),
            "expected 'was removed' error, got: {err}"
        );
    }

    #[tokio::test]
    async fn verify_bls_registration_fails_when_key_mismatch_after_registration() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join(unique_key_filename());
        let storage_dir = dir.path().join("storage");

        // Generate a keypair
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Track call count
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        Mock::given(method("GET"))
            .and(path("/api/nodes/NODE-mismatch/check"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call: node exists but no BLS key
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-mismatch",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": null
                    }))
                } else {
                    // Second call: a DIFFERENT key was registered
                    ResponseTemplate::new(200).set_body_json(json!({
                        "node_id": "NODE-mismatch",
                        "address": "bc1qtest",
                        "xpubkey": "xpub123",
                        "bls_public_key": "differentkey123456789abcdef"
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

        let err =
            perform_onboarding_with_reader(&client, "NODE-mismatch", &config, &mut buffer, &reader)
                .await
                .unwrap_err();

        assert!(
            err.to_string().contains("BLS public key mismatch"),
            "expected 'mismatch' error, got: {err}"
        );
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
