//! BLS key management for onboarding.
//!
//! Handles loading, generating, and encrypting BLS keys.

use crate::crypto::{BlsKeyPair, BLS_KEY_FILENAME};
use crate::database::default_app_dir;
use crate::node::onboarding::OnboardingConfig;
use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable name for providing the BLS password non-interactively.
/// This is useful for automation, testing, and scripted deployments.
pub const BLS_PASSWORD_ENV: &str = "BLS_PASSWORD";

/// Environment variable name for providing the encrypted BLS blob non-interactively.
pub const BLS_BLOB_ENV: &str = "BLS_ENCRYPTED_BLOB";

/// Trait for reading passwords and interactive input from the user.
/// This abstraction enables testing without interactive input.
pub trait PasswordReader {
    /// Read a password (for existing key).
    fn read_password(&self) -> Result<String>;

    /// Read and confirm a new password.
    /// Returns an error if passwords don't match or validation fails.
    fn read_new_password(&self, writer: &mut dyn Write) -> Result<String>;

    /// Read the encrypted BLS key blob (copy-pasted from Horizon Wallet).
    fn read_blob(&self) -> Result<String>;

    /// Wait for the user to press Enter.
    #[allow(dead_code)]
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

    fn read_blob(&self) -> Result<String> {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("failed to read encrypted key blob: {e}"))?;
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("encrypted key blob cannot be empty"));
        }
        Ok(trimmed)
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
///
/// **Import caveat:** [`Self::read_password`] and [`Self::read_new_password`] both use
/// `BLS_PASSWORD`. For a non-interactive Horizon Wallet import, the wallet export password
/// and the new on-disk password must therefore be the same, or you must use interactive mode.
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

    fn read_blob(&self) -> Result<String> {
        let raw = std::env::var(BLS_BLOB_ENV).map_err(|_| {
            anyhow!("{BLS_BLOB_ENV} environment variable is required in non-interactive mode")
        })?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!(
                "{BLS_BLOB_ENV} is set but empty (after trimming); paste the full encrypted blob"
            ));
        }
        Ok(trimmed)
    }

    fn wait_for_enter(&self) -> Result<()> {
        // In non-interactive mode, we don't wait for user input
        Ok(())
    }
}

/// Returns the appropriate password reader based on environment.
/// Uses [`EnvPasswordReader`] if `BLS_PASSWORD` is set, otherwise [`TerminalPasswordReader`].
/// For non-interactive wallet import, set `BLS_ENCRYPTED_BLOB` as well (see [`EnvPasswordReader`]).
pub fn get_password_reader() -> Box<dyn PasswordReader> {
    if std::env::var(BLS_PASSWORD_ENV).is_ok() {
        Box::new(EnvPasswordReader)
    } else {
        Box::new(TerminalPasswordReader) // LCOV_EXCL_LINE
    }
}

/// Get the path to the BLS key file.
pub fn get_key_path(config: &OnboardingConfig) -> Result<PathBuf> {
    if let Some(ref path) = config.bls_key_path {
        return Ok(path.clone());
    }
    let app_dir = default_app_dir().ok_or_else(|| {
        anyhow!("unable to determine application data directory for storing BLS keys")
    })?;
    Ok(app_dir.join(BLS_KEY_FILENAME))
}

/// Ensure a BLS keypair exists, either by loading it or importing from Horizon Wallet.
pub async fn ensure_bls_keypair(
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
        writeln!(writer, "No BLS key found. Import from Horizon Wallet.")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "Please paste your encrypted BLS key blob from Horizon Wallet:"
        )?;
        writer.flush().ok();

        let blob = password_reader.read_blob()?;

        writeln!(
            writer,
            "Enter the password used to export the key from Horizon Wallet:"
        )?;
        let wallet_password = password_reader.read_password()?;

        let secret_key_hex = crate::crypto::decrypt_wallet_blob(&blob, &wallet_password)?;
        let keypair = BlsKeyPair::from_secret_key_hex(&secret_key_hex)?;

        writeln!(writer, "✓ BLS key successfully decrypted")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "Choose a password to protect the key on this machine."
        )?;
        writeln!(
            writer,
            "This password will be required each time you start the application."
        )?;
        writeln!(writer)?;

        let local_password = password_reader.read_new_password(writer)?;
        keypair.save_encrypted(key_path, &local_password).await?;

        writeln!(writer, "✓ BLS key saved to {}", key_path.display())?;
        Ok(keypair)
    }
}

/// Mock password reader for testing.
/// Returns a pre-configured password without any user interaction.
#[cfg(test)]
pub struct MockPasswordReader {
    password: String,
    blob: Option<String>,
}

#[cfg(test)]
impl MockPasswordReader {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            blob: None,
        }
    }

    pub fn with_blob(password: impl Into<String>, blob: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            blob: Some(blob.into()),
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

    fn read_blob(&self) -> Result<String> {
        self.blob
            .clone()
            .ok_or_else(|| anyhow!("no blob configured in mock"))
    }

    fn wait_for_enter(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsKeyPair;
    use std::path::PathBuf;

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
    #[serial_test::serial]
    fn env_password_reader_read_blob_trims_and_succeeds() {
        std::env::remove_var(BLS_BLOB_ENV);
        std::env::set_var(BLS_BLOB_ENV, "  ablobvalue  \n");
        let reader = EnvPasswordReader;
        assert_eq!(reader.read_blob().unwrap(), "ablobvalue");
        std::env::remove_var(BLS_BLOB_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_blob_fails_when_unset() {
        std::env::remove_var(BLS_BLOB_ENV);
        let reader = EnvPasswordReader;
        let err = reader.read_blob().unwrap_err();
        assert!(err.to_string().contains(BLS_BLOB_ENV));
        assert!(err.to_string().contains("required"));
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_blob_fails_when_empty_after_trim() {
        std::env::remove_var(BLS_BLOB_ENV);
        std::env::set_var(BLS_BLOB_ENV, "   \t  ");
        let reader = EnvPasswordReader;
        let err = reader.read_blob().unwrap_err();
        assert!(err.to_string().contains("empty"));
        std::env::remove_var(BLS_BLOB_ENV);
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
    async fn ensure_bls_keypair_imports_from_wallet_blob() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("imported_key.enc");

        let bls_hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let wallet_password = "walletpass123";
        let salt = [1u8; 16];
        let iv = [2u8; 16];
        let blob = crate::crypto::wallet_import::encrypt_test_blob(
            bls_hex_key,
            wallet_password,
            &salt,
            &iv,
        );

        let reader = MockPasswordReader::with_blob(wallet_password, blob);
        let mut buffer = Vec::new();

        let keypair = ensure_bls_keypair(&key_path, &mut buffer, &reader)
            .await
            .unwrap();

        let expected = BlsKeyPair::from_secret_key_hex(bls_hex_key).unwrap();
        assert_eq!(keypair.public_key_hex(), expected.public_key_hex());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("No BLS key found"));
        assert!(output.contains("BLS key successfully decrypted"));
        assert!(output.contains("BLS key saved to"));
        assert!(!keypair.public_key_hex().is_empty());
        assert!(BlsKeyPair::key_file_exists(&key_path).await);

        let reloaded = BlsKeyPair::load_encrypted(&key_path, wallet_password)
            .await
            .unwrap();
        assert_eq!(reloaded.public_key_hex(), keypair.public_key_hex());
    }

    #[tokio::test]
    async fn ensure_bls_keypair_loads_existing_key() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("existing_key.enc");
        let password = "testpassword123";

        // Create an existing key
        let original = BlsKeyPair::generate().unwrap();
        let original_pk = original.public_key_hex();
        original.save_encrypted(&key_path, password).await.unwrap();

        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let loaded = ensure_bls_keypair(&key_path, &mut buffer, &reader)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("Found existing BLS key"));
        assert_eq!(loaded.public_key_hex(), original_pk);
    }
}
