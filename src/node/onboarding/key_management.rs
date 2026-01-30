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

/// Ensure a BLS keypair exists, either by loading it or generating a new one.
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
    async fn ensure_bls_keypair_generates_new_key_when_none_exists() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("new_key.enc");
        let password = "testpassword123";
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let keypair = ensure_bls_keypair(&key_path, &mut buffer, &reader)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("No BLS key found"));
        assert!(output.contains("BLS keypair generated and saved"));
        assert!(!keypair.public_key_hex().is_empty());
        assert!(BlsKeyPair::key_file_exists(&key_path).await);
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
