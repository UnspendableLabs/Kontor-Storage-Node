//! BLS key management module.
//!
//! Provides functionality for generating, storing (encrypted), and loading BLS keypairs.
//! The private key is encrypted using Argon2id for key derivation and AES-256-GCM for encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blst::min_sig::{PublicKey, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use zeroize::Zeroizing;

/// BLS key file name stored in app data directory.
pub const BLS_KEY_FILENAME: &str = "bls_key.enc";

/// Salt size for Argon2id (16 bytes recommended).
const SALT_SIZE: usize = 16;

/// Nonce size for AES-256-GCM (12 bytes).
const NONCE_SIZE: usize = 12;

/// Argon2id parameters (following OWASP recommendations for sensitive keys).
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 lanes

/// Encrypted BLS key file format.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedKeyFile {
    /// Version of the key file format.
    version: u32,
    /// Salt used for Argon2id key derivation.
    salt: Vec<u8>,
    /// Nonce used for AES-256-GCM.
    nonce: Vec<u8>,
    /// Encrypted private key bytes.
    ciphertext: Vec<u8>,
}

/// A BLS keypair with the private key stored securely.
#[derive(Debug)]
pub struct BlsKeyPair {
    secret_key: Zeroizing<Vec<u8>>,
    public_key: PublicKey,
}

impl BlsKeyPair {
    /// Generate a new random BLS keypair.
    pub fn generate() -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(ikm.as_mut());

        let sk = SecretKey::key_gen(ikm.as_slice(), &[])
            .map_err(|_| anyhow!("failed to generate BLS secret key"))?;
        let pk = sk.sk_to_pk();

        Ok(Self {
            secret_key: Zeroizing::new(sk.to_bytes().to_vec()),
            public_key: pk,
        })
    }

    /// Get the public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    /// Get the raw public key bytes (48 bytes for BLS12-381 MinSig scheme).
    #[allow(dead_code)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    /// Get access to the secret key for signing operations.
    #[allow(dead_code)]
    pub fn secret_key(&self) -> Result<SecretKey> {
        SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| anyhow!("failed to deserialize secret key"))
    }

    /// Save the keypair to an encrypted file.
    pub async fn save_encrypted(&self, path: &Path, password: &str) -> Result<()> {
        let derived_key = derive_key(password, None)?;

        let cipher = Aes256Gcm::new_from_slice(derived_key.key.as_slice())
            .map_err(|e| anyhow!("failed to create cipher: {e}"))?;

        let nonce = Nonce::from_slice(&derived_key.nonce);
        let ciphertext = cipher
            .encrypt(nonce, self.secret_key.as_slice())
            .map_err(|e| anyhow!("failed to encrypt private key: {e}"))?;

        let key_file = EncryptedKeyFile {
            version: 1,
            salt: derived_key.salt,
            nonce: derived_key.nonce.to_vec(),
            ciphertext,
        };

        let json = serde_json::to_string_pretty(&key_file)
            .context("failed to serialize encrypted key file")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("failed to create key directory")?;
        }

        fs::write(path, json)
            .await
            .context("failed to write encrypted key file")?;

        Ok(())
    }

    /// Load a keypair from an encrypted file.
    pub async fn load_encrypted(path: &Path, password: &str) -> Result<Self> {
        let json = fs::read_to_string(path)
            .await
            .context("failed to read encrypted key file")?;

        let key_file: EncryptedKeyFile =
            serde_json::from_str(&json).context("failed to parse encrypted key file")?;

        if key_file.version != 1 {
            return Err(anyhow!(
                "unsupported key file version: {}",
                key_file.version
            ));
        }

        let derived_key = derive_key_with_salt(password, &key_file.salt, &key_file.nonce)?;

        let cipher = Aes256Gcm::new_from_slice(derived_key.key.as_slice())
            .map_err(|e| anyhow!("failed to create cipher: {e}"))?;

        let nonce = Nonce::from_slice(&key_file.nonce);
        let plaintext = cipher
            .decrypt(nonce, key_file.ciphertext.as_slice())
            .map_err(|_| {
                anyhow!("failed to decrypt private key: incorrect password or corrupted file")
            })?;

        let sk = SecretKey::from_bytes(&plaintext)
            .map_err(|_| anyhow!("failed to deserialize decrypted secret key"))?;
        let pk = sk.sk_to_pk();

        Ok(Self {
            secret_key: Zeroizing::new(plaintext),
            public_key: pk,
        })
    }

    /// Check if a key file exists at the given path.
    pub async fn key_file_exists(path: &Path) -> bool {
        fs::metadata(path).await.is_ok()
    }
}

struct DerivedKey {
    key: Zeroizing<[u8; 32]>,
    salt: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
}

fn derive_key(password: &str, existing_salt: Option<&[u8]>) -> Result<DerivedKey> {
    let salt = match existing_salt {
        Some(s) => s.to_vec(),
        None => {
            let mut salt = vec![0u8; SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt);
            salt
        }
    };

    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|e| anyhow!("failed to derive key: {e}"))?;

    Ok(DerivedKey { key, salt, nonce })
}

fn derive_key_with_salt(password: &str, salt: &[u8], nonce: &[u8]) -> Result<DerivedKey> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("failed to derive key: {e}"))?;

    let mut nonce_arr = [0u8; NONCE_SIZE];
    nonce_arr.copy_from_slice(nonce);

    Ok(DerivedKey {
        key,
        salt: salt.to_vec(),
        nonce: nonce_arr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_filename() -> String {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("test_bls_key_{id}.enc")
    }

    #[test]
    fn generate_creates_valid_keypair() {
        let keypair = BlsKeyPair::generate().unwrap();
        let pk_hex = keypair.public_key_hex();

        // BLS12-381 MinSig public key is 96 bytes = 192 hex characters
        assert_eq!(pk_hex.len(), 192);

        // Should be able to get secret key
        let sk = keypair.secret_key().unwrap();
        assert_eq!(
            sk.sk_to_pk().to_bytes().to_vec(),
            keypair.public_key_bytes()
        );
    }

    #[tokio::test]
    async fn save_and_load_encrypted_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());
        let password = "test-password-123";

        let original = BlsKeyPair::generate().unwrap();
        let original_pk = original.public_key_hex();

        original.save_encrypted(&path, password).await.unwrap();

        assert!(BlsKeyPair::key_file_exists(&path).await);

        let loaded = BlsKeyPair::load_encrypted(&path, password).await.unwrap();

        assert_eq!(loaded.public_key_hex(), original_pk);
    }

    #[tokio::test]
    async fn load_with_wrong_password_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());

        let keypair = BlsKeyPair::generate().unwrap();
        keypair
            .save_encrypted(&path, "correct-password")
            .await
            .unwrap();

        let result = BlsKeyPair::load_encrypted(&path, "wrong-password").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("incorrect password"));
    }

    #[tokio::test]
    async fn key_file_exists_returns_false_for_missing_file() {
        let path = Path::new("/nonexistent/path/to/key.enc");
        assert!(!BlsKeyPair::key_file_exists(path).await);
    }

    #[test]
    fn public_key_hex_is_consistent() {
        let keypair = BlsKeyPair::generate().unwrap();
        let hex1 = keypair.public_key_hex();
        let hex2 = keypair.public_key_hex();
        assert_eq!(hex1, hex2);
    }
}
