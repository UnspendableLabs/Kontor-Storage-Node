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
#[cfg(test)]
use blst::min_sig::Signature;
use blst::min_sig::{PublicKey, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use zeroize::Zeroizing;

/// Domain Separation Tag for HTTP Message Signatures (RFC 9421).
pub const HTTP_SIGNATURE_DST: &[u8] = b"HORIZON_PORTAL_HTTP_SIG";

/// Domain Separation Tag for agreement instruction signatures.
pub const AGREEMENT_SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

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
    /// Generate a new random BLS keypair (test-only; production keys come from wallet import).
    #[cfg(test)]
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

    /// Create a BLS keypair from a hex-encoded secret key (64 hex characters = 32 bytes).
    ///
    /// This is used when importing a key from Horizon Wallet after decryption.
    pub fn from_secret_key_hex(hex_key: &str) -> Result<Self> {
        let sk_bytes = hex::decode(hex_key).context("invalid hex in BLS secret key")?;
        if sk_bytes.len() != 32 {
            return Err(anyhow!(
                "BLS secret key must be 32 bytes, got {}",
                sk_bytes.len()
            ));
        }
        let sk = SecretKey::from_bytes(&sk_bytes)
            .map_err(|_| anyhow!("invalid BLS secret key bytes"))?;
        let pk = sk.sk_to_pk();
        Ok(Self {
            secret_key: Zeroizing::new(sk_bytes),
            public_key: pk,
        })
    }

    /// Get the public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    /// Get the raw public key bytes (48 bytes for BLS12-381 MinSig scheme).
    #[cfg(test)]
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    /// Get access to the secret key for signing operations.
    fn secret_key(&self) -> Result<SecretKey> {
        SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| anyhow!("failed to deserialize secret key"))
    }

    /// Sign a message with the BLS private key using the HTTP signature DST.
    /// Returns the signature as a hex-encoded string (96 characters).
    pub fn sign_http_message(&self, message: &[u8]) -> Result<String> {
        self.sign_with_dst(message, HTTP_SIGNATURE_DST)
    }

    /// Sign a message with the BLS private key using the agreement signature DST.
    /// Returns the signature as a hex-encoded string (96 characters).
    pub fn sign_agreement_instruction(&self, message: &[u8]) -> Result<String> {
        self.sign_with_dst(message, AGREEMENT_SIGNATURE_DST)
    }

    /// Sign a message with the BLS private key using a specific DST.
    /// Returns the signature as a hex-encoded string (96 characters).
    fn sign_with_dst(&self, message: &[u8], dst: &[u8]) -> Result<String> {
        let sk = self.secret_key()?;
        let sig = sk.sign(message, dst, &[]);
        Ok(hex::encode(sig.to_bytes()))
    }

    /// Verify a BLS signature against a message and public key.
    #[cfg(test)]
    fn verify_http_signature(
        public_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool> {
        Self::verify_signature_with_dst(public_key_hex, message, signature_hex, HTTP_SIGNATURE_DST)
    }

    /// Verify a BLS signature against a message, public key, and DST.
    #[cfg(test)]
    fn verify_signature_with_dst(
        public_key_hex: &str,
        message: &[u8],
        signature_hex: &str,
        dst: &[u8],
    ) -> Result<bool> {
        let pk_bytes = hex::decode(public_key_hex).context("invalid public key hex")?;
        let pk =
            PublicKey::from_bytes(&pk_bytes).map_err(|_| anyhow!("invalid public key bytes"))?;

        let sig_bytes = hex::decode(signature_hex).context("invalid signature hex")?;
        let sig =
            Signature::from_bytes(&sig_bytes).map_err(|_| anyhow!("invalid signature bytes"))?;

        let result = sig.verify(true, message, dst, &[], &pk, true);
        Ok(result == blst::BLST_ERROR::BLST_SUCCESS)
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

    #[test]
    fn sign_http_message_produces_valid_signature() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"test message for signing";

        let signature = keypair.sign_http_message(message).unwrap();

        // BLS12-381 MinSig signature is 48 bytes = 96 hex characters
        assert_eq!(signature.len(), 96);

        // Verify the signature
        let is_valid =
            BlsKeyPair::verify_http_signature(&keypair.public_key_hex(), message, &signature)
                .unwrap();
        assert!(is_valid, "signature should be valid");
    }

    #[test]
    fn sign_agreement_instruction_produces_valid_signature() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"agreement instruction data";

        let signature = keypair.sign_agreement_instruction(message).unwrap();

        // BLS12-381 MinSig signature is 48 bytes = 96 hex characters
        assert_eq!(signature.len(), 96);

        // Verify with the agreement DST
        let is_valid = BlsKeyPair::verify_signature_with_dst(
            &keypair.public_key_hex(),
            message,
            &signature,
            AGREEMENT_SIGNATURE_DST,
        )
        .unwrap();
        assert!(is_valid, "agreement signature should be valid");
    }

    #[test]
    fn signature_verification_fails_for_wrong_message() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"original message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign_http_message(message).unwrap();

        let is_valid =
            BlsKeyPair::verify_http_signature(&keypair.public_key_hex(), wrong_message, &signature)
                .unwrap();
        assert!(!is_valid, "signature should not verify with wrong message");
    }

    #[test]
    fn signature_verification_fails_for_wrong_dst() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"test message";

        // Sign with HTTP DST
        let signature = keypair.sign_http_message(message).unwrap();

        // Try to verify with agreement DST
        let is_valid = BlsKeyPair::verify_signature_with_dst(
            &keypair.public_key_hex(),
            message,
            &signature,
            AGREEMENT_SIGNATURE_DST,
        )
        .unwrap();
        assert!(!is_valid, "signature should not verify with wrong DST");
    }

    #[test]
    fn verify_signature_rejects_invalid_public_key_hex() {
        let result = BlsKeyPair::verify_http_signature(
            "not-valid-hex",
            b"message",
            "00".repeat(48).as_str(),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid public key"));
    }

    #[test]
    fn verify_signature_rejects_invalid_signature_hex() {
        let keypair = BlsKeyPair::generate().unwrap();
        let result =
            BlsKeyPair::verify_http_signature(&keypair.public_key_hex(), b"message", "invalid");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid signature"));
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

    #[test]
    fn from_secret_key_hex_creates_valid_keypair() {
        let original = BlsKeyPair::generate().unwrap();
        let sk_hex = hex::encode(&*original.secret_key);
        let restored = BlsKeyPair::from_secret_key_hex(&sk_hex).unwrap();
        assert_eq!(restored.public_key_hex(), original.public_key_hex());
    }

    #[test]
    fn from_secret_key_hex_rejects_invalid_hex() {
        let result = BlsKeyPair::from_secret_key_hex("not-valid-hex");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid hex"));
    }

    #[test]
    fn from_secret_key_hex_rejects_wrong_length() {
        let short_hex = "aabbccdd"; // 4 bytes, not 32
        let result = BlsKeyPair::from_secret_key_hex(short_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }
}
