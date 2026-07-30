//! BLS key management module.
//!
//! Provides functionality for generating, storing (encrypted), and loading BLS keypairs.
//! The private key is encrypted using Argon2id for key derivation and AES-256-GCM for encryption.
//!
//! # Status
//!
//! `bls_key.enc` is the **legacy** at-rest format, kept so a node that predates
//! [`crate::crypto::keystore`] still comes up and can be migrated. New nodes
//! seal their key in `keystore.json` instead. The format below is therefore
//! frozen: the Argon2id parameters, the empty AAD, and the field names are all
//! load-bearing for reading files that already exist on operators' volumes.

use anyhow::{anyhow, Context, Result};
#[cfg(test)]
use blst::min_sig::Signature;
use blst::min_sig::{PublicKey, SecretKey};
#[cfg(test)]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, Kdf};

/// This format predates any notion of AAD and must keep sealing with none, or
/// every `bls_key.enc` already on disk stops opening.
const LEGACY_AAD: &[u8] = b"";

/// Domain Separation Tag for HTTP Message Signatures (RFC 9421).
pub const HTTP_SIGNATURE_DST: &[u8] = b"HORIZON_PORTAL_HTTP_SIG";

/// Domain Separation Tag for Kontor operation signatures (KONTOR_BLS_DST).
pub const KONTOR_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// BLS key file name stored in app data directory.
pub const BLS_KEY_FILENAME: &str = "bls_key.enc";

/// Encrypted BLS key file format.
#[derive(Serialize, Deserialize)]
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

// Manual Debug impl: avoid printing any of the encrypted material (salt, nonce,
// ciphertext). Only the sizes are safe to log.
impl std::fmt::Debug for EncryptedKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedKeyFile")
            .field("salt", &format_args!("<{} bytes>", self.salt.len()))
            .field("nonce", &format_args!("<{} bytes>", self.nonce.len()))
            .field(
                "ciphertext",
                &format_args!("<{} bytes>", self.ciphertext.len()),
            )
            .finish()
    }
}

/// A BLS keypair with the private key stored securely.
pub struct BlsKeyPair {
    secret_key: Zeroizing<Vec<u8>>,
    public_key: PublicKey,
}

// Manual Debug impl: the derived impl forwarded to `Vec<u8>`'s Debug which
// prints the raw secret-key bytes. Show only a short public-key fingerprint.
impl std::fmt::Debug for BlsKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk_hex = self.public_key_hex();
        let fingerprint = pk_hex.get(..8).unwrap_or(pk_hex.as_str());
        f.debug_struct("BlsKeyPair")
            .field("public_key", &format_args!("{fingerprint}..."))
            .finish()
    }
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

    /// The private key, in the same hex form [`Self::from_secret_key_hex`]
    /// accepts.
    ///
    /// This exists so a key can be moved between at-rest formats — a legacy
    /// `bls_key.enc` into [`crate::crypto::keystore`] — without a second
    /// representation of the secret being invented for the trip. `Zeroizing` so
    /// the caller cannot forget to scrub it; nothing else should be calling this.
    #[must_use]
    pub fn secret_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.secret_key.as_slice()))
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

    /// Sign a message with the BLS private key using the Kontor operation DST.
    /// Returns the signature as a hex-encoded string (96 characters).
    pub fn sign_kontor_op_message(&self, message: &[u8]) -> Result<String> {
        self.sign_with_dst(message, KONTOR_BLS_DST)
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
        let salt = aead::random_salt();
        let key = aead::derive_kek(password.as_bytes(), &salt, &Kdf::AT_REST)?;
        let (nonce, ciphertext) = aead::seal(&key, LEGACY_AAD, self.secret_key.as_slice())?;

        let key_file = EncryptedKeyFile {
            version: 1,
            salt,
            nonce,
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

        let key = aead::derive_kek(password.as_bytes(), &key_file.salt, &Kdf::AT_REST)?;

        let plaintext = aead::open(
            &key,
            LEGACY_AAD,
            &key_file.nonce,
            key_file.ciphertext.as_slice(),
        )
        .map_err(|_| {
            anyhow!("failed to decrypt private key: incorrect password or corrupted file")
        })?;

        let sk = SecretKey::from_bytes(&plaintext)
            .map_err(|_| anyhow!("failed to deserialize decrypted secret key"))?;
        let pk = sk.sk_to_pk();

        Ok(Self {
            secret_key: plaintext,
            public_key: pk,
        })
    }

    /// Check if a key file exists at the given path.
    pub async fn key_file_exists(path: &Path) -> Result<bool> {
        match fs::metadata(path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => {
                Err(anyhow::Error::new(e)
                    .context(format!("checking key file at {}", path.display())))
            }
        }
    }
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
    fn sign_kontor_op_message_produces_valid_signature() {
        let keypair = BlsKeyPair::generate().unwrap();
        let message = b"agreement instruction data";

        let signature = keypair.sign_kontor_op_message(message).unwrap();

        // BLS12-381 MinSig signature is 48 bytes = 96 hex characters
        assert_eq!(signature.len(), 96);

        // Verify with the Kontor operation DST
        let is_valid = BlsKeyPair::verify_signature_with_dst(
            &keypair.public_key_hex(),
            message,
            &signature,
            KONTOR_BLS_DST,
        )
        .unwrap();
        assert!(is_valid, "kontor op signature should be valid");
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

        // Try to verify with Kontor operation DST
        let is_valid = BlsKeyPair::verify_signature_with_dst(
            &keypair.public_key_hex(),
            message,
            &signature,
            KONTOR_BLS_DST,
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

    /// Pins the on-disk format. `bls_key.enc` files already exist on operators'
    /// volumes, so the parameters this test spells out — Argon2id at
    /// [`Kdf::AT_REST`], AES-256-GCM with no AAD, the raw secret as plaintext —
    /// are a compatibility contract, not an implementation detail. A file built
    /// by hand from the primitives must open through the real loader.
    #[tokio::test]
    async fn load_encrypted_reads_the_frozen_wire_format() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());
        let password = "test-password-123";

        let keypair = BlsKeyPair::generate().unwrap();
        let expected_pk = keypair.public_key_hex();

        let salt = vec![42u8; aead::SALT_SIZE];
        let key = aead::derive_kek(password.as_bytes(), &salt, &Kdf::AT_REST).unwrap();
        let (nonce, ciphertext) = aead::seal(&key, b"", keypair.secret_key.as_slice()).unwrap();

        let json = serde_json::to_string(&EncryptedKeyFile {
            version: 1,
            salt,
            nonce,
            ciphertext,
        })
        .unwrap();
        fs::write(&path, json).await.unwrap();

        let loaded = BlsKeyPair::load_encrypted(&path, password).await.unwrap();
        assert_eq!(loaded.public_key_hex(), expected_pk);
    }

    #[tokio::test]
    async fn save_and_load_encrypted_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());
        let password = "test-password-123";

        let original = BlsKeyPair::generate().unwrap();
        let original_pk = original.public_key_hex();

        original.save_encrypted(&path, password).await.unwrap();

        assert!(BlsKeyPair::key_file_exists(&path).await.unwrap());

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
        assert!(!BlsKeyPair::key_file_exists(path).await.unwrap());
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

    #[tokio::test]
    async fn load_encrypted_rejects_unsupported_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());

        let key_file = serde_json::json!({
            "version": 99,
            "salt": vec![0u8; 16],
            "nonce": vec![0u8; 12],
            "ciphertext": vec![0u8; 32],
        });
        tokio::fs::write(&path, serde_json::to_string_pretty(&key_file).unwrap())
            .await
            .unwrap();

        let result = BlsKeyPair::load_encrypted(&path, "password").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported key file version"),
            "error should mention unsupported version"
        );
    }

    #[tokio::test]
    async fn load_encrypted_rejects_corrupted_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(unique_filename());

        tokio::fs::write(&path, "not valid json").await.unwrap();

        let result = BlsKeyPair::load_encrypted(&path, "password").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("parse encrypted key file"),
            "error should mention parsing"
        );
    }

    #[tokio::test]
    async fn load_encrypted_rejects_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/key.enc");
        let result = BlsKeyPair::load_encrypted(path, "password").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("read encrypted key file"),
            "error should mention reading"
        );
    }

    #[test]
    fn debug_redacts_secret_key() {
        let keypair = BlsKeyPair::generate().unwrap();
        let sk_hex = hex::encode(&*keypair.secret_key);
        let pk_hex = keypair.public_key_hex();
        let debug_str = format!("{:?}", keypair);

        assert!(
            !debug_str.contains(&sk_hex),
            "Debug output must not contain the raw secret key hex; got: {debug_str}"
        );
        assert!(
            !debug_str.contains("secret_key"),
            "Debug output must not mention the secret_key field; got: {debug_str}"
        );

        let fingerprint = &pk_hex[..8];
        assert!(
            debug_str.contains(fingerprint),
            "Debug output should include the first 8 chars of the public key hex as a fingerprint; got: {debug_str}"
        );
    }

    #[test]
    fn encrypted_key_file_debug_redacts_byte_contents() {
        let key_file = EncryptedKeyFile {
            version: 1,
            salt: vec![0xAB; 16],
            nonce: vec![0xCD; 12],
            ciphertext: vec![0xEF; 48],
        };
        let debug_str = format!("{:?}", key_file);

        assert!(debug_str.contains("EncryptedKeyFile"));
        assert!(debug_str.contains("<16 bytes>"));
        assert!(debug_str.contains("<12 bytes>"));
        assert!(debug_str.contains("<48 bytes>"));
        // None of the raw byte values should appear.
        assert!(!debug_str.contains("171"), "salt byte 0xAB leaked");
        assert!(!debug_str.contains("205"), "nonce byte 0xCD leaked");
        assert!(!debug_str.contains("239"), "ciphertext byte 0xEF leaked");
    }

    #[tokio::test]
    async fn save_encrypted_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("sub").join("dir").join(unique_filename());

        let keypair = BlsKeyPair::generate().unwrap();
        keypair
            .save_encrypted(&nested, "password123")
            .await
            .unwrap();

        assert!(nested.exists(), "key file should be created in nested dir");
        let loaded = BlsKeyPair::load_encrypted(&nested, "password123")
            .await
            .unwrap();
        assert_eq!(loaded.public_key_hex(), keypair.public_key_hex());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn key_file_exists_propagates_permission_errors() {
        // Cover the Err arm (lines 269-272) of key_file_exists
        // by attempting to stat a file inside a directory we lack permissions for.
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let restricted = dir.path().join("restricted");
        fs::create_dir_all(&restricted).unwrap();
        let target = restricted.join(unique_filename());

        // Create the file then drop permissions on the parent dir
        fs::write(&target, b"placeholder").unwrap();
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000)).unwrap();

        let result = BlsKeyPair::key_file_exists(&target).await;

        // Restore permissions so tempdir can clean up
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755)).ok();

        assert!(
            result.is_err(),
            "permission errors should be propagated, got: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("checking key file at"),
            "error should include context: {err}"
        );
    }

    #[tokio::test]
    async fn save_encrypted_works_with_relative_filename_having_no_parent() {
        // Cover the path.parent() == None branch (line 213/217) of save_encrypted
        // by saving to a bare filename in the current working directory.
        use tokio::sync::Mutex;
        // Serialize to avoid current_dir races between tests.
        static CWD_LOCK: Mutex<()> = Mutex::const_new(());
        let _guard = CWD_LOCK.lock().await;

        let prev_cwd = std::env::current_dir().unwrap();
        let tmp = tempdir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let bare_name = format!("relative_{}.enc", unique_filename());
        let path = std::path::PathBuf::from(&bare_name);

        let keypair = BlsKeyPair::generate().unwrap();
        let result = keypair.save_encrypted(&path, "password123").await;

        // Restore CWD before any panics
        std::env::set_current_dir(prev_cwd).unwrap();

        result.expect("saving to bare filename should succeed");
        assert!(
            tmp.path().join(&bare_name).exists(),
            "bare filename should resolve relative to CWD"
        );
    }
}
