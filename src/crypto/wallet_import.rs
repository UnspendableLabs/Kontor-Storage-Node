//! Wallet blob decryption module.
//!
//! Decrypts BLS private key blobs exported from the Horizon Wallet.
//! The wallet export format uses Argon2id key derivation with AES-256 in **SIC/CTR** mode
//! (Dart `encrypt` package default `AESMode.sic`), with PKCS#7 padding — **not** AES-CBC.
//!
//! **Salt handling:** the Argon2 salt is the UTF-8 encoding of the base64 *text* in segment 2
//! (same as hash-wasm after `getUInt8Buffer` in Horizon's `encryption_worker.js`), not the
//! base64-decoded bytes.

use aes::Aes256;
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use cipher::block_padding::{Pkcs7, RawPadding};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use zeroize::Zeroizing;

const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 6;
const ARGON2_P_COST: u32 = 4;
const IV_BASE64_LEN: usize = 24;
/// Horizon Wallet's web worker passes the salt segment as a base64 *string* into Argon2;
/// hash-wasm UTF-8-encodes that string (see `getUInt8Buffer` in `encryption_worker.js`), it does
/// not base64-decode it. We must match that behaviour.
const EXPECTED_DECODED_SALT_BYTES: usize = 16;
const EXPECTED_IV_LEN: usize = 16;
const BLS_PRIVATE_KEY_HEX_LEN: usize = 64;

/// Decrypt an encrypted BLS private key blob exported from Horizon Wallet.
///
/// The input is a hex string (as displayed by the wallet export).
/// Returns the 64-character hex string of the raw 32-byte BLS private key.
pub fn decrypt_wallet_blob(encrypted_hex: &str, password: &str) -> Result<String> {
    let raw_bytes = hex::decode(encrypted_hex).context("invalid hex encoding in wallet blob")?;
    let payload = String::from_utf8(raw_bytes).context("hex-decoded bytes are not valid UTF-8")?;

    let stripped = payload
        .strip_prefix("A2::")
        .ok_or_else(|| anyhow!("wallet blob missing A2:: prefix"))?;

    let segments: Vec<&str> = stripped.split("::").collect();
    if segments.len() != 4 {
        return Err(anyhow!(
            "expected 4 segments after A2:: prefix, got {}",
            segments.len()
        ));
    }

    // Validate segment shape (16 random bytes, base64-encoded) — same blob as the wallet stores.
    let decoded_salt = STANDARD
        .decode(segments[2])
        .context("invalid base64 in salt segment")?;
    if decoded_salt.len() != EXPECTED_DECODED_SALT_BYTES {
        return Err(anyhow!(
            "expected base64 salt segment to decode to {EXPECTED_DECODED_SALT_BYTES} bytes, got {}",
            decoded_salt.len()
        ));
    }

    // Argon2 salt must be the UTF-8 bytes of the base64 *text* (not the decoded bytes).
    let salt_for_argon2 = segments[2].as_bytes();

    let iv_ct = segments[3];
    if iv_ct.len() < IV_BASE64_LEN {
        return Err(anyhow!(
            "segment 3 too short to contain IV ({IV_BASE64_LEN} base64 chars required)"
        ));
    }
    let (iv_b64, ct_b64) = iv_ct.split_at(IV_BASE64_LEN);

    let iv = STANDARD
        .decode(iv_b64)
        .context("invalid base64 in IV portion")?;
    if iv.len() != EXPECTED_IV_LEN {
        return Err(anyhow!(
            "expected {EXPECTED_IV_LEN}-byte IV, got {}",
            iv.len()
        ));
    }

    let ciphertext = STANDARD
        .decode(ct_b64)
        .context("invalid base64 in ciphertext portion")?;
    if ciphertext.is_empty() {
        return Err(anyhow!("ciphertext is empty"));
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt_for_argon2, key.as_mut())
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;

    // Horizon uses PointyCastle `AES/SIC/PKCS7` — AES-CTR with PKCS#7 (matches `Ctr128BE` + PointyCastle SIC).
    let mut buf = ciphertext;
    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key.as_ref(), &iv)
        .map_err(|e| anyhow!("failed to initialise AES-256-CTR decryptor: {e}"))?;
    cipher.apply_keystream(&mut buf);

    let unpadded = Pkcs7::raw_unpad(&buf)
        .map_err(|_| anyhow!("AES-CTR decryption failed (wrong password or corrupted data)"))?;
    let plaintext = Zeroizing::new(unpadded.to_vec());

    let hex_key =
        std::str::from_utf8(&plaintext).context("decrypted payload is not valid UTF-8")?;

    if hex_key.len() != BLS_PRIVATE_KEY_HEX_LEN {
        return Err(anyhow!(
            "expected {BLS_PRIVATE_KEY_HEX_LEN}-char hex private key, got {}",
            hex_key.len()
        ));
    }

    hex::decode(hex_key).context("decrypted key is not valid hex")?;

    Ok(hex_key.to_owned())
}

/// Build an encrypted wallet blob for testing purposes.
#[cfg(test)]
pub(crate) fn encrypt_test_blob(
    bls_hex_key: &str,
    password: &str,
    salt: &[u8; 16],
    iv: &[u8; 16],
) -> String {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_b64 = STANDARD.encode(salt);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_b64.as_bytes(), &mut key)
        .unwrap();

    const BS: usize = 16;
    let pt = bls_hex_key.as_bytes();
    let pad_len = BS - (pt.len() % BS);
    let mut padded = vec![0u8; pt.len() + pad_len];
    padded[..pt.len()].copy_from_slice(pt);
    Pkcs7::raw_pad(&mut padded, pt.len());

    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(&key, iv).unwrap();
    cipher.apply_keystream(&mut padded);
    let ciphertext = padded;

    let iv_b64 = STANDARD.encode(iv);
    let ct_b64 = STANDARD.encode(&ciphertext);

    let payload = format!("A2::v=19::m=65536,t=6,p=4::{salt_b64}::{iv_b64}{ct_b64}");
    hex::encode(payload.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_decrypt() {
        let bls_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let password = "hunter2";
        let salt = [1u8; 16];
        let iv = [2u8; 16];

        let blob = encrypt_test_blob(bls_key, password, &salt, &iv);
        let result = decrypt_wallet_blob(&blob, password).unwrap();
        assert_eq!(result, bls_key);
    }

    #[test]
    fn invalid_hex_input() {
        let result = decrypt_wallet_blob("zzzz_not_hex", "password");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("hex"),
            "error should mention hex"
        );
    }

    #[test]
    fn missing_a2_prefix() {
        let payload = "WRONG::v=19::m=65536,t=6,p=4::AAAA::BBBB";
        let blob = hex::encode(payload.as_bytes());
        let result = decrypt_wallet_blob(&blob, "password");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("A2:: prefix"),
            "error should mention A2:: prefix"
        );
    }

    #[test]
    fn wrong_number_of_segments() {
        let payload = "A2::v=19::m=65536,t=6,p=4";
        let blob = hex::encode(payload.as_bytes());
        let result = decrypt_wallet_blob(&blob, "password");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("4 segments"),
            "error should mention segment count"
        );
    }

    #[test]
    fn wrong_password_fails() {
        let bls_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let salt = [3u8; 16];
        let iv = [4u8; 16];

        let blob = encrypt_test_blob(bls_key, "correct-password", &salt, &iv);
        let result = decrypt_wallet_blob(&blob, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_base64_in_salt() {
        let payload = "A2::v=19::m=65536,t=6,p=4::!!!invalid!!!::AgICAgICAgICAgICAg==AAAA";
        let blob = hex::encode(payload.as_bytes());
        let result = decrypt_wallet_blob(&blob, "password");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("base64"),
            "error should mention base64"
        );
    }

    #[test]
    fn invalid_base64_in_ciphertext() {
        let salt_b64 = STANDARD.encode([5u8; 16]);
        let iv_b64 = STANDARD.encode([6u8; 16]);
        let payload = format!("A2::v=19::m=65536,t=6,p=4::{salt_b64}::{iv_b64}!!!invalid!!!");
        let blob = hex::encode(payload.as_bytes());
        let result = decrypt_wallet_blob(&blob, "password");
        assert!(result.is_err());
    }
}
