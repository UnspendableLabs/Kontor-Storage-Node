//! BLS key verification utilities.

use anyhow::{anyhow, Result};

/// Normalize a hex-encoded key by removing optional 0x prefix and converting to lowercase.
fn normalize_hex_key(key: &str) -> String {
    key.strip_prefix("0x")
        .or_else(|| key.strip_prefix("0X"))
        .unwrap_or(key)
        .to_lowercase()
}

/// Verify that the local BLS public key matches the one registered on Horizon Market.
pub fn verify_bls_key_match(local_key: &str, remote_key: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
