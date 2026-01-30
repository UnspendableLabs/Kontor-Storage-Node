//! RFC 9421 HTTP Message Signatures with BLS cryptography.
//!
//! Implements HTTP request signing for Portal API authentication.

use crate::crypto::BlsKeyPair;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Covered components for requests without body.
const COVERED_COMPONENTS_NO_BODY: &[&str] = &[
    "@method",
    "@target-uri",
    "x-request-timestamp",
    "x-request-nonce",
];

/// Covered components for requests with body.
const COVERED_COMPONENTS_WITH_BODY: &[&str] = &[
    "@method",
    "@target-uri",
    "content-digest",
    "content-length",
    "content-type",
    "x-request-timestamp",
    "x-request-nonce",
];

/// Build a Content-Digest header value using SHA-256 (RFC 9530).
pub fn content_digest(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    let encoded = BASE64.encode(hash);
    format!("sha-256=:{encoded}:")
}

/// Generate a unique nonce for request replay protection.
pub fn generate_nonce() -> String {
    format!("nonce-{}", Uuid::new_v4())
}

/// Get the current Unix timestamp in seconds.
///
/// # Panics
/// Panics if system time is before Unix epoch (should never happen in practice).
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Build the signing string for RFC 9421 HTTP Message Signatures.
///
/// The signing string is a newline-separated list of `component: value` pairs.
fn build_signing_string(
    method: &str,
    target_uri: &str,
    timestamp: u64,
    nonce: &str,
    body: Option<(&[u8], &str)>, // (body_bytes, content_type)
) -> String {
    let mut lines = Vec::new();

    // Derived components (lowercase method)
    lines.push(format!("@method: {}", method.to_lowercase()));
    lines.push(format!("@target-uri: {target_uri}"));

    // If body is present, add body-related headers
    if let Some((body_bytes, content_type)) = body {
        let digest = content_digest(body_bytes);
        lines.push(format!("content-digest: {digest}"));
        lines.push(format!("content-length: {}", body_bytes.len()));
        lines.push(format!("content-type: {content_type}"));
    }

    // Always include timestamp and nonce
    lines.push(format!("x-request-timestamp: {timestamp}"));
    lines.push(format!("x-request-nonce: {nonce}"));

    lines.join("\n")
}

/// Build the Signature-Input header value.
fn build_signature_input(node_id: &str, has_body: bool) -> String {
    let components = if has_body {
        COVERED_COMPONENTS_WITH_BODY
    } else {
        COVERED_COMPONENTS_NO_BODY
    };

    let component_list: String = components
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(" ");

    format!("sig1=({component_list});keyid=\"{node_id}\";alg=\"bls\"")
}

/// Sign an HTTP request and return the headers needed for authentication.
pub fn sign_request(
    keypair: &BlsKeyPair,
    node_id: &str,
    method: &str,
    target_uri: &str,
    body: Option<(&[u8], &str)>, // (body_bytes, content_type)
) -> Result<HeaderMap> {
    let timestamp = current_timestamp();
    let nonce = generate_nonce();

    sign_request_with_params(
        keypair, node_id, method, target_uri, body, timestamp, &nonce,
    )
}

/// Sign an HTTP request with explicit timestamp and nonce (useful for testing).
pub fn sign_request_with_params(
    keypair: &BlsKeyPair,
    node_id: &str,
    method: &str,
    target_uri: &str,
    body: Option<(&[u8], &str)>,
    timestamp: u64,
    nonce: &str,
) -> Result<HeaderMap> {
    let has_body = body.is_some();
    let signing_string = build_signing_string(method, target_uri, timestamp, nonce, body);

    // Sign the message
    let signature = keypair.sign_http_message(signing_string.as_bytes())?;

    // Build headers
    let mut headers = HeaderMap::new();

    let sig_input = build_signature_input(node_id, has_body);
    headers.insert(
        "Signature-Input",
        HeaderValue::from_str(&sig_input)
            .map_err(|e| anyhow::anyhow!("invalid signature-input header: {e}"))?,
    );

    let sig_header = format!("sig1=:{signature}:");
    headers.insert(
        "Signature",
        HeaderValue::from_str(&sig_header)
            .map_err(|e| anyhow::anyhow!("invalid signature header: {e}"))?,
    );

    headers.insert(
        "X-Request-Timestamp",
        HeaderValue::from_str(&timestamp.to_string())
            .map_err(|e| anyhow::anyhow!("invalid timestamp header: {e}"))?,
    );

    headers.insert(
        "X-Request-Nonce",
        HeaderValue::from_str(nonce).map_err(|e| anyhow::anyhow!("invalid nonce header: {e}"))?,
    );

    if let Some((body_bytes, content_type)) = body {
        let digest = content_digest(body_bytes);
        headers.insert(
            "Content-Digest",
            HeaderValue::from_str(&digest)
                .map_err(|e| anyhow::anyhow!("invalid content-digest header: {e}"))?,
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_str(content_type)
                .map_err(|e| anyhow::anyhow!("invalid content-type header: {e}"))?,
        );
        headers.insert("Content-Length", HeaderValue::from(body_bytes.len()));
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_digest_produces_rfc9530_format() {
        let body = b"hello world";
        let digest = content_digest(body);

        assert!(digest.starts_with("sha-256=:"));
        assert!(digest.ends_with(":"));

        // Verify the hash is correct
        let expected_hash = Sha256::digest(body);
        let expected = format!("sha-256=:{}:", BASE64.encode(expected_hash));
        assert_eq!(digest, expected);
    }

    #[test]
    fn generate_nonce_is_unique() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert!(nonce1.starts_with("nonce-"));
        assert!(nonce2.starts_with("nonce-"));
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn current_timestamp_is_reasonable() {
        let ts = current_timestamp();
        // Should be after 2024-01-01
        assert!(ts > 1704067200);
        // Should be before 2100-01-01
        assert!(ts < 4102444800);
    }

    #[test]
    fn build_signing_string_without_body() {
        let signing_string =
            build_signing_string("GET", "/api/agreements", 1704067200, "nonce-abc123", None);

        let expected = "@method: get\n\
                        @target-uri: /api/agreements\n\
                        x-request-timestamp: 1704067200\n\
                        x-request-nonce: nonce-abc123";
        assert_eq!(signing_string, expected);
    }

    #[test]
    fn build_signing_string_with_body() {
        let body = b"{}";
        let signing_string = build_signing_string(
            "POST",
            "/api/files",
            1704067200,
            "nonce-xyz789",
            Some((body, "application/json")),
        );

        let digest = content_digest(body);
        let expected = format!(
            "@method: post\n\
             @target-uri: /api/files\n\
             content-digest: {digest}\n\
             content-length: 2\n\
             content-type: application/json\n\
             x-request-timestamp: 1704067200\n\
             x-request-nonce: nonce-xyz789"
        );
        assert_eq!(signing_string, expected);
    }

    #[test]
    fn build_signature_input_without_body() {
        let input = build_signature_input("NODE-123", false);

        assert!(input.contains("sig1="));
        assert!(input.contains("@method"));
        assert!(input.contains("@target-uri"));
        assert!(input.contains("x-request-timestamp"));
        assert!(input.contains("x-request-nonce"));
        assert!(input.contains("keyid=\"NODE-123\""));
        assert!(input.contains("alg=\"bls\""));
        assert!(!input.contains("content-digest"));
    }

    #[test]
    fn build_signature_input_with_body() {
        let input = build_signature_input("NODE-456", true);

        assert!(input.contains("content-digest"));
        assert!(input.contains("content-length"));
        assert!(input.contains("content-type"));
    }

    #[test]
    fn sign_request_produces_all_required_headers() {
        let keypair = BlsKeyPair::generate().unwrap();
        let headers = sign_request(&keypair, "NODE-test", "GET", "/api/test", None).unwrap();

        assert!(headers.contains_key("Signature-Input"));
        assert!(headers.contains_key("Signature"));
        assert!(headers.contains_key("X-Request-Timestamp"));
        assert!(headers.contains_key("X-Request-Nonce"));

        // Should not have body headers
        assert!(!headers.contains_key("Content-Digest"));
    }

    #[test]
    fn sign_request_with_body_includes_digest_headers() {
        let keypair = BlsKeyPair::generate().unwrap();
        let body = b"{\"test\": true}";
        let headers = sign_request(
            &keypair,
            "NODE-test",
            "POST",
            "/api/test",
            Some((body, "application/json")),
        )
        .unwrap();

        assert!(headers.contains_key("Signature-Input"));
        assert!(headers.contains_key("Signature"));
        assert!(headers.contains_key("X-Request-Timestamp"));
        assert!(headers.contains_key("X-Request-Nonce"));
        assert!(headers.contains_key("Content-Digest"));
        assert!(headers.contains_key("Content-Type"));
        assert!(headers.contains_key("Content-Length"));
    }

    #[test]
    fn signature_format_is_correct() {
        let keypair = BlsKeyPair::generate().unwrap();
        let headers = sign_request(&keypair, "NODE-test", "GET", "/api/test", None).unwrap();

        let signature = headers.get("Signature").unwrap().to_str().unwrap();
        assert!(signature.starts_with("sig1=:"));
        assert!(signature.ends_with(":"));

        // Extract and verify signature length (should be 96 hex chars = 48 bytes)
        let sig_hex = signature.trim_start_matches("sig1=:").trim_end_matches(':');
        assert_eq!(sig_hex.len(), 96);
    }

    #[test]
    fn sign_request_with_params_uses_provided_values() {
        let keypair = BlsKeyPair::generate().unwrap();
        let timestamp = 1704067200u64;
        let nonce = "nonce-fixed";

        let headers = sign_request_with_params(
            &keypair,
            "NODE-test",
            "GET",
            "/api/test",
            None,
            timestamp,
            nonce,
        )
        .unwrap();

        assert_eq!(
            headers
                .get("X-Request-Timestamp")
                .unwrap()
                .to_str()
                .unwrap(),
            "1704067200"
        );
        assert_eq!(
            headers.get("X-Request-Nonce").unwrap().to_str().unwrap(),
            "nonce-fixed"
        );
    }
}
