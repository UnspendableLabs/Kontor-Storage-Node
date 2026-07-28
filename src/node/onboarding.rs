//! Node onboarding module.
//!
//! Handles BLS key loading/import, node identity lookup, Portal authentication,
//! and registry nonce retrieval.

pub mod key_management;

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::PortalClient;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub use key_management::{get_password_reader, PasswordReader};

#[cfg(test)]
pub use key_management::BLS_PASSWORD_ENV;

#[cfg(test)]
pub use key_management::MockPasswordReader;

#[cfg(not(test))]
const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Shorter interval in unit tests so polling scenarios finish quickly.
#[cfg(test)]
const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Result of the onboarding process.
pub struct OnboardingResult {
    /// The BLS keypair for signing requests.
    pub keypair: crate::crypto::BlsKeyPair,
    /// The node ID returned by Portal lookup.
    pub node_id: String,
    /// The signer ID from the registry.
    pub signer_id: u64,
    /// JWT token for authenticated API requests.
    pub token: String,
    /// Next nonce for registry transactions.
    pub next_nonce: u64,
}

// Manual Debug impl: the keypair and JWT token are secrets and must never be
// printed. We redact both while still surfacing the non-sensitive identifiers.
impl std::fmt::Debug for OnboardingResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardingResult")
            .field("node_id", &self.node_id)
            .field("signer_id", &self.signer_id)
            .field("next_nonce", &self.next_nonce)
            .field("token", &"<redacted>")
            .field("keypair", &"<BlsKeyPair>")
            .finish()
    }
}

/// How far onboarding got.
///
/// The unregistered case is not an error. A Portal that has never seen this BLS
/// key — or has been reset since it last did — answers the lookup with a 404,
/// and the only way out is for an operator to register the key from a machine
/// holding the Horizon Wallet that owns it. Exiting here would take `/admin`
/// down with the node and leave them nothing to do it from, so the caller
/// starts the server anyway and waits.
pub enum OnboardingOutcome {
    /// Registered, authenticated, and ready to run.
    Ready(Box<OnboardingResult>),
    /// The BLS key loaded, but the Portal has no node for it.
    Unregistered(Box<UnregisteredNode>),
}

/// A loaded key the Portal does not recognize.
///
/// The public key is carried alongside the pair it came from because both
/// callers need it: one to tell the operator what to register, the other to
/// keep asking the Portal whether it has appeared.
pub struct UnregisteredNode {
    pub keypair: crate::crypto::BlsKeyPair,
    pub bls_pubkey: String,
}

impl std::fmt::Debug for UnregisteredNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnregisteredNode")
            .field("bls_pubkey", &self.bls_pubkey)
            .field("keypair", &"<BlsKeyPair>")
            .finish()
    }
}

impl OnboardingOutcome {
    /// The onboarding result, panicking if the node turned out to be
    /// unregistered.
    #[cfg(test)]
    fn expect_ready(self) -> OnboardingResult {
        match self {
            Self::Ready(result) => *result,
            Self::Unregistered(_) => panic!("expected a registered node"),
        }
    }
}

impl std::fmt::Debug for OnboardingOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(result) => f.debug_tuple("Ready").field(result).finish(),
            Self::Unregistered(node) => f.debug_tuple("Unregistered").field(node).finish(),
        }
    }
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
/// 1. Loads or imports the BLS keypair from disk / Horizon Wallet
/// 2. Looks up the node identity on Portal by BLS public key
/// 3. Authenticates via challenge/response to obtain a JWT
/// 4. Fetches the current registry nonce
///
/// Uses the appropriate password reader based on environment (BLS_PASSWORD env var or terminal).
pub async fn perform_onboarding(
    client: &PortalClient,
    config: &OnboardingConfig,
    writer: &mut impl Write,
) -> Result<OnboardingOutcome> {
    let password_reader = get_password_reader();
    perform_onboarding_with_reader(client, config, writer, password_reader.as_ref()).await
}

/// Perform the node onboarding process with a custom password reader.
/// This variant is useful for testing.
pub async fn perform_onboarding_with_reader(
    client: &PortalClient,
    config: &OnboardingConfig,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<OnboardingOutcome> {
    // Step 1: Load or import BLS keypair
    let key_path = key_management::get_key_path(config)?;
    let keypair = key_management::ensure_bls_keypair(&key_path, writer, password_reader).await?;
    let bls_pubkey = keypair.public_key_hex();
    writeln!(writer, "✓ BLS key loaded")?;

    // Step 2: Look up node by BLS public key
    writeln!(writer, "Looking up node identity...")?;
    let mut waiting = false;
    let (node_id, signer_id) = loop {
        let lookup = match client.lookup_node(&bls_pubkey).await {
            Ok(l) => l,
            Err(e) => {
                let is_not_found = e
                    .downcast_ref::<HttpStatusError>()
                    .map(|s| s.status == reqwest::StatusCode::NOT_FOUND)
                    .unwrap_or(false);
                if is_not_found {
                    if waiting {
                        writeln!(writer)?;
                    }
                    writeln!(
                        writer,
                        "\nNo node registered with this BLS public key.\n  \
                         BLS public key: {bls_pubkey}\n  \
                         Open /admin and register this key on the Portal to continue."
                    )?;
                    return Ok(OnboardingOutcome::Unregistered(Box::new(
                        UnregisteredNode {
                            keypair,
                            bls_pubkey,
                        },
                    )));
                }
                return Err(e);
            }
        };
        if let Some(sid) = lookup.signer_id {
            if waiting {
                writeln!(writer)?;
            }
            writeln!(
                writer,
                "✓ Node {} found (signer_id: {})",
                lookup.node_id, sid
            )?;
            break (lookup.node_id, sid);
        }
        if !waiting {
            writeln!(
                writer,
                "Node {} found but RegisterBlsKey transaction not yet confirmed.",
                lookup.node_id
            )?;
            write!(writer, "Waiting for on-chain confirmation")?;
            waiting = true;
        } else {
            write!(writer, ".")?;
        }
        writer.flush()?;
        tokio::time::sleep(REGISTRATION_POLL_INTERVAL).await;
    };

    // Step 3: Login (challenge/response)
    writeln!(writer, "Authenticating with Portal...")?;
    let challenge = client.login_challenge(&node_id).await?;
    // Horizon Portal verifies with `request.challenge.as_bytes()` (hex string UTF-8), not decoded bytes.
    let signature = keypair.sign_http_message(challenge.challenge.as_bytes())?;
    let login = client
        .login_submit(&node_id, &challenge.challenge, &signature, Some(0))
        .await?;
    writeln!(writer, "✓ Authenticated as {}", login.user_id)?;

    // Step 4: Fetch current nonce
    let registry = client.get_registry_entry(signer_id).await?;
    writeln!(writer, "✓ Registry nonce: {}", registry.next_nonce)?;

    Ok(OnboardingOutcome::Ready(Box::new(OnboardingResult {
        keypair,
        node_id,
        signer_id,
        token: login.token,
        next_nonce: registry.next_nonce,
    })))
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;
    use crate::crypto::BlsKeyPair;
    use serde_json::json;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mount_all_mocks_except_lookup(
        mock_server: &MockServer,
        node_id: &str,
        public_key: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token": "jwt-test-token",
                "user_id": node_id,
                "role": "node",
                "expires_in": 86400
            })))
            .mount(mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/signers/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "signer_id": 42,
                "x_only_pubkey": "abc123",
                "bls_pubkey": public_key,
                "next_nonce": 7
            })))
            .mount(mock_server)
            .await;
    }

    async fn mount_all_mocks(mock_server: &MockServer, node_id: &str, public_key: &str) {
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": node_id,
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(mock_server)
            .await;

        mount_all_mocks_except_lookup(mock_server, node_id, public_key).await;
    }

    #[tokio::test]
    async fn onboarding_succeeds_full_flow() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        mount_all_mocks(&mock_server, "node-test123", &public_key).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap()
            .expect_ready();

        assert_eq!(result.keypair.public_key_hex(), public_key);
        assert_eq!(result.node_id, "node-test123");
        assert_eq!(result.signer_id, 42);
        assert_eq!(result.token, "jwt-test-token");
        assert_eq!(result.next_nonce, 7);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("BLS key loaded"));
        assert!(output.contains("Node node-test123 found"));
        assert!(output.contains("Authenticated as node-test123"));
        assert!(output.contains("Registry nonce: 7"));
    }

    /// A 404 is the state a Portal reset leaves every node in. It must not be
    /// an error: the operator needs `/admin` up to register the key again, and
    /// the key they need is the one held here.
    #[tokio::test]
    async fn onboarding_reports_unregistered_when_lookup_returns_404() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": "node not found"
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let outcome = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap();

        match outcome {
            OnboardingOutcome::Unregistered(node) => {
                assert_eq!(node.bls_pubkey, public_key);
                assert_eq!(node.keypair.public_key_hex(), public_key);
            }
            OnboardingOutcome::Ready(_) => panic!("a 404 lookup cannot produce a ready node"),
        }

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("No node registered with this BLS public key"),
            "the operator needs to be told which key to register: {output}"
        );
        assert!(
            output.contains(&public_key),
            "the message must carry the key itself: {output}"
        );
        assert!(
            output.contains("/admin"),
            "the message must point at where registration happens: {output}"
        );
    }

    /// Both arms of the outcome end up in a `tracing` field or a panic message
    /// sooner or later, and neither may carry the secret key.
    #[test]
    fn debug_output_redacts_the_keypair_either_way() {
        let unregistered = OnboardingOutcome::Unregistered(Box::new(UnregisteredNode {
            keypair: BlsKeyPair::generate().unwrap(),
            bls_pubkey: "beef".to_string(),
        }));
        let rendered = format!("{unregistered:?}");
        assert!(rendered.contains("beef"), "{rendered}");
        assert!(rendered.contains("<BlsKeyPair>"), "{rendered}");

        let ready = OnboardingOutcome::Ready(Box::new(OnboardingResult {
            keypair: BlsKeyPair::generate().unwrap(),
            node_id: "node-debug".to_string(),
            signer_id: 7,
            token: "super-secret-jwt".to_string(),
            next_nonce: 1,
        }));
        let rendered = format!("{ready:?}");
        assert!(rendered.contains("node-debug"), "{rendered}");
        assert!(!rendered.contains("super-secret-jwt"), "{rendered}");
    }

    /// A node whose registration was still unconfirmed when the Portal was
    /// reset goes from "waiting" to "gone" mid-poll. The progress line has to
    /// be closed off before the message, or it runs onto the same line.
    #[tokio::test]
    async fn onboarding_reports_unregistered_after_waiting() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-pending",
                "signer_id": null,
                "bls_public_key": public_key
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_string("gone"))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let outcome = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap();

        assert!(matches!(outcome, OnboardingOutcome::Unregistered(_)));

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("Waiting for on-chain confirmation\n"),
            "the progress line must be terminated before the notice: {output}"
        );
    }

    /// Anything other than a 404 — the Portal down, a proxy in the way — is a
    /// real failure, and registering again would not fix it.
    #[tokio::test]
    async fn onboarding_fails_when_lookup_errors_for_another_reason() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("502"), "got: {err}");
    }

    #[tokio::test]
    async fn onboarding_succeeds_after_signer_id_pending() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // First mounted mock wins for equal priority: two pending lookups, then the default mock.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-pending",
                "signer_id": null,
                "bls_public_key": public_key
            })))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-pending",
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        mount_all_mocks_except_lookup(&mock_server, "node-pending", &public_key).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let result = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap()
            .expect_ready();

        assert_eq!(result.node_id, "node-pending");
        assert_eq!(result.signer_id, 42);

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("RegisterBlsKey transaction not yet confirmed"),
            "expected pending message, got: {output}"
        );
        assert!(output.contains('.'), "expected progress dots while waiting");
        assert!(
            output.contains("Node node-pending found (signer_id: 42)"),
            "expected success line after poll, got: {output}"
        );
    }

    #[tokio::test]
    async fn onboarding_fails_when_login_returns_error() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_bls.enc");
        let storage_dir = dir.path().join("storage");

        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        let public_key = keypair.public_key_hex();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        // Lookup succeeds
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", &public_key))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": "node-test123",
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        // Login challenge succeeds
        Mock::given(method("GET"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "challenge": hex::encode(b"test-challenge"),
                "expires_in": 300
            })))
            .mount(&mock_server)
            .await;

        // Login submit fails
        Mock::given(method("POST"))
            .and(path("/api/users/login"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid signature"
            })))
            .mount(&mock_server)
            .await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), storage_dir);
        let config = OnboardingConfig {
            bls_key_path: Some(key_path),
        };
        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err = perform_onboarding_with_reader(&client, &config, &mut buffer, &reader)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("status 401"),
            "expected 401 error, got: {err}"
        );
    }

    #[test]
    fn onboarding_config_default_has_no_bls_key_path() {
        let config = OnboardingConfig::default();
        assert!(config.bls_key_path.is_none());
    }

    #[test]
    fn onboarding_result_debug_impl() {
        let keypair = BlsKeyPair::generate().unwrap();
        let result = OnboardingResult {
            keypair,
            node_id: "node-debug".to_string(),
            signer_id: 42,
            token: "test-token".to_string(),
            next_nonce: 0,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("OnboardingResult"));
        assert!(
            debug_str.contains("<redacted>"),
            "Debug output must redact the JWT token, got: {debug_str}"
        );
        assert!(
            !debug_str.contains("test-token"),
            "Debug output must not contain the raw JWT token, got: {debug_str}"
        );
        assert!(
            debug_str.contains("<BlsKeyPair>"),
            "Debug output must use the <BlsKeyPair> placeholder, got: {debug_str}"
        );
        // Safety net: the old derive(Debug) would have printed this prefix,
        // leaking the secret_key bytes. Make sure we never do that again.
        assert!(
            !debug_str.contains("BlsKeyPair { sk:"),
            "Debug output must not expose BlsKeyPair internals, got: {debug_str}"
        );
        assert!(
            !debug_str.contains("secret_key"),
            "Debug output must not mention the secret_key field, got: {debug_str}"
        );
    }
}
