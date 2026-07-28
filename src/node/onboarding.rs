//! Node onboarding module.
//!
//! Handles BLS key loading/import, node identity lookup, Portal authentication,
//! and registry nonce retrieval.

pub mod key_management;

use crate::clients::http_helpers::HttpStatusError;
use crate::clients::PortalClient;
use crate::crypto::mnemonic::{DerivedIdentityInfo, MnemonicIdentity, MnemonicSettings};
use crate::node::registration;
use anyhow::{anyhow, Result};
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
    /// Set when the keys came from a mnemonic, so `/admin` can name the account
    /// and address this node runs as.
    pub derived: Option<DerivedIdentityInfo>,
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
    /// Set when the keys came from a mnemonic. On this outcome it carries the
    /// Taproot address a Portal admin still has to whitelist, which is the one
    /// thing standing between the node and a normal start.
    pub derived: Option<DerivedIdentityInfo>,
}

impl std::fmt::Debug for UnregisteredNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnregisteredNode")
            .field("bls_pubkey", &self.bls_pubkey)
            .field("derived", &self.derived)
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
    /// The seed phrase to derive from, when one is configured. `Some` puts the
    /// node in mnemonic mode: it derives its own keys, ignores the key file, and
    /// registers itself.
    ///
    /// Read from the environment by the caller rather than in here, so the
    /// whole flow stays a function of its arguments.
    pub mnemonic: Option<MnemonicSettings>,
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

/// Register a mnemonic-derived node with the Portal, after checking that doing
/// so is the right move.
///
/// Returns `true` if the Portal accepted the registration and the caller should
/// look the node up again, `false` if it refused for a reason an operator has to
/// act on — a whitelist entry, most often — and the node should fall back to
/// serving `/admin` and waiting.
///
/// # Errors
/// If the configured account is not the one this node is registered under. That
/// is fatal on purpose: see [`registration::find_registered_siblings`].
async fn self_register(
    client: &PortalClient,
    identity: &crate::crypto::MnemonicIdentity,
    writer: &mut impl Write,
) -> Result<bool> {
    writeln!(
        writer,
        "\nThe Portal does not know this BLS key yet. Checking why before registering..."
    )?;

    // Is this node's own Taproot address already registered, but against some
    // other BLS key? Registering again would not help — the Portal keys its
    // nodes by the xpub, so the row is already taken.
    if let Ok(existing) = client.check_node(&identity.node_id).await {
        if let Some(other) = existing
            .bls_public_key
            .filter(|key| !key.eq_ignore_ascii_case(&identity.bls_pubkey()))
        {
            return Err(anyhow!(
                "This node's Taproot address is already registered with a different BLS key.\n  \
                   node id:  {}\n  \
                   address:  {}\n  \
                   registered key: {other}\n  \
                   derived key:    {}\n  \
                 The mnemonic or the account index does not match the wallet this node \
                 was registered from.",
                identity.node_id,
                identity.taproot_address,
                identity.bls_pubkey(),
            ));
        }
    }

    let siblings = registration::find_registered_siblings(client, identity).await;
    if !siblings.is_empty() {
        return Err(registration::wrong_account_error(identity, &siblings));
    }

    writeln!(
        writer,
        "No node is registered on any account of this mnemonic. Registering account {}...",
        identity.account
    )?;

    let request = registration::build_self_registration(identity)?;
    match client.register_node(&request).await {
        Ok(response) => {
            writeln!(writer, "✓ Registered as {}", response.node_id)?;
            Ok(true)
        }
        Err(e) => {
            // Not fatal: the commonest cause by far is an address a Portal admin
            // has not whitelisted yet, and `/admin` plus the background lookup
            // will pick the node up the moment they do.
            writeln!(
                writer,
                "\nThe Portal refused the registration: {e:#}\n  \
                   Taproot address: {}\n  \
                 If this is ADDRESS_NOT_WHITELISTED, ask a Portal admin to whitelist that \
                 address. This node re-checks on its own once they have.",
                identity.taproot_address
            )?;
            Ok(false)
        }
    }
}

/// Perform the node onboarding process with a custom password reader.
/// This variant is useful for testing.
pub async fn perform_onboarding_with_reader(
    client: &PortalClient,
    config: &OnboardingConfig,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<OnboardingOutcome> {
    // Step 1: Derive, load, or import the BLS keypair
    let key_path = key_management::get_key_path(config)?;
    let keys = key_management::ensure_node_keys(
        &key_path,
        config.mnemonic.as_ref(),
        writer,
        password_reader,
    )
    .await?;
    let bls_pubkey = keys.keypair().public_key_hex();
    writeln!(writer, "✓ BLS key loaded")?;

    // Step 2: Look up node by BLS public key
    writeln!(writer, "Looking up node identity...")?;
    let mut waiting = false;
    // A mnemonic node registers itself, but only once per start: after the call
    // succeeds the row exists and the loop below waits for it to confirm. Trying
    // again on a second 404 would be an infinite loop over a Portal that is
    // telling us something we are not listening to.
    let mut self_registered = false;
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

                    match (keys.identity(), self_registered) {
                        (Some(identity), false) => {
                            self_registered = true;
                            if self_register(client, identity, writer).await? {
                                continue;
                            }
                        }
                        // Registered a moment ago and the Portal still says no.
                        // Nothing here can fix that, and nothing a browser could
                        // do would either — the node already signed everything.
                        (Some(identity), true) => writeln!(
                            writer,
                            "\nThe Portal accepted the registration but still has no node for \
                             this key.\n  \
                               BLS public key:  {bls_pubkey}\n  \
                               Taproot address: {}\n  \
                             Restart the node to try again.",
                            identity.taproot_address
                        )?,
                        (None, _) => writeln!(
                            writer,
                            "\nNo node registered with this BLS public key.\n  \
                             BLS public key: {bls_pubkey}\n  \
                             Open /admin and register this key on the Portal to continue."
                        )?,
                    }

                    let derived = keys.identity().map(MnemonicIdentity::info);
                    return Ok(OnboardingOutcome::Unregistered(Box::new(
                        UnregisteredNode {
                            keypair: keys.into_keypair(),
                            bls_pubkey,
                            derived,
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
    let derived = keys.identity().map(MnemonicIdentity::info);
    let keypair = keys.into_keypair();
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
        derived,
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

    /* ---------------- mnemonic mode ---------------- */

    /// The canonical BIP-39 phrase. Nothing about it is Horizon-specific — the
    /// derivation is pinned in `crypto::mnemonic`, and these tests only care
    /// that the keys reach the Portal calls.
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";

    fn derived_identity(account: u32) -> MnemonicIdentity {
        MnemonicIdentity::derive(&MnemonicSettings::new(
            TEST_PHRASE,
            crate::crypto::BitcoinNetwork::Signet,
            account,
        ))
        .unwrap()
    }

    fn mnemonic_config(account: u32) -> OnboardingConfig {
        OnboardingConfig {
            // Deliberately a path that cannot exist: mnemonic mode must never
            // touch the key file, and a bogus path proves it did not try.
            bls_key_path: Some(PathBuf::from("/nonexistent/bls_key.enc")),
            mnemonic: Some(MnemonicSettings::new(
                TEST_PHRASE,
                crate::crypto::BitcoinNetwork::Signet,
                account,
            )),
        }
    }

    /// Every lookup answers 404, so nothing on this mnemonic looks registered.
    /// Mounted last: wiremock takes the first mock that matches.
    async fn mount_lookup_catch_all_404(mock_server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(mock_server)
            .await;
    }

    async fn mount_check_404(mock_server: &MockServer, node_id: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/api/nodes/{node_id}/check")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .mount(mock_server)
            .await;
    }

    /// The whole point of the feature: a node handed nothing but a seed phrase
    /// registers itself and comes up, with no wallet and no key file.
    #[tokio::test]
    async fn a_mnemonic_node_registers_itself_and_onboards() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let identity = derived_identity(2);
        let public_key = identity.bls_pubkey();

        // First lookup 404s, which is what triggers the registration; the one
        // after it finds the row the Portal just wrote.
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key.as_str()))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": { "code": "NODE_NOT_FOUND", "message": "no node" }
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", public_key.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "signer_id": 42,
                "bls_public_key": public_key
            })))
            .mount(&mock_server)
            .await;

        mount_check_404(&mock_server, &identity.node_id).await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "x_only_pubkey": hex::encode(identity.x_only),
                "bls_public_key": public_key
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        mount_lookup_catch_all_404(&mock_server).await;
        mount_all_mocks_except_lookup(&mock_server, &identity.node_id, &public_key).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), dir.path().join("s"));
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let result =
            perform_onboarding_with_reader(&client, &mnemonic_config(2), &mut buffer, &reader)
                .await
                .unwrap()
                .expect_ready();

        assert_eq!(result.keypair.public_key_hex(), public_key);
        let derived = result.derived.expect("a mnemonic node carries its account");
        assert_eq!(derived.account, 2);
        assert_eq!(derived.taproot_address, identity.taproot_address);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains(&identity.taproot_address), "{output}");
        assert!(output.contains("Registered as"), "{output}");
    }

    /// The migration hazard. Two nodes run on accounts 2 and 3; pointing one at
    /// account 1 must stop, not quietly mint a third node and strand the
    /// agreements of the one it replaced.
    #[tokio::test]
    async fn a_wrong_account_index_is_fatal_and_names_the_right_one() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let configured = derived_identity(1);
        let real = derived_identity(3);

        Mock::given(method("GET"))
            .and(path("/api/nodes/lookup"))
            .and(query_param("bls_pubkey", real.bls_pubkey().as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": real.node_id,
                "signer_id": 42,
                "bls_public_key": real.bls_pubkey()
            })))
            .mount(&mock_server)
            .await;
        mount_check_404(&mock_server, &configured.node_id).await;
        // Registering here is the bug this test exists to catch.
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;
        mount_lookup_catch_all_404(&mock_server).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), dir.path().join("s"));
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let err =
            perform_onboarding_with_reader(&client, &mnemonic_config(1), &mut buffer, &reader)
                .await
                .unwrap_err()
                .to_string();

        assert!(err.contains("KONTOR_STORAGE_ACCOUNT_INDEX"), "{err}");
        assert!(err.contains("account 3"), "{err}");
        assert!(err.contains(&real.taproot_address), "{err}");
    }

    /// The other way the same mistake shows up: the address is registered, but
    /// against a BLS key this mnemonic does not derive. Registering again would
    /// not fix it — the Portal keys nodes by the xpub.
    #[tokio::test]
    async fn an_address_registered_with_another_key_is_fatal() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let identity = derived_identity(2);
        let stranger = BlsKeyPair::generate().unwrap().public_key_hex();

        Mock::given(method("GET"))
            .and(path(format!("/api/nodes/{}/check", identity.node_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "address": identity.taproot_address,
                "xpubkey": identity.xpubkey,
                "bls_public_key": stranger,
                "signer_id": 9
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;
        mount_lookup_catch_all_404(&mock_server).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), dir.path().join("s"));
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let err =
            perform_onboarding_with_reader(&client, &mnemonic_config(2), &mut buffer, &reader)
                .await
                .unwrap_err()
                .to_string();

        assert!(err.contains("different BLS key"), "{err}");
        assert!(err.contains(&stranger), "{err}");
    }

    /// The Portal took the registration and then kept answering 404. Retrying
    /// would spin forever, so the node gives up for this start — and says so in
    /// terms that do not send the operator looking for a wallet.
    #[tokio::test]
    async fn a_registration_the_portal_forgets_is_not_retried_forever() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let identity = derived_identity(5);

        mount_check_404(&mock_server, &identity.node_id).await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "node_id": identity.node_id,
                "x_only_pubkey": hex::encode(identity.x_only),
                "bls_public_key": identity.bls_pubkey()
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        mount_lookup_catch_all_404(&mock_server).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), dir.path().join("s"));
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let outcome =
            perform_onboarding_with_reader(&client, &mnemonic_config(5), &mut buffer, &reader)
                .await
                .unwrap();

        assert!(matches!(outcome, OnboardingOutcome::Unregistered(_)));

        let output = String::from_utf8(buffer).unwrap();
        assert!(
            output.contains("still has no node for this key"),
            "{output}"
        );
        assert!(!output.contains("Open /admin and register"), "{output}");
    }

    /// A refused registration is the whitelist, not a broken node. `/admin` has
    /// to come up so the operator can read the address off it, and the node has
    /// to keep polling so it recovers the moment the address is added.
    #[tokio::test]
    async fn a_refused_registration_leaves_the_node_unregistered_not_dead() {
        let mock_server = MockServer::start().await;
        let dir = tempdir().unwrap();
        let identity = derived_identity(4);

        mount_check_404(&mock_server, &identity.node_id).await;
        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {
                    "code": "ADDRESS_NOT_WHITELISTED",
                    "message": "Bitcoin address is not whitelisted for node registration"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        mount_lookup_catch_all_404(&mock_server).await;

        let client = crate::clients::PortalClient::new(mock_server.uri(), dir.path().join("s"));
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let outcome =
            perform_onboarding_with_reader(&client, &mnemonic_config(4), &mut buffer, &reader)
                .await
                .unwrap();

        match outcome {
            OnboardingOutcome::Unregistered(node) => {
                assert_eq!(node.bls_pubkey, identity.bls_pubkey());
                let derived = node.derived.expect("the address to whitelist must survive");
                assert_eq!(derived.taproot_address, identity.taproot_address);
            }
            OnboardingOutcome::Ready(_) => panic!("a refused registration cannot be ready"),
        }

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("ADDRESS_NOT_WHITELISTED"), "{output}");
        assert!(output.contains(&identity.taproot_address), "{output}");
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
            mnemonic: None,
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
            mnemonic: None,
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
            derived: None,
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
            derived: None,
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
            mnemonic: None,
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
            mnemonic: None,
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
            mnemonic: None,
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
            mnemonic: None,
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
            derived: None,
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
