//! Building the node's own `RegisterBlsKey` payload.
//!
//! # Why the node can sign most of its own registration
//!
//! The Portal's `POST /api/nodes/register` wants five fields, and only two of
//! them need a wallet:
//!
//! - `xpubkey` and `schnorr_sig` come from Horizon Wallet. The Schnorr half of
//!   the proof of possession is a BIP340 signature over
//!   `sha256("KONTOR_XONLY_TO_BLS_V1" || bls_pubkey)`, which needs the Taproot
//!   secret key. That key never leaves the wallet, so this is the one piece the
//!   node cannot produce for itself.
//! - `bls_pubkey`, `bls_sig` and `registration_signature` are all made with the
//!   BLS key — which the node holds, having imported it at onboarding. It builds
//!   them here.
//!
//! None of the five carry a nonce, a timestamp, or a server-issued challenge:
//! every one is a pure function of the two keys. A registration is therefore
//! replayable, which is what lets a node re-register itself unattended after the
//! Portal's database has been reset.

use anyhow::{anyhow, Context, Result};
use bip32::ExtendedKey;

use crate::clients::kontor_op::{
    build_signing_message, Inst, InstKind, SignerRef, REGISTER_BLS_KEY_GAS_LIMIT,
};
use crate::clients::portal::{RegisterNodeRequest, WhitelistRequestBody};
use crate::clients::PortalClient;
use crate::crypto::mnemonic::{ACCOUNT_INDEX_ENV, FIRST_ACCOUNT, REGISTER_NEW_ACCOUNT_ENV};
use crate::crypto::{BitcoinNetwork, BlsKeyPair, MnemonicIdentity, PublicIdentity};
use crate::node::known_identity::KnownIdentity;

/// Prefix the Portal signs over to bind a BLS key to a Taproot identity.
///
/// Mirrors `BLS_BINDING_PREFIX` in Horizon Portal's `api/users.rs`.
const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_BLS_TO_XONLY_V1";

/// Hex length of a BLS12-381 min-sig public key (96 bytes, on G2).
const BLS_PUBKEY_HEX_LEN: usize = 192;

/// Hex length of a BIP340 Schnorr signature (64 bytes).
const SCHNORR_SIG_HEX_LEN: usize = 128;

/// Derive the 32-byte x-only public key from an extended public key.
///
/// The Portal does this with `Xpub::from_str(..).public_key.x_only_public_key()`
/// and puts the result inside the message it verifies, so the two derivations
/// have to agree. For a well-formed xpub they do trivially: the serialized key
/// is already a compressed secp256k1 point, and x-only is that point minus its
/// `02`/`03` parity byte.
///
/// `bip32::ExtendedKey` is what does the base58check and the 78-byte length
/// check, which is also how `crate::crypto::mnemonic` serializes the xpub in the
/// first place — the two stay in step by construction. It is parsed rather than
/// `XPub`: this only needs the serialized bytes, and stopping short of a curve
/// point is what leaves room for the diagnosis below.
///
/// The derivation path is deliberately ignored — the account-level key *is* the
/// identity, exactly as the Portal treats it.
///
/// # Errors
/// If `xpub` is not valid base58check, is the wrong length, or does not carry a
/// compressed public key (an `xprv`, say, whose key field starts with `00`).
pub fn x_only_from_xpub(xpub: &str) -> Result<[u8; 32]> {
    let key: ExtendedKey = xpub
        .parse()
        .map_err(|e| anyhow!("invalid extended public key: {e}"))?;

    // The one malformed input worth naming. An `xprv` is the same length and
    // carries the same checksum rules, so everything above accepts it and the
    // 32 bytes below would be a secret key read as a public one.
    if key.key_bytes[0] != 0x02 && key.key_bytes[0] != 0x03 {
        return Err(anyhow!(
            "extended key does not hold a compressed public key (prefix {:#04x}); \
             an extended *private* key was probably passed",
            key.key_bytes[0]
        ));
    }

    Ok(key.key_bytes[1..]
        .try_into()
        .expect("a compressed secp256k1 point is 33 bytes"))
}

/// The message whose BLS signature proves the BLS key agrees to be bound to
/// `x_only`.
///
/// Mirrors Horizon Portal's `verify_bls_binding`.
fn bls_binding_message(x_only: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + x_only.len());
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(x_only);
    msg
}

/// The proof that this node holds both keys it names, shared by a
/// registration and a whitelist request.
///
/// Both Portal endpoints verify the same three bindings — the xpub's x-only
/// key, the Schnorr signature over the BLS key, and the BLS signature over the
/// x-only key — so both bodies are built from this one struct.
struct BindingProof {
    xpubkey: String,
    bls_pubkey: String,
    schnorr_sig: String,
    bls_sig: String,
    x_only: [u8; 32],
}

/// Validate the wallet-supplied fields and produce the BLS half of the proof.
///
/// `bls_sig` is recomputed rather than taken from the wallet: BLS signing is
/// deterministic, so the value is identical, and producing it here proves the
/// node actually holds the key it is about to bind.
///
/// # Errors
/// If the wallet-supplied fields are malformed, or if `bls_pubkey` is not this
/// node's own key.
fn build_binding_proof(
    keypair: &BlsKeyPair,
    xpubkey: &str,
    bls_pubkey: &str,
    schnorr_sig: &str,
) -> Result<BindingProof> {
    let bls_pubkey = bls_pubkey.trim().to_ascii_lowercase();
    let schnorr_sig = schnorr_sig.trim().to_ascii_lowercase();
    let xpubkey = xpubkey.trim();

    validate_hex_field(&bls_pubkey, BLS_PUBKEY_HEX_LEN, "bls_pubkey")?;
    validate_hex_field(&schnorr_sig, SCHNORR_SIG_HEX_LEN, "schnorr_sig")?;

    // The wallet account the operator picked must be the one whose BLS key this
    // node imported. Registering any other key would succeed on the Portal and
    // then leave the node looking up a public key it cannot sign for — the same
    // 404 it started from, one restart later.
    let own_pubkey = keypair.public_key_hex();
    if bls_pubkey != own_pubkey {
        return Err(anyhow!(
            "the wallet account's BLS key does not match this node's key.\n  \
             node:   {own_pubkey}\n  \
             wallet: {bls_pubkey}\n  \
             Select the wallet account this node's key was exported from."
        ));
    }

    let x_only = x_only_from_xpub(xpubkey)?;
    let bls_sig = keypair.sign_kontor_op_message(&bls_binding_message(&x_only))?;

    Ok(BindingProof {
        xpubkey: xpubkey.to_string(),
        bls_pubkey,
        schnorr_sig,
        bls_sig,
        x_only,
    })
}

/// Build the full `POST /api/nodes/register` body for this node's BLS key.
///
/// The op is signed with `nonce = 0` and `sponsored = true`, matching what the
/// Portal rebuilds in `verify_registration_signature`. Both are inside the
/// signed bytes — the registration has no account to draw a nonce from or gas
/// from yet, so the Portal publishes it and pays.
///
/// # Errors
/// If the wallet-supplied fields are malformed, if `bls_pubkey` is not this
/// node's own key, or if the op cannot be serialized.
pub fn build_registration_request(
    keypair: &BlsKeyPair,
    xpubkey: &str,
    bls_pubkey: &str,
    schnorr_sig: &str,
) -> Result<RegisterNodeRequest> {
    let proof = build_binding_proof(keypair, xpubkey, bls_pubkey, schnorr_sig)?;

    let inst = Inst {
        gas_limit: REGISTER_BLS_KEY_GAS_LIMIT,
        kind: InstKind::RegisterBlsKey {
            bls_pubkey: hex::decode(&proof.bls_pubkey).context("decoding bls_pubkey")?,
            schnorr_sig: hex::decode(&proof.schnorr_sig).context("decoding schnorr_sig")?,
            bls_sig: hex::decode(&proof.bls_sig).context("decoding bls_sig")?,
        },
    };
    let message = build_signing_message(&SignerRef::XOnlyPubkey(proof.x_only), 0, true, &inst)?;
    let registration_signature = keypair.sign_kontor_op_message(&message)?;

    Ok(RegisterNodeRequest {
        xpubkey: proof.xpubkey,
        bls_pubkey: proof.bls_pubkey,
        schnorr_sig: proof.schnorr_sig,
        bls_sig: proof.bls_sig,
        registration_signature,
    })
}

/// Build this node's own registration from its public identity.
///
/// The Schnorr signature is read off the record rather than produced, which is
/// the whole point of writing it down at setup: it is a signature over a fixed
/// digest, it carries no nonce, and the Portal accepts the same bytes forever.
/// A node that threw its seed away registers exactly as well as one that kept
/// it.
///
/// # Errors
/// If the recorded fields are malformed, or if `keypair` is not the key the
/// identity names.
pub fn build_registration_from_public(
    keypair: &BlsKeyPair,
    public: &PublicIdentity,
) -> Result<RegisterNodeRequest> {
    build_registration_request(
        keypair,
        &public.xpubkey,
        &public.bls_pubkey,
        &public.schnorr_binding_sig,
    )
}

/// The operator's contact details on a whitelist request, as the Portal admin
/// reviewing the queue will see them.
#[derive(Debug, Clone)]
pub struct WhitelistContact {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub company: Option<String>,
}

/// The Portal's own field caps, mirrored so a body that cannot pass review
/// there is refused here instead. This matters more than usual politeness:
/// whitelist submissions are quota'd per IP, and the Portal charges the quota
/// *before* validating — a malformed body spends an attempt and fixes nothing.
const CONTACT_NAME_MAX: usize = 100;
const CONTACT_EMAIL_MAX: usize = 320;
const CONTACT_COMPANY_MAX: usize = 200;

impl WhitelistContact {
    /// Trim every field and refuse what the Portal would refuse.
    ///
    /// The email check is the same shallow shape test the Portal applies — one
    /// `@`, no whitespace, a domain with a dot — not a deliverability check;
    /// its job is to catch a pasted-in-the-wrong-field mistake before it costs
    /// a quota attempt.
    ///
    /// # Errors
    /// If a required field is empty, over the Portal's cap, or the email is
    /// not shaped like one.
    fn normalized(&self) -> Result<Self> {
        let first_name = normalized_name(&self.first_name, "first name")?;
        let last_name = normalized_name(&self.last_name, "last name")?;

        let email = self.email.trim();
        if email.is_empty() {
            return Err(anyhow!("the contact email is required"));
        }
        if email.len() > CONTACT_EMAIL_MAX {
            return Err(anyhow!(
                "the contact email must be at most {CONTACT_EMAIL_MAX} characters"
            ));
        }
        let parts: Vec<&str> = email.split('@').collect();
        let domain_has_a_dot = parts
            .get(1)
            .is_some_and(|domain| domain.split('.').filter(|label| !label.is_empty()).count() >= 2);
        if email.chars().any(char::is_whitespace)
            || parts.len() != 2
            || parts[0].is_empty()
            || !domain_has_a_dot
        {
            return Err(anyhow!("'{email}' is not a valid email address"));
        }

        // Blank means absent: an empty string is what an untouched form field
        // sends, and the Portal stores `null` for it either way.
        let company = self
            .company
            .as_deref()
            .map(str::trim)
            .filter(|company| !company.is_empty());
        if company.is_some_and(|company| company.len() > CONTACT_COMPANY_MAX) {
            return Err(anyhow!(
                "the company name must be at most {CONTACT_COMPANY_MAX} characters"
            ));
        }

        Ok(Self {
            first_name,
            last_name,
            email: email.to_string(),
            company: company.map(str::to_string),
        })
    }
}

fn normalized_name(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("the contact {field} is required"));
    }
    if value.len() > CONTACT_NAME_MAX {
        return Err(anyhow!(
            "the contact {field} must be at most {CONTACT_NAME_MAX} characters"
        ));
    }
    Ok(value.to_string())
}

/// Build the full `POST /api/nodes/whitelist/request` body.
///
/// The proof of possession is the registration's own, minus the op signature —
/// the Portal wants to know the requester holds both keys before it queues
/// anything, and deriving the P2TR address from `xpubkey` itself is what keeps
/// anyone from requesting a whitelist entry for an address they do not own.
///
/// # Errors
/// If the key fields are malformed, if `bls_pubkey` is not this node's own
/// key, or if the contact details would not pass the Portal's validation.
pub fn build_whitelist_request(
    keypair: &BlsKeyPair,
    xpubkey: &str,
    bls_pubkey: &str,
    schnorr_sig: &str,
    contact: &WhitelistContact,
) -> Result<WhitelistRequestBody> {
    let contact = contact.normalized()?;
    let proof = build_binding_proof(keypair, xpubkey, bls_pubkey, schnorr_sig)?;

    Ok(WhitelistRequestBody {
        xpubkey: proof.xpubkey,
        bls_pubkey: proof.bls_pubkey,
        schnorr_sig: proof.schnorr_sig,
        bls_sig: proof.bls_sig,
        first_name: contact.first_name,
        last_name: contact.last_name,
        email: contact.email,
        company: contact.company,
    })
}

/// Build this node's own whitelist request from its public identity — the
/// mnemonic-node counterpart of [`build_whitelist_request`], reading the
/// Schnorr signature off the record exactly as
/// [`build_registration_from_public`] does.
///
/// # Errors
/// See [`build_whitelist_request`].
pub fn build_whitelist_from_public(
    keypair: &BlsKeyPair,
    public: &PublicIdentity,
    contact: &WhitelistContact,
) -> Result<WhitelistRequestBody> {
    build_whitelist_request(
        keypair,
        &public.xpubkey,
        &public.bls_pubkey,
        &public.schnorr_binding_sig,
        contact,
    )
}

/// Whether a refusal is one that offering the same registration again cannot
/// lift.
///
/// A registration is a pure function of this node's two keys — no nonce, no
/// timestamp, no challenge — so the same bytes go out every time. A Portal that
/// has judged those bytes malformed, or that has already given this node's xpub
/// to a different BLS key, answers identically forever; offering it again only
/// buries the line that says so.
///
/// `403` is deliberately not in this set. It is `ADDRESS_NOT_WHITELISTED`, the
/// one refusal a human clears without the request changing, and replaying
/// through it is what lets whitelisting an address be the whole of the
/// operator's work. Timeouts, rate limits and `5xx` are out for the neighbouring
/// reason: nothing about them says the registration was read and rejected.
///
/// `401` is out too, for a reason particular to this endpoint: registration is
/// unauthenticated by design — the node has no credential until it succeeds — so
/// the Portal itself has no way to answer `401`. One that arrives came from
/// something in front of it (an auth proxy, a staging gate, a WAF), which is a
/// deployment problem a human fixes without the request changing. Treating it as
/// final would strand the node until someone restarted the container, on exactly
/// the unattended deployments this path exists for.
#[must_use]
pub fn refusal_is_final(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::clients::http_helpers::HttpStatusError>()
        .is_some_and(|e| {
            matches!(
                e.status,
                reqwest::StatusCode::BAD_REQUEST
                    | reqwest::StatusCode::CONFLICT
                    | reqwest::StatusCode::UNPROCESSABLE_ENTITY
            )
        })
}

/// How many wallet accounts to probe when the configured one is unknown.
///
/// Only reached on the failure path, and only until something is found. Ten
/// covers every account a wallet realistically hands out before an operator
/// would have noticed something else was wrong.
///
/// Past it the scan finds nothing and the node registers, which is the
/// destructive outcome this whole path exists to avoid — so every message built
/// from a scan says how far it looked rather than implying it looked everywhere.
const ACCOUNT_SCAN_MAX: u32 = 10;

/// How the scan describes its own reach, for the messages that report it.
#[must_use]
pub fn account_scan_range() -> String {
    format!("accounts {FIRST_ACCOUNT}-{ACCOUNT_SCAN_MAX}")
}

/// A node the Portal knows, derived from the same mnemonic as this one.
#[derive(Debug, Clone)]
pub struct RegisteredSibling {
    pub account: u32,
    pub network: BitcoinNetwork,
    pub node_id: String,
    pub taproot_address: String,
}

impl std::fmt::Display for RegisteredSibling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "account {} ({}) -> {} ({})",
            self.account, self.network, self.node_id, self.taproot_address
        )
    }
}

/// Find identities from this mnemonic that the Portal has already registered.
///
/// # Why this runs before registering
///
/// A 404 on the configured account means one of two things: this node is new, or
/// the account index is wrong. Registering is right for the first and quietly
/// destructive for the second — it mints a *second* node while the real one
/// keeps the agreements, and the operator sees a node that works and does
/// nothing. Since every account of a mnemonic is one derivation away, the node
/// can simply go and look, and say which account it should have been.
///
/// Finding a sibling does not settle it, because one mnemonic legitimately backs
/// several nodes, one per account. What the scan produces is a list; whether that
/// list is fatal is [`REGISTER_NEW_ACCOUNT_ENV`]'s decision, and the caller's.
///
/// The configured account's own network is scanned first, then that account on
/// the other coin type: a wrong `KONTOR_STORAGE_NETWORK` produces exactly the
/// same symptom and costs one extra lookup to rule out.
///
/// Errors from individual probes are swallowed. This runs to explain a failure
/// that has already happened; a Portal that answers some lookups and not others
/// should not turn a clear diagnosis into an obscure one.
pub async fn find_registered_siblings(
    client: &PortalClient,
    identity: &MnemonicIdentity,
) -> Vec<RegisteredSibling> {
    let mut candidates: Vec<(u32, BitcoinNetwork)> = (FIRST_ACCOUNT..=ACCOUNT_SCAN_MAX)
        .filter(|account| *account != identity.account)
        .map(|account| (account, identity.network))
        .collect();
    candidates.push((identity.account, identity.network.counterpart()));

    let mut found = Vec::new();
    for (account, network) in candidates {
        let Ok(sibling) = identity.sibling(account, network) else {
            continue;
        };
        if client.lookup_node(&sibling.bls_pubkey()).await.is_ok() {
            found.push(RegisteredSibling {
                account,
                network,
                node_id: sibling.node_id,
                taproot_address: sibling.taproot_address,
            });
        }
    }
    found
}

/// The account guard's refusal, as a type the caller can recognise.
///
/// A distinct error rather than a bare `anyhow!` for one reason:
/// [`crate::app::runtime`] retries a failed activation on a backoff, and this is
/// the one failure that must not be retried. The guard only runs on a node that
/// still holds its seed — it derives neighbouring accounts to reach its verdict
/// — and the supervisor's retry re-opens the keystore, which by design has no
/// seed in it. So a second attempt would not reach the guard at all: it would
/// quietly do the thing the guard has just refused, thirty seconds later, and
/// register the second identity this error exists to prevent.
///
/// Retrying it is not trying again. It is going around it.
#[derive(Debug)]
pub struct WrongAccount(String);

impl std::fmt::Display for WrongAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WrongAccount {}

/// Whether a failure is [`WrongAccount`], anywhere in its chain.
///
/// Asked of the whole chain rather than the head, so wrapping the error in
/// context on the way up — which every layer between the guard and the
/// supervisor is free to do — cannot quietly turn a refusal back into something
/// retryable.
#[must_use]
pub fn refusal_is_the_account_guard(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<WrongAccount>())
}

/// The error an operator sees when the configured account may not be the
/// registered one.
///
/// Fatal, and permanently so: see [`WrongAccount`] for why it must not be
/// retried. The two things it can mean are not equally recoverable — a mistyped
/// [`ACCOUNT_INDEX_ENV`] strands a running node's agreements behind a second
/// identity, while a genuine second node is one environment variable away from
/// starting. So the message names both readings and the variable that picks
/// between them.
///
/// `known` is the identity this node last onboarded under, when there is one.
/// Reaching this error with a record that does not match means the account
/// index changed under a node that was already running as something else, which
/// is the most actionable thing that can be said here — so it is said first,
/// and it stands on its own: that branch never reads `siblings`, which is what
/// lets the caller raise this on a record alone when the scan came back empty.
///
/// The advice it gives — correct the variable and start again — is only true
/// because nothing has been sealed yet when this is raised. See
/// [`crate::node::onboarding::key_management::KeySource::Migrating`], which is
/// what keeps the keystore out of the way until the identity has been accepted.
#[must_use]
pub fn wrong_account_error(
    identity: &MnemonicIdentity,
    siblings: &[RegisteredSibling],
    known: Option<&KnownIdentity>,
) -> anyhow::Error {
    anyhow::Error::new(WrongAccount(wrong_account_message(
        identity, siblings, known,
    )))
}

fn wrong_account_message(
    identity: &MnemonicIdentity,
    siblings: &[RegisteredSibling],
    known: Option<&KnownIdentity>,
) -> String {
    if let Some(record) = known {
        return format!(
            "This node has already run as {} (account {}, {}), and {} = {} derives a \
             different identity.\n  \
               derived BLS key: {}\n  \
               derived address: {}\n\n  \
             Set {} back to {} — the account this node is registered under. Registering \
             account {} instead would create a second node and leave this one's \
             agreements behind.\n\n  \
             If you really mean to move this node to another account, delete its \
             storage directory's .node-identity.json and set {}=1.",
            record.node_id,
            record.account,
            record.network,
            ACCOUNT_INDEX_ENV,
            identity.account,
            identity.bls_pubkey(),
            identity.taproot_address,
            ACCOUNT_INDEX_ENV,
            record.account,
            identity.account,
            REGISTER_NEW_ACCOUNT_ENV,
        );
    }

    let listed = siblings
        .iter()
        .map(|sibling| format!("    {sibling}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "No node is registered for {} = {} ({}).\n  \
           derived BLS key: {}\n  \
           derived address: {}\n\n  \
         This mnemonic does have registered nodes, on other accounts ({} checked):\n{}\n\n  \
         If this node should be one of those, set {} to its account. Registering \
         account {} instead would create a second node and leave that one's \
         agreements behind.\n\n  \
         If this really is a new node alongside them, set {}=1 to say so and it \
         will register account {} on the next start.",
        ACCOUNT_INDEX_ENV,
        identity.account,
        identity.network,
        identity.bls_pubkey(),
        identity.taproot_address,
        account_scan_range(),
        listed,
        ACCOUNT_INDEX_ENV,
        identity.account,
        REGISTER_NEW_ACCOUNT_ENV,
        identity.account,
    )
}

/// What the node prints when it registers an account the guards would otherwise
/// have refused.
///
/// The operator has already said this is deliberate, so this is not a warning —
/// but whatever the node was refusing over is spelled out anyway, because the
/// one thing that would make the decision wrong is a picture that does not look
/// like the deployment they think they have.
///
/// Either half can be absent: a node can be moving off a recorded identity with
/// no sibling registered anywhere (the case a Portal reset produces), or
/// joining siblings having never run before.
#[must_use]
pub fn new_account_notice(
    identity: &MnemonicIdentity,
    siblings: &[RegisteredSibling],
    known: Option<&KnownIdentity>,
) -> String {
    let mut notice = format!(
        "{REGISTER_NEW_ACCOUNT_ENV} is set, so account {} registers as a new node.",
        identity.account
    );

    if let Some(record) = known {
        notice.push_str(&format!(
            "\n  This node last ran as {} (account {}, {}), which it now leaves behind.",
            record.node_id, record.account, record.network
        ));
    }

    if !siblings.is_empty() {
        let listed = siblings
            .iter()
            .map(|sibling| format!("    {sibling}"))
            .collect::<Vec<_>>()
            .join("\n");
        notice.push_str(&format!(
            "\n  It joins this mnemonic's existing nodes ({} checked):\n{listed}",
            account_scan_range(),
        ));
    }

    notice
}

/// Reject a hex field before it reaches the Portal, so a typo reads as a
/// message about the field rather than a 400 from somewhere else.
fn validate_hex_field(value: &str, expected_len: usize, field: &str) -> Result<()> {
    if value.len() != expected_len {
        return Err(anyhow!(
            "{field} must be {expected_len} hex characters, got {}",
            value.len()
        ));
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("{field} is not valid hex"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP32 test vector 1, chain m — the canonical xpub, and the x-only key is
    /// its serialized public key with the parity byte dropped.
    const BIP32_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const BIP32_X_ONLY: &str = "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

    fn keypair() -> BlsKeyPair {
        BlsKeyPair::generate().unwrap()
    }

    #[test]
    fn derives_the_x_only_key_the_portal_would_derive() {
        let x_only = x_only_from_xpub(BIP32_XPUB).unwrap();
        assert_eq!(hex::encode(x_only), BIP32_X_ONLY);
    }

    /// Every shape of malformed input an operator can paste into the field.
    ///
    /// Asserted as one property — refused, and named as the extended key it
    /// failed to be — rather than on the wording of each case, which belongs to
    /// `bip32` now. What matters here is that none of them reaches the Portal.
    #[test]
    fn malformed_extended_keys_are_refused() {
        let flipped = {
            let mut broken = BIP32_XPUB.to_string();
            broken.pop();
            broken.push('9');
            broken
        };

        for (label, input) in [
            ("surrounding whitespace", format!(" {BIP32_XPUB}")),
            ("a flipped character", flipped),
            ("characters outside the alphabet", "xpub0OIl".to_string()),
            ("an empty string", String::new()),
            // Valid base58check, but 25 bytes rather than 78: a plain address.
            (
                "a payload that is not 78 bytes",
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            ),
        ] {
            let err = x_only_from_xpub(&input)
                .expect_err(&format!("{label} must not parse as an extended key"));
            assert!(
                format!("{err:#}").contains("invalid extended public key"),
                "{label}: {err:#}"
            );
        }
    }

    /// The xprv counterpart of the vector above: same length, same checksum
    /// rules, but its key field starts with the `00` padding byte. The one
    /// malformed input that gets its own message, because the 32 bytes past
    /// that byte are a *secret* key and reading them as a public one would be
    /// silent.
    #[test]
    fn an_extended_private_key_is_rejected() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let err = x_only_from_xpub(xprv).unwrap_err();
        assert!(
            format!("{err:#}").contains("compressed public key"),
            "{err:#}"
        );
    }

    #[test]
    fn the_binding_message_is_the_prefix_then_the_key() {
        let msg = bls_binding_message(&[9u8; 32]);
        assert!(msg.starts_with(BLS_BINDING_PREFIX));
        assert_eq!(&msg[BLS_BINDING_PREFIX.len()..], &[9u8; 32]);
    }

    #[test]
    fn builds_a_request_carrying_the_nodes_own_key() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap();

        assert_eq!(request.xpubkey, BIP32_XPUB);
        assert_eq!(request.bls_pubkey, keypair.public_key_hex());
        assert_eq!(request.schnorr_sig, "ab".repeat(64));
        assert_eq!(request.bls_sig.len(), 96);
        assert_eq!(request.registration_signature.len(), 96);
    }

    fn derived(account: u32) -> MnemonicIdentity {
        MnemonicIdentity::derive(&crate::crypto::MnemonicSettings::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
            BitcoinNetwork::Signet,
            account,
        ))
        .unwrap()
    }

    /// A mnemonic node fills in the two fields the wallet used to supply, and
    /// the result has to be indistinguishable from the wallet-driven one.
    #[test]
    fn a_self_registration_is_shaped_like_a_wallet_one() {
        let identity = derived(2);
        let request =
            build_registration_from_public(&identity.keypair, &identity.public().unwrap()).unwrap();

        assert_eq!(request.xpubkey, identity.xpubkey);
        assert_eq!(request.bls_pubkey, identity.bls_pubkey());
        assert_eq!(request.schnorr_sig.len(), SCHNORR_SIG_HEX_LEN);
        assert_eq!(request.bls_sig.len(), 96);
        assert_eq!(request.registration_signature.len(), 96);

        // The x-only key the Portal will recover from `xpubkey` is the one the
        // node signed with.
        assert_eq!(x_only_from_xpub(&request.xpubkey).unwrap(), identity.x_only);
    }

    /// Same property the wallet path has: no nonce, no timestamp, so a node can
    /// re-register itself unattended after a Portal reset.
    #[test]
    fn a_self_registration_is_deterministic() {
        let identity = derived(3);
        let public = identity.public().unwrap();
        let first = build_registration_from_public(&identity.keypair, &public).unwrap();
        let second = build_registration_from_public(&identity.keypair, &public).unwrap();

        assert_eq!(first.schnorr_sig, second.schnorr_sig);
        assert_eq!(first.bls_sig, second.bls_sig);
        assert_eq!(first.registration_signature, second.registration_signature);
    }

    fn sibling_of(identity: &MnemonicIdentity) -> RegisteredSibling {
        RegisteredSibling {
            account: identity.account,
            network: identity.network,
            node_id: identity.node_id.clone(),
            taproot_address: identity.taproot_address.clone(),
        }
    }

    /// The message an operator acts on. It has to name the variable, the
    /// account they should have used, and its address.
    #[test]
    fn the_wrong_account_error_names_what_to_change() {
        let identity = derived(1);
        let real = derived(3);
        let siblings = vec![sibling_of(&real)];

        let rendered = wrong_account_error(&identity, &siblings, None).to_string();

        assert!(rendered.contains(ACCOUNT_INDEX_ENV), "{rendered}");
        assert!(rendered.contains("account 3"), "{rendered}");
        assert!(rendered.contains(&real.taproot_address), "{rendered}");
        assert!(rendered.contains(&identity.taproot_address), "{rendered}");
        assert!(rendered.contains("second node"), "{rendered}");
    }

    /// What [`crate::app::runtime`] reads to decide not to retry.
    ///
    /// Through a wrapper, because the supervisor sees this error after
    /// onboarding has had every chance to add context to it, and a check that
    /// only looked at the head of the chain would silently turn a refusal back
    /// into something worth trying again in thirty seconds.
    #[test]
    fn the_account_guards_refusal_is_recognisable_through_context() {
        let refusal = wrong_account_error(&derived(1), &[sibling_of(&derived(3))], None);
        assert!(refusal_is_the_account_guard(&refusal));

        let wrapped = refusal.context("onboarding failed").context("activating");
        assert!(
            refusal_is_the_account_guard(&wrapped),
            "the whole chain is asked, not just what is on top"
        );
        // And the operator still reads the message rather than the wrapper's
        // idea of it.
        assert!(format!("{wrapped:#}").contains(ACCOUNT_INDEX_ENV));

        assert!(
            !refusal_is_the_account_guard(&anyhow!("the Portal was not reachable")),
            "everything else is a failure worth retrying"
        );
    }

    /// The same message has to serve the operator whose account index is right
    /// and who is simply adding a node — otherwise the only way out of a correct
    /// refusal is to guess that one exists.
    #[test]
    fn the_wrong_account_error_offers_the_way_out() {
        let rendered =
            wrong_account_error(&derived(4), &[sibling_of(&derived(2))], None).to_string();

        assert!(rendered.contains(REGISTER_NEW_ACCOUNT_ENV), "{rendered}");
        assert!(rendered.contains("really is a new node"), "{rendered}");
    }

    /// Neither message may imply the scan looked everywhere: past account 10 it
    /// finds nothing, and "no siblings" would then read as proof there are none.
    #[test]
    fn both_messages_say_how_far_the_scan_looked() {
        let siblings = [sibling_of(&derived(2))];
        let range = account_scan_range();
        // Named from the first account, not from 0: the range an operator reads
        // has to be one they could type into `KONTOR_STORAGE_ACCOUNT_INDEX`.
        assert_eq!(range, "accounts 1-10");

        assert!(wrong_account_error(&derived(4), &siblings, None)
            .to_string()
            .contains(&range));
        assert!(new_account_notice(&derived(4), &siblings, None).contains(&range));
    }

    /// What an opted-in node prints. It is not a warning, but it has to list the
    /// siblings: a list that does not match the nodes the operator thinks they
    /// run is the one signal that the opt-in was a mistake.
    #[test]
    fn the_new_account_notice_lists_what_it_registers_alongside() {
        let existing = derived(2);
        let rendered = new_account_notice(&derived(4), &[sibling_of(&existing)], None);

        assert!(rendered.contains(REGISTER_NEW_ACCOUNT_ENV), "{rendered}");
        assert!(rendered.contains("account 4"), "{rendered}");
        assert!(rendered.contains(&existing.node_id), "{rendered}");
        assert!(rendered.contains(&existing.taproot_address), "{rendered}");
    }

    /// The line between "come back later" and "this will never work". Getting
    /// `403` on the wrong side of it would strand every node waiting on a
    /// whitelist entry, which is the ordinary way a node comes up.
    #[test]
    fn only_a_read_and_rejected_registration_is_final() {
        use crate::clients::http_helpers::HttpStatusError;

        let refusal = |status: reqwest::StatusCode| {
            anyhow::Error::new(HttpStatusError {
                status,
                body: String::new(),
                context: "register node".to_string(),
            })
        };

        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::CONFLICT,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert!(refusal_is_final(&refusal(status)), "{status}");
        }

        for status in [
            // The whitelist: cleared by a human, without the request changing.
            reqwest::StatusCode::FORBIDDEN,
            // Registration takes no credential, so this came from a proxy in
            // front of the Portal — a deployment problem, not a verdict on the
            // request. Giving up on it would strand the node until a restart.
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::REQUEST_TIMEOUT,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::BAD_GATEWAY,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(!refusal_is_final(&refusal(status)), "{status}");
        }

        // A transport failure never reached the Portal at all, so it says
        // nothing about the request.
        assert!(!refusal_is_final(&anyhow!("connection refused")));
    }

    fn record_of(identity: &MnemonicIdentity) -> KnownIdentity {
        KnownIdentity {
            node_id: identity.node_id.clone(),
            account: identity.account,
            network: identity.network.to_string(),
            bls_pubkey: identity.bls_pubkey(),
        }
    }

    /// A record on its own has to be enough to refuse. The scan cannot see a
    /// Portal that was reset, so pairing a reset with a mistyped account index
    /// leaves the record as the only evidence that this node is not new.
    #[test]
    fn a_record_alone_is_enough_to_name_the_wrong_account() {
        let was = derived(2);
        let now = derived(5);

        let rendered = wrong_account_error(&now, &[], Some(&record_of(&was))).to_string();

        assert!(rendered.contains(&was.node_id), "{rendered}");
        assert!(rendered.contains("account 2"), "{rendered}");
        assert!(rendered.contains(ACCOUNT_INDEX_ENV), "{rendered}");
        assert!(rendered.contains("second node"), "{rendered}");
        // Nothing was found, so nothing may be listed as if it had been.
        assert!(!rendered.contains(&account_scan_range()), "{rendered}");
    }

    /// The opted-in counterpart: the notice still has to say what is being left
    /// behind, even with no sibling to list.
    #[test]
    fn the_new_account_notice_names_a_record_with_no_siblings() {
        let was = derived(2);
        let rendered = new_account_notice(&derived(5), &[], Some(&record_of(&was)));

        assert!(rendered.contains(REGISTER_NEW_ACCOUNT_ENV), "{rendered}");
        assert!(rendered.contains(&was.node_id), "{rendered}");
        assert!(rendered.contains("leaves behind"), "{rendered}");
        // No siblings were found, so the notice must not gesture at a list.
        assert!(!rendered.contains("It joins"), "{rendered}");
    }

    fn contact() -> WhitelistContact {
        WhitelistContact {
            first_name: "Ada".to_string(),
            last_name: "Lovelace".to_string(),
            email: "ada@example.com".to_string(),
            company: None,
        }
    }

    /// The whitelist request carries the registration's own proof of
    /// possession: same fields, same bytes. Anything else and the Portal would
    /// accept one and refuse the other for the same keys.
    #[test]
    fn a_whitelist_request_carries_the_registrations_own_proof() {
        let identity = derived(2);
        let public = identity.public().unwrap();
        let registration = build_registration_from_public(&identity.keypair, &public).unwrap();
        let whitelist =
            build_whitelist_from_public(&identity.keypair, &public, &contact()).unwrap();

        assert_eq!(whitelist.xpubkey, registration.xpubkey);
        assert_eq!(whitelist.bls_pubkey, registration.bls_pubkey);
        assert_eq!(whitelist.schnorr_sig, registration.schnorr_sig);
        assert_eq!(whitelist.bls_sig, registration.bls_sig);
        assert_eq!(whitelist.first_name, "Ada");
        assert_eq!(whitelist.last_name, "Lovelace");
        assert_eq!(whitelist.email, "ada@example.com");
        assert_eq!(whitelist.company, None);
    }

    /// Whatever surrounds what the operator typed is not part of it, and a
    /// blank company is an absent one — the Portal stores `null` either way.
    #[test]
    fn whitelist_contact_fields_are_trimmed_and_blank_company_is_absent() {
        let keypair = keypair();
        let request = build_whitelist_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"ab".repeat(64),
            &WhitelistContact {
                first_name: "  Ada ".to_string(),
                last_name: " Lovelace  ".to_string(),
                email: " ada@example.com ".to_string(),
                company: Some("   ".to_string()),
            },
        )
        .unwrap();

        assert_eq!(request.first_name, "Ada");
        assert_eq!(request.last_name, "Lovelace");
        assert_eq!(request.email, "ada@example.com");
        assert_eq!(request.company, None);
    }

    /// Submissions are quota'd per IP and the Portal charges the quota before
    /// validating, so everything it would refuse has to be refused here first.
    #[test]
    fn a_contact_the_portal_would_refuse_never_leaves_the_node() {
        let keypair = keypair();
        let build = |contact: WhitelistContact| {
            build_whitelist_request(
                &keypair,
                BIP32_XPUB,
                &keypair.public_key_hex(),
                &"ab".repeat(64),
                &contact,
            )
        };

        for (label, broken) in [
            (
                "an empty first name",
                WhitelistContact {
                    first_name: " ".to_string(),
                    ..contact()
                },
            ),
            (
                "an over-long last name",
                WhitelistContact {
                    last_name: "x".repeat(101),
                    ..contact()
                },
            ),
            (
                "an email with no @",
                WhitelistContact {
                    email: "ada.example.com".to_string(),
                    ..contact()
                },
            ),
            (
                "an email with a bare domain",
                WhitelistContact {
                    email: "ada@example".to_string(),
                    ..contact()
                },
            ),
            (
                "an email with whitespace",
                WhitelistContact {
                    email: "ada lovelace@example.com".to_string(),
                    ..contact()
                },
            ),
            (
                "an over-long company",
                WhitelistContact {
                    company: Some("x".repeat(201)),
                    ..contact()
                },
            ),
        ] {
            assert!(build(broken).is_err(), "{label} must be refused locally");
        }
    }

    /// Same guard as the registration path: a request naming a key this node
    /// cannot sign for would queue an entry for somebody else's address.
    #[test]
    fn a_whitelist_request_for_a_foreign_bls_key_is_refused() {
        let mine = keypair();
        let other = keypair();
        let err = build_whitelist_request(
            &mine,
            BIP32_XPUB,
            &other.public_key_hex(),
            &"ab".repeat(64),
            &contact(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match this node's key"),
            "{err:#}"
        );
    }

    /// The two signatures answer different questions — "this BLS key accepts
    /// that Taproot key" and "this BLS key authorizes that op" — so they must
    /// not come out the same.
    #[test]
    fn the_binding_and_the_op_are_signed_separately() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap();
        assert_ne!(request.bls_sig, request.registration_signature);
    }

    /// Same inputs, same bytes: this is what makes a registration replayable
    /// after the Portal's database is wiped.
    #[test]
    fn the_request_is_deterministic() {
        let keypair = keypair();
        let pubkey = keypair.public_key_hex();
        let first =
            build_registration_request(&keypair, BIP32_XPUB, &pubkey, &"ab".repeat(64)).unwrap();
        let second =
            build_registration_request(&keypair, BIP32_XPUB, &pubkey, &"ab".repeat(64)).unwrap();
        assert_eq!(first.bls_sig, second.bls_sig);
        assert_eq!(first.registration_signature, second.registration_signature);
    }

    #[test]
    fn hex_fields_are_normalized_to_lowercase() {
        let keypair = keypair();
        let request = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex().to_ascii_uppercase(),
            &"AB".repeat(64),
        )
        .unwrap();
        assert_eq!(request.schnorr_sig, "ab".repeat(64));
    }

    #[test]
    fn a_foreign_bls_key_is_refused() {
        let mine = keypair();
        let other = keypair();
        let err = build_registration_request(
            &mine,
            BIP32_XPUB,
            &other.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match this node's key"),
            "{err:#}"
        );
    }

    #[test]
    fn a_wrong_length_schnorr_signature_is_refused() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, &keypair.public_key_hex(), "abcd")
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("schnorr_sig must be 128 hex characters"),
            "{err:#}"
        );
    }

    #[test]
    fn a_non_hex_schnorr_signature_is_refused() {
        let keypair = keypair();
        let err = build_registration_request(
            &keypair,
            BIP32_XPUB,
            &keypair.public_key_hex(),
            &"zz".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("schnorr_sig is not valid hex"),
            "{err:#}"
        );
    }

    /// The length check has to come before the identity check, or a malformed
    /// key reads as "wrong wallet account" and sends the operator hunting for
    /// the wrong problem.
    #[test]
    fn a_wrong_length_bls_key_is_refused_as_a_length_problem() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, "abcd", &"ab".repeat(64)).unwrap_err();
        assert!(
            format!("{err:#}").contains("bls_pubkey must be 192 hex characters"),
            "{err:#}"
        );
    }

    #[test]
    fn a_non_hex_bls_key_is_refused() {
        let keypair = keypair();
        let err =
            build_registration_request(&keypair, BIP32_XPUB, &"zz".repeat(96), &"ab".repeat(64))
                .unwrap_err();
        assert!(
            format!("{err:#}").contains("bls_pubkey is not valid hex"),
            "{err:#}"
        );
    }

    #[test]
    fn a_malformed_xpub_is_refused() {
        let keypair = keypair();
        let err = build_registration_request(
            &keypair,
            "not-an-xpub",
            &keypair.public_key_hex(),
            &"ab".repeat(64),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid extended public key"),
            "{err:#}"
        );
    }
}
