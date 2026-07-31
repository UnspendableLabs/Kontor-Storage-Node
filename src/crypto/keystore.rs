//! The node's sealed key store.
//!
//! # What it holds
//!
//! One secret — the BLS private key — and the [`PublicIdentity`] describing what
//! that key speaks for. The mnemonic it was derived from is never here, in any
//! form; see [`crate::crypto::identity`] for why nothing needs it after setup.
//!
//! # Envelope encryption, and why the extra level
//!
//! The secret is sealed under a random **data key** (DEK). The DEK is then
//! sealed once per **slot**, each slot holding it under a different
//! key-encryption key. That is one indirection more than strictly necessary to
//! encrypt one secret, and it buys three things that matter operationally:
//!
//! - Adding a way to unlock the node — pasting a key into the platform's secret
//!   store — is one small write, not a re-encryption.
//! - Removing one does not invalidate the others.
//! - Rotating the DEK never needs the mnemonic back.
//!
//! It is the model LUKS and `age` use, for the same reasons.
//!
//! # The slots, and what each one actually defends against
//!
//! There is no ranking here, only different exposures, and the documentation
//! must not pretend otherwise:
//!
//! - [`SlotKind::File`] — a random key in `.seal-key` next to the keystore. This
//!   is the zero-configuration default, and it defends against the *environment*
//!   leaking: `docker inspect`, `/proc/<pid>/environ`, a platform dashboard, a
//!   crash dump, an APM agent capturing the environment. It does nothing against
//!   someone who can read the volume, since the key sits beside the ciphertext.
//! - [`SlotKind::Env`] — the same 32 bytes, held in `KONTOR_SEAL_KEY` instead.
//!   Defends against the *volume* leaking: a snapshot, a backup, a disk handed
//!   on. Does nothing against environment exposure.
//! - [`SlotKind::Passphrase`] — a human secret, held nowhere. Defends against
//!   both, and costs unattended restarts, since nothing on the machine can
//!   supply it. Reachable through this API, never created on the zero-config
//!   path, and never the only slot — [`Keystore::remove_slot`] enforces that.
//!
//! On a platform that holds both the environment and the volume, neither File
//! nor Env defends against the platform. Both defend against a mnemonic in an
//! environment variable, which is the actual thing being replaced: a stolen slot
//! key plus a stolen keystore yields one node's signing key, not a wallet.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, Kdf, KEY_SIZE};
use crate::crypto::identity::PublicIdentity;
use crate::crypto::BlsKeyPair;

/// The keystore file, inside the application data directory.
pub const KEYSTORE_FILENAME: &str = "keystore.json";

/// The generated seal key, alongside it. Dotted, like `.node-identity.json`,
/// because it is machinery rather than content.
pub const SEAL_KEY_FILENAME: &str = ".seal-key";

/// Environment variable holding a base64 seal key.
pub const SEAL_KEY_ENV: &str = "KONTOR_SEAL_KEY";

/// The only format version this node writes or reads.
const VERSION: u32 = 1;

/// Binds the sealed secret to its purpose, so a slot wrap can never be replayed
/// in its place.
const SECRET_AAD: &[u8] = b"KONTOR_KEYSTORE_SECRET_V1";

/// Domain separation for the fingerprint, so it cannot collide with any other
/// hash of the same bytes.
const FINGERPRINT_DOMAIN: &[u8] = b"KONTOR_SEAL_KEY_FP_V1";

/// How a seal key reaches this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotKind {
    /// `KONTOR_SEAL_KEY`.
    Env,
    /// `.seal-key` next to the keystore.
    File,
    /// Typed by a human at `/admin`. Never available at boot.
    Passphrase,
}

impl SlotKind {
    /// Whether a node holding only this kind of slot can come back from a
    /// restart without a human.
    #[must_use]
    pub fn is_unattended(self) -> bool {
        matches!(self, Self::Env | Self::File)
    }

    /// The AAD binding a wrap to the slot it belongs to.
    fn aad(self) -> &'static [u8] {
        match self {
            Self::Env => b"KONTOR_KEYSTORE_SLOT_V1:env",
            Self::File => b"KONTOR_KEYSTORE_SLOT_V1:file",
            Self::Passphrase => b"KONTOR_KEYSTORE_SLOT_V1:passphrase",
        }
    }
}

impl fmt::Display for SlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Env => "env",
            Self::File => "file",
            Self::Passphrase => "passphrase",
        })
    }
}

/// Material that can unwrap a slot.
///
/// A raw key is used as the key-encryption key directly: it is already 32
/// uniform random bytes, and running Argon2 over it would cost 64 MiB per boot
/// to add nothing. A passphrase is not uniform, so it carries the passphrase
/// itself and the KEK is derived per slot from that slot's own salt.
#[derive(Clone)]
pub enum SealKey {
    Raw {
        kind: SlotKind,
        key: Zeroizing<[u8; KEY_SIZE]>,
    },
    Passphrase(Zeroizing<String>),
}

// Manual Debug: the whole point of the type is that its contents never reach a
// log line.
impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealKey")
            .field("kind", &self.kind())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SealKey {
    /// Wrap 32 raw bytes as a key of the given kind. Test-only: production
    /// keys are generated or decoded, never assembled by hand.
    #[cfg(test)]
    #[must_use]
    pub fn raw(kind: SlotKind, key: Zeroizing<[u8; KEY_SIZE]>) -> Self {
        Self::Raw { kind, key }
    }

    /// A freshly generated random key.
    #[must_use]
    pub fn generate(kind: SlotKind) -> Self {
        Self::Raw {
            kind,
            key: aead::random_key(),
        }
    }

    /// A key from an operator-typed passphrase.
    #[must_use]
    pub fn passphrase(value: impl Into<String>) -> Self {
        Self::Passphrase(Zeroizing::new(value.into()))
    }

    /// Decode a base64 key as it appears in `KONTOR_SEAL_KEY` or `.seal-key`.
    ///
    /// # Errors
    /// If the text is not base64, or does not decode to exactly 32 bytes.
    pub fn decode(kind: SlotKind, encoded: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            BASE64
                .decode(encoded.trim())
                .with_context(|| format!("{kind} seal key is not valid base64"))?,
        );
        if bytes.len() != KEY_SIZE {
            return Err(anyhow!(
                "{kind} seal key must decode to {KEY_SIZE} bytes, got {}",
                bytes.len()
            ));
        }

        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        key.copy_from_slice(&bytes);
        Ok(Self::Raw { kind, key })
    }

    /// The base64 form, for showing once in `/admin` or writing to `.seal-key`.
    ///
    /// `None` for a passphrase, for the same reason [`Self::fingerprint`] is:
    /// the two callers are "write this to `.seal-key`" and "hand this back to
    /// the browser", and neither is ever a thing to do with a secret an
    /// operator typed and holds elsewhere. Returning the passphrase here would
    /// make writing it to the volume a one-character mistake.
    #[must_use]
    pub fn encode(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Raw { key, .. } => Some(Zeroizing::new(BASE64.encode(key.as_slice()))),
            Self::Passphrase(_) => None,
        }
    }

    /// Which slot this key opens.
    #[must_use]
    pub fn kind(&self) -> SlotKind {
        match self {
            Self::Raw { kind, .. } => *kind,
            Self::Passphrase(_) => SlotKind::Passphrase,
        }
    }

    /// A short identifier an operator can compare between a log line and a
    /// browser without either of them showing the key.
    ///
    /// `None` for a passphrase, and that is the whole point of the return type.
    /// A raw key is 32 uniform random bytes, so four bytes of a hash of it
    /// narrows nothing: there is no list to try. A passphrase is chosen by a
    /// human, and this value is published — [`crate::server::admin::seal`]
    /// returns it in a body the sealed channel deliberately does not cover. A
    /// fingerprint of it would let anyone who saw that body confirm guesses
    /// offline at one `SHA-256` each, against the 64 MiB of Argon2id per guess
    /// that opening the keystore itself costs. The identifier is not worth that.
    #[must_use]
    pub fn fingerprint(&self) -> Option<String> {
        let Self::Raw { key, .. } = self else {
            return None;
        };

        Some(aead::fingerprint(FINGERPRINT_DOMAIN, key.as_slice()))
    }

    /// The key-encryption key for a slot, deriving it when the slot needs a salt.
    fn kek(&self, slot: &Slot) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
        match self {
            Self::Raw { key, .. } => Ok(key.clone()),
            Self::Passphrase(value) => {
                let salt = slot
                    .salt
                    .as_deref()
                    .ok_or_else(|| anyhow!("passphrase slot is missing its salt"))?;
                let salt = hex::decode(salt).context("passphrase slot has a malformed salt")?;
                aead::derive_kek(value.as_bytes(), &salt, &slot.kdf.unwrap_or(Kdf::AT_REST))
            }
        }
    }

    /// The salt and parameters a new slot for this key needs, if any.
    fn new_slot_kdf(&self) -> (Option<String>, Option<Kdf>) {
        match self {
            Self::Raw { .. } => (None, None),
            Self::Passphrase(_) => (Some(hex::encode(aead::random_salt())), Some(Kdf::AT_REST)),
        }
    }
}

/// One way of unwrapping the data key.
#[derive(Clone, Serialize, Deserialize)]
struct Slot {
    kind: SlotKind,
    /// Present only on passphrase slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    /// Present only on passphrase slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<Kdf>,
    nonce: String,
    ct: String,
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot")
            .field("kind", &self.kind)
            .field("ct", &format_args!("<{} chars>", self.ct.len()))
            .finish_non_exhaustive()
    }
}

/// A sealed byte string and the nonce it was sealed with.
#[derive(Clone, Serialize, Deserialize)]
struct SealedBytes {
    nonce: String,
    ct: String,
}

impl fmt::Debug for SealedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBytes")
            .field("ct", &format_args!("<{} chars>", self.ct.len()))
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    slots: Vec<Slot>,
    secret: SealedBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public: Option<PublicIdentity>,
}

/// The node's sealed key store, as read from or written to disk.
#[derive(Debug, Clone)]
pub struct Keystore {
    path: PathBuf,
    file: KeystoreFile,
}

impl Keystore {
    /// Where the keystore lives for a given application directory.
    #[must_use]
    pub fn path_in(app_dir: &Path) -> PathBuf {
        app_dir.join(KEYSTORE_FILENAME)
    }

    /// Read the keystore, or `None` if this node has never been provisioned.
    ///
    /// A file that exists but cannot be parsed is an **error**, not a `None`.
    /// The two states mean opposite things: `None` invites the setup wizard to
    /// provision a fresh identity, and doing that on top of a keystore that is
    /// merely unreadable would strand the real key behind a new one.
    ///
    /// # Errors
    /// If the file cannot be read, parsed, or carries an unknown version.
    pub async fn load(app_dir: &Path) -> Result<Option<Self>> {
        let path = Self::path_in(app_dir);
        let raw = match tokio::fs::read(&path).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("reading the keystore at {}", path.display())))
            }
        };

        let file: KeystoreFile = serde_json::from_slice(&raw)
            .with_context(|| format!("parsing the keystore at {}", path.display()))?;

        aead::check_version(&path, file.version, VERSION)?;

        if file.slots.is_empty() {
            return Err(anyhow!(
                "the keystore at {} has no slots, so nothing can unlock it",
                path.display()
            ));
        }

        Ok(Some(Self { path, file }))
    }

    /// Create a keystore around a BLS secret, sealed for one key.
    ///
    /// The secret is passed as hex because that is the form every source of one
    /// already produces — mnemonic derivation, a wallet export, the legacy key
    /// file — and re-parsing it here would only add a way to disagree.
    ///
    /// # Errors
    /// If the secret is not a valid BLS key, if it disagrees with `public`, or
    /// if the file cannot be written.
    pub fn provision(
        app_dir: &Path,
        secret_hex: &Zeroizing<String>,
        public: Option<PublicIdentity>,
        key: &SealKey,
    ) -> Result<Self> {
        // Refuse to seal something that is not a key, and refuse to seal a key
        // that does not match the identity it is being filed under. Both are
        // silent-corruption failures otherwise: the first surfaces at the next
        // boot, the second as a Portal 404 nobody can explain.
        let keypair = BlsKeyPair::from_secret_key_hex(secret_hex)
            .context("the secret being sealed is not a valid BLS private key")?;
        if let Some(identity) = &public {
            let derived = keypair.public_key_hex();
            if derived != identity.bls_pubkey {
                return Err(anyhow!(
                    "the secret being sealed does not match the identity it is filed under\n  \
                     identity: {}\n  key:      {derived}",
                    identity.bls_pubkey
                ));
            }
        }

        let dek = aead::random_key();
        let (nonce, ct) = aead::seal(&dek, SECRET_AAD, secret_hex.as_bytes())?;

        let mut store = Self {
            path: Self::path_in(app_dir),
            file: KeystoreFile {
                version: VERSION,
                slots: Vec::new(),
                secret: SealedBytes {
                    nonce: hex::encode(nonce),
                    ct: hex::encode(ct),
                },
                public,
            },
        };

        store.file.slots.push(wrap_dek(&dek, key)?);
        store.write()?;
        Ok(store)
    }

    /// The identity this keystore describes, readable without unsealing.
    #[must_use]
    pub fn public(&self) -> Option<&PublicIdentity> {
        self.file.public.as_ref()
    }

    /// Which kinds of key can open this keystore.
    #[must_use]
    pub fn slots(&self) -> Vec<SlotKind> {
        self.file.slots.iter().map(|slot| slot.kind).collect()
    }

    /// Open the BLS key.
    ///
    /// # Errors
    /// If no slot matches this key's kind, if the key is wrong, or if the key
    /// that comes out is not the one [`Self::public`] describes.
    pub fn unseal(&self, key: &SealKey) -> Result<BlsKeyPair> {
        let dek = self.unwrap_dek(key)?;
        let secret_hex = aead::open(
            &dek,
            SECRET_AAD,
            &hex::decode(&self.file.secret.nonce).context("malformed secret nonce")?,
            &hex::decode(&self.file.secret.ct).context("malformed secret ciphertext")?,
        )
        .context("the keystore's data key did not open its secret; the file is corrupt")?;

        let secret_hex = Zeroizing::new(
            String::from_utf8(secret_hex.to_vec()).context("the sealed secret is not text")?,
        );
        let keypair = BlsKeyPair::from_secret_key_hex(&secret_hex)
            .context("the sealed secret is not a valid BLS private key")?;

        // The public record and the sealed key are written together and must
        // stay together. If they ever disagree, the node would onboard as one
        // identity while signing as another, and the Portal would answer 404
        // forever with nothing to point at.
        if let Some(identity) = self.public() {
            let derived = keypair.public_key_hex();
            if derived != identity.bls_pubkey {
                return Err(anyhow!(
                    "this keystore's sealed key does not match the identity it records\n  \
                     recorded: {}\n  sealed:   {derived}",
                    identity.bls_pubkey
                ));
            }
        }

        Ok(keypair)
    }

    /// Add another way to unlock this keystore, replacing any existing slot of
    /// the same kind.
    ///
    /// # Errors
    /// If `unlock` does not open the keystore, or the file cannot be written.
    pub fn add_slot(&mut self, unlock: &SealKey, new: &SealKey) -> Result<()> {
        let dek = self.unwrap_dek(unlock)?;
        let slot = wrap_dek(&dek, new)?;

        self.file
            .slots
            .retain(|existing| existing.kind != new.kind());
        self.file.slots.push(slot);
        self.write()
    }

    /// Drop a way of unlocking this keystore.
    ///
    /// Refuses to leave the node unopenable, and refuses to leave it unable to
    /// come back from a restart on its own — a keystore whose only slot is a
    /// passphrase turns every crash into an outage that waits for a human.
    ///
    /// # Errors
    /// If no such slot exists, if removing it would strand the node, or if the
    /// file cannot be written.
    pub fn remove_slot(&mut self, kind: SlotKind) -> Result<()> {
        if !self.file.slots.iter().any(|slot| slot.kind == kind) {
            return Err(anyhow!("this keystore has no {kind} slot"));
        }

        let remaining: Vec<SlotKind> = self
            .file
            .slots
            .iter()
            .map(|slot| slot.kind)
            .filter(|slot| *slot != kind)
            .collect();

        if remaining.is_empty() {
            return Err(anyhow!(
                "the {kind} slot is the only way to unlock this node; removing it would \
                 seal the key away for good. Add another slot first."
            ));
        }
        if !slots_can_boot_unattended(&remaining) {
            return Err(anyhow!(
                "removing the {kind} slot would leave only slots a human has to type, so \
                 the node could not come back from a restart on its own. Add an env or \
                 file slot first."
            ));
        }

        self.file.slots.retain(|slot| slot.kind != kind);
        self.write()
    }

    fn unwrap_dek(&self, key: &SealKey) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
        let kind = key.kind();
        let slot = self
            .file
            .slots
            .iter()
            .find(|slot| slot.kind == kind)
            .ok_or_else(|| {
                anyhow!(
                    "this keystore has no {kind} slot; it can be unlocked with: {}",
                    self.slots()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;

        let kek = key.kek(slot)?;
        let opened = aead::open(
            &kek,
            kind.aad(),
            &hex::decode(&slot.nonce).context("malformed slot nonce")?,
            &hex::decode(&slot.ct).context("malformed slot ciphertext")?,
        )
        .with_context(|| format!("the {kind} seal key did not open this keystore"))?;

        if opened.len() != KEY_SIZE {
            return Err(anyhow!("the {kind} slot did not hold a data key"));
        }
        let mut dek = Zeroizing::new([0u8; KEY_SIZE]);
        dek.copy_from_slice(&opened);
        Ok(dek)
    }

    fn write(&self) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(&self.file).context("encoding the keystore")?;
        aead::write_secret_file(&self.path, &encoded)
    }
}

/// Whether a node holding these slots could come back from a restart without a
/// human at a terminal.
///
/// One implementation, two callers: [`Keystore::remove_slot`], which enforces
/// that it stays true, and [`crate::app::lifecycle::SealStatus`], which answers
/// the same question about the copy `/admin` can see and is what decides
/// whether a restart is a recovery or an outage. A predicate this load-bearing
/// must not be spelled out twice and drift.
#[must_use]
pub fn slots_can_boot_unattended(slots: &[SlotKind]) -> bool {
    slots.iter().any(|slot| slot.is_unattended())
}

fn wrap_dek(dek: &Zeroizing<[u8; KEY_SIZE]>, key: &SealKey) -> Result<Slot> {
    let kind = key.kind();
    let (salt, kdf) = key.new_slot_kdf();
    let staged = Slot {
        kind,
        salt,
        kdf,
        nonce: String::new(),
        ct: String::new(),
    };

    let kek = key.kek(&staged)?;
    let (nonce, ct) = aead::seal(&kek, kind.aad(), dek.as_slice())?;

    Ok(Slot {
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
        ..staged
    })
}

/// Where the seal key came from, so the node can say so and `/admin` can offer
/// the right next step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealKeySource {
    /// Read from `KONTOR_SEAL_KEY`.
    Env,
    /// Read from `.seal-key`.
    File,
    /// Generated on this boot and written to `.seal-key`.
    Generated,
    /// Typed by an operator at `/admin`. Never available at boot, so a node that
    /// opened this way cannot claim it could restart on its own.
    Passphrase,
}

impl SealKeySource {
    #[must_use]
    pub fn kind(self) -> SlotKind {
        match self {
            Self::Env => SlotKind::Env,
            Self::File | Self::Generated => SlotKind::File,
            Self::Passphrase => SlotKind::Passphrase,
        }
    }
}

/// Every seal key this boot could try, in the order it should try them.
///
/// Plural, and that is the whole point of the type. `KONTOR_SEAL_KEY` is tried
/// first so that hardening is a pure environment change — the operator pastes
/// the key into the platform, redeploys, and the node reports that it opened
/// through the env slot, which is the evidence `/admin` requires before it will
/// offer to delete the file. But *preferring* the environment is not the same as
/// *depending* on it: the file this node generated for itself is still sitting
/// there, by design, precisely because the paste might have been wrong.
#[derive(Debug)]
pub struct SealKeyCandidates {
    /// Usable keys, environment first.
    pub keys: Vec<(SealKey, SealKeySource)>,
    /// Sources that were present and could not be turned into a key at all.
    /// Reported rather than raised: one bad source must not hide a good one.
    pub problems: Vec<String>,
}

/// Collect every seal key on this machine, and every reason one is missing.
#[must_use]
pub fn candidate_seal_keys(app_dir: &Path) -> SealKeyCandidates {
    let mut keys = Vec::new();
    let mut problems = Vec::new();

    if let Ok(encoded) = std::env::var(SEAL_KEY_ENV) {
        if !encoded.trim().is_empty() {
            match SealKey::decode(SlotKind::Env, &encoded) {
                Ok(key) => keys.push((key, SealKeySource::Env)),
                Err(e) => problems.push(format!(
                    "{SEAL_KEY_ENV} is set but unusable ({e:#}). It must be 32 random bytes, \
                     base64."
                )),
            }
        }
    }

    let path = app_dir.join(SEAL_KEY_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(encoded) => match SealKey::decode(SlotKind::File, &encoded) {
            Ok(key) => keys.push((key, SealKeySource::File)),
            Err(e) => problems.push(format!("{} is unusable ({e:#})", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => problems.push(format!("reading {} failed: {e}", path.display())),
    }

    SealKeyCandidates { keys, problems }
}

/// Find the seal key a *new* keystore should be sealed under.
///
/// The counterpart to [`candidate_seal_keys`], and the difference is the whole
/// reason there are two: that one is for opening a keystore, where a broken
/// source is something to step over, and this one is for creating one, where it
/// is something to stop at. Sealing a fresh key under a generated file key while
/// the operator believes their `KONTOR_SEAL_KEY` is the one in use would produce
/// a node nobody can open from the environment they configured.
///
/// With `generate` set and no source present, a key is created and written. That
/// is what makes a node with no configuration at all able to seal something on
/// its very first boot; it is only ever done while provisioning, never on the way
/// up to an existing keystore, where a generated key would simply fail to open
/// it.
///
/// # Errors
/// If a present source is malformed, or a generated key cannot be written.
pub fn resolve_seal_key(
    app_dir: &Path,
    generate: bool,
) -> Result<Option<(SealKey, SealKeySource)>> {
    let candidates = candidate_seal_keys(app_dir);

    if let Some(problem) = candidates.problems.first() {
        return Err(anyhow!("{problem}"));
    }
    if let Some(first) = candidates.keys.into_iter().next() {
        return Ok(Some(first));
    }
    if !generate {
        return Ok(None);
    }

    let key = SealKey::generate(SlotKind::File);
    let encoded = key
        .encode()
        .ok_or_else(|| anyhow!("a generated seal key must be a raw key"))?;
    aead::write_secret_file(&app_dir.join(SEAL_KEY_FILENAME), encoded.as_bytes())?;
    Ok(Some((key, SealKeySource::Generated)))
}

/// Delete the generated seal key file.
///
/// Only ever correct once the node has proved it can unseal through another
/// slot; [`crate::server::admin`] is what enforces that.
///
/// # Errors
/// If the file exists but cannot be removed.
pub fn remove_seal_key_file(app_dir: &Path) -> Result<()> {
    let path = app_dir.join(SEAL_KEY_FILENAME);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("removing {}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::sample as sample_identity;

    /// A BLS secret and the identity that goes with it.
    fn fixture() -> (Zeroizing<String>, PublicIdentity) {
        let keypair = BlsKeyPair::generate().unwrap();
        let secret = keypair.secret_key_hex();
        let mut identity = sample_identity();
        identity.bls_pubkey = keypair.public_key_hex();
        (secret, identity)
    }

    fn provision(dir: &Path, key: &SealKey) -> (Keystore, String) {
        let (secret, identity) = fixture();
        let pubkey = identity.bls_pubkey.clone();
        let store = Keystore::provision(dir, &secret, Some(identity), key).unwrap();
        (store, pubkey)
    }

    #[tokio::test]
    async fn provision_then_load_and_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (_, pubkey) = provision(dir.path(), &key);

        let loaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(loaded.unseal(&key).unwrap().public_key_hex(), pubkey);
        assert_eq!(loaded.slots(), vec![SlotKind::File]);
        assert!(slots_can_boot_unattended(&loaded.slots()));
    }

    #[tokio::test]
    async fn load_is_none_before_provisioning() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Keystore::load(dir.path()).await.unwrap().is_none());
    }

    /// A keystore that exists but cannot be read must not look like a node that
    /// was never set up: the wizard would provision a second identity on top of
    /// a key that is merely unreadable.
    #[tokio::test]
    async fn a_corrupt_keystore_is_an_error_not_an_absence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(Keystore::path_in(dir.path()), b"{ not json").unwrap();

        let err = Keystore::load(dir.path()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("parsing the keystore"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_future_version_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        provision(dir.path(), &key);

        let path = Keystore::path_in(dir.path());
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("\"version\": 1", "\"version\": 99")).unwrap();

        let err = Keystore::load(dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[tokio::test]
    async fn a_keystore_with_no_slots_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        provision(dir.path(), &key);

        let path = Keystore::path_in(dir.path());
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["slots"] = serde_json::json!([]);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let err = Keystore::load(dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("no slots"), "{err}");
    }

    #[test]
    fn unseal_rejects_the_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (store, _) = provision(dir.path(), &key);

        let other = SealKey::generate(SlotKind::File);
        let err = store.unseal(&other).unwrap_err();
        assert!(format!("{err:#}").contains("did not open"), "{err:#}");
    }

    #[test]
    fn unseal_names_the_slots_it_has_when_the_kind_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (store, _) = provision(dir.path(), &key);

        let err = store.unseal(&SealKey::generate(SlotKind::Env)).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("no env slot"), "{rendered}");
        assert!(rendered.contains("file"), "{rendered}");
    }

    /// Tampering has to be caught by the AEAD rather than producing a key that
    /// is merely wrong.
    #[tokio::test]
    async fn a_tampered_ciphertext_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        provision(dir.path(), &key);

        let path = Keystore::path_in(dir.path());
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let ct = file["secret"]["ct"].as_str().unwrap().to_string();
        let flipped = format!(
            "{}{}",
            if ct.starts_with('a') { 'b' } else { 'a' },
            &ct[1..]
        );
        file["secret"]["ct"] = serde_json::json!(flipped);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let store = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert!(store.unseal(&key).is_err());
    }

    #[test]
    fn add_slot_gives_a_second_way_in() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, pubkey) = provision(dir.path(), &file_key);

        let env_key = SealKey::generate(SlotKind::Env);
        store.add_slot(&file_key, &env_key).unwrap();

        assert_eq!(store.slots(), vec![SlotKind::File, SlotKind::Env]);
        assert_eq!(store.unseal(&env_key).unwrap().public_key_hex(), pubkey);
        assert_eq!(store.unseal(&file_key).unwrap().public_key_hex(), pubkey);
    }

    #[test]
    fn add_slot_replaces_a_slot_of_the_same_kind() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, pubkey) = provision(dir.path(), &file_key);

        let first = SealKey::generate(SlotKind::Env);
        store.add_slot(&file_key, &first).unwrap();
        let second = SealKey::generate(SlotKind::Env);
        store.add_slot(&file_key, &second).unwrap();

        assert_eq!(store.slots(), vec![SlotKind::File, SlotKind::Env]);
        assert_eq!(store.unseal(&second).unwrap().public_key_hex(), pubkey);
        assert!(store.unseal(&first).is_err());
    }

    #[test]
    fn add_slot_refuses_an_unlock_key_that_does_not_work() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, _) = provision(dir.path(), &file_key);

        let wrong = SealKey::generate(SlotKind::File);
        assert!(store
            .add_slot(&wrong, &SealKey::generate(SlotKind::Env))
            .is_err());
        assert_eq!(store.slots(), vec![SlotKind::File]);
    }

    #[test]
    fn a_passphrase_slot_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, pubkey) = provision(dir.path(), &file_key);

        let phrase = SealKey::passphrase("correct horse battery staple");
        store.add_slot(&file_key, &phrase).unwrap();

        assert_eq!(store.unseal(&phrase).unwrap().public_key_hex(), pubkey);
        assert!(store
            .unseal(&SealKey::passphrase("wrong passphrase entirely"))
            .is_err());
    }

    #[test]
    fn remove_slot_refuses_the_last_one() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (mut store, _) = provision(dir.path(), &key);

        let err = store.remove_slot(SlotKind::File).unwrap_err();
        assert!(err.to_string().contains("only way to unlock"), "{err}");
        assert_eq!(store.slots(), vec![SlotKind::File]);
    }

    /// The rule that keeps the zero-config promise: a node must never be left
    /// able to start only when a human is watching.
    #[test]
    fn remove_slot_refuses_to_leave_only_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, _) = provision(dir.path(), &file_key);
        store
            .add_slot(&file_key, &SealKey::passphrase("correct horse battery"))
            .unwrap();

        let err = store.remove_slot(SlotKind::File).unwrap_err();
        assert!(
            err.to_string().contains("come back from a restart"),
            "{err}"
        );
    }

    #[test]
    fn remove_slot_drops_the_file_slot_once_env_exists() {
        let dir = tempfile::tempdir().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        let (mut store, pubkey) = provision(dir.path(), &file_key);
        let env_key = SealKey::generate(SlotKind::Env);
        store.add_slot(&file_key, &env_key).unwrap();

        store.remove_slot(SlotKind::File).unwrap();

        assert_eq!(store.slots(), vec![SlotKind::Env]);
        assert_eq!(store.unseal(&env_key).unwrap().public_key_hex(), pubkey);
        assert!(store.unseal(&file_key).is_err());
    }

    #[test]
    fn remove_slot_reports_a_slot_that_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (mut store, _) = provision(dir.path(), &key);

        let err = store.remove_slot(SlotKind::Env).unwrap_err();
        assert!(err.to_string().contains("no env slot"), "{err}");
    }

    /// The check that stops a keystore from filing a key under someone else's
    /// identity — the failure that would otherwise show up as an unexplainable
    /// Portal 404.
    #[test]
    fn provision_refuses_a_secret_that_does_not_match_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, _) = fixture();
        let (_, other_identity) = fixture();

        let err = Keystore::provision(
            dir.path(),
            &secret,
            Some(other_identity),
            &SealKey::generate(SlotKind::File),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the identity"),
            "{err}"
        );
    }

    #[test]
    fn provision_refuses_something_that_is_not_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let err = Keystore::provision(
            dir.path(),
            &Zeroizing::new("not hex".to_string()),
            None,
            &SealKey::generate(SlotKind::File),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a valid BLS"), "{err:#}");
    }

    #[tokio::test]
    async fn unseal_refuses_a_key_that_disagrees_with_the_recorded_identity() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        provision(dir.path(), &key);

        // Rewrite only the public record, leaving the sealed key alone.
        let path = Keystore::path_in(dir.path());
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["public"]["bls_pubkey"] =
            serde_json::json!(BlsKeyPair::generate().unwrap().public_key_hex());
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let store = Keystore::load(dir.path()).await.unwrap().unwrap();
        let err = store.unseal(&key).unwrap_err();
        assert!(
            err.to_string().contains("does not match the identity"),
            "{err}"
        );
    }

    #[test]
    fn a_fingerprint_identifies_a_key_without_revealing_it() {
        let key = SealKey::generate(SlotKind::File);
        let fingerprint = key.fingerprint().unwrap();

        assert_eq!(fingerprint.len(), 8);
        assert_eq!(key.fingerprint(), Some(fingerprint.clone()));
        assert_ne!(
            key.fingerprint(),
            SealKey::generate(SlotKind::File).fingerprint()
        );
        assert!(!key.encode().unwrap().contains(&fingerprint));
    }

    /// A passphrase has no fingerprint, and must not grow one. The value is
    /// published in a body the sealed channel does not cover, so four bytes of a
    /// hash of a human-chosen secret would be an offline confirmation oracle at
    /// one `SHA-256` per guess — against the 64 MiB of Argon2id that trying the
    /// same guess against the keystore costs.
    #[test]
    fn a_passphrase_has_no_fingerprint_to_publish() {
        let phrase = SealKey::passphrase("correct horse battery staple");

        assert_eq!(phrase.fingerprint(), None);
        assert!(SealKey::generate(SlotKind::File).fingerprint().is_some());
    }

    /// And no encoding either. The two callers of `encode` write the result to
    /// `.seal-key` or hand it back to a browser, and doing either with a
    /// passphrase would put an operator's own secret somewhere they never chose
    /// to put it.
    #[test]
    fn a_passphrase_has_no_encoding_to_hand_out() {
        let phrase = SealKey::passphrase("correct horse battery staple");

        assert!(phrase.encode().is_none());
        assert!(SealKey::generate(SlotKind::File).encode().is_some());
    }

    #[test]
    fn a_seal_key_never_prints_itself() {
        let key = SealKey::generate(SlotKind::Env);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains(key.encode().unwrap().as_str()),
            "{rendered}"
        );
    }

    #[test]
    fn seal_keys_round_trip_through_base64() {
        let key = SealKey::generate(SlotKind::Env);
        let decoded = SealKey::decode(SlotKind::Env, &key.encode().unwrap()).unwrap();
        assert_eq!(decoded.fingerprint(), key.fingerprint());

        assert!(SealKey::decode(SlotKind::Env, "not base64!!").is_err());
        let err = SealKey::decode(SlotKind::Env, &BASE64.encode([0u8; 8])).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[test]
    #[serial_test::serial]
    fn resolve_seal_key_generates_one_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(SEAL_KEY_ENV);

        assert!(resolve_seal_key(dir.path(), false).unwrap().is_none());
        assert!(!dir.path().join(SEAL_KEY_FILENAME).exists());

        let (key, source) = resolve_seal_key(dir.path(), true).unwrap().unwrap();
        assert_eq!(source, SealKeySource::Generated);
        assert_eq!(key.kind(), SlotKind::File);

        // The second call must find the file rather than generating again — a
        // fresh key every boot would not open the previous boot's keystore.
        let (again, source) = resolve_seal_key(dir.path(), true).unwrap().unwrap();
        assert_eq!(source, SealKeySource::File);
        assert_eq!(again.fingerprint(), key.fingerprint());
    }

    #[test]
    #[serial_test::serial]
    fn the_environment_wins_over_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(SEAL_KEY_ENV);
        let (file_key, _) = resolve_seal_key(dir.path(), true).unwrap().unwrap();

        let env_key = SealKey::generate(SlotKind::Env);
        std::env::set_var(SEAL_KEY_ENV, env_key.encode().unwrap().as_str());

        let (resolved, source) = resolve_seal_key(dir.path(), true).unwrap().unwrap();
        assert_eq!(source, SealKeySource::Env);
        assert_eq!(resolved.fingerprint(), env_key.fingerprint());
        assert_ne!(resolved.fingerprint(), file_key.fingerprint());

        std::env::remove_var(SEAL_KEY_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn a_blank_environment_variable_is_not_a_seal_key() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(SEAL_KEY_ENV, "   ");

        let (_, source) = resolve_seal_key(dir.path(), true).unwrap().unwrap();
        assert_eq!(source, SealKeySource::Generated);

        std::env::remove_var(SEAL_KEY_ENV);
    }

    /// A malformed key must stop the node by name. Falling through to the file
    /// would silently ignore what the operator asked for and, on a keystore with
    /// only an env slot, fail much later with something unrelated.
    #[test]
    #[serial_test::serial]
    fn a_malformed_environment_variable_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(SEAL_KEY_ENV, "obviously not base64 ****");

        let err = resolve_seal_key(dir.path(), true).unwrap_err();
        assert!(format!("{err:#}").contains(SEAL_KEY_ENV), "{err:#}");

        std::env::remove_var(SEAL_KEY_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn a_malformed_key_file_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(SEAL_KEY_ENV);
        std::fs::write(dir.path().join(SEAL_KEY_FILENAME), "not base64 ****").unwrap();

        let err = resolve_seal_key(dir.path(), true).unwrap_err();
        assert!(format!("{err:#}").contains(SEAL_KEY_FILENAME), "{err:#}");
    }

    #[test]
    #[serial_test::serial]
    fn removing_the_key_file_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(SEAL_KEY_ENV);
        resolve_seal_key(dir.path(), true).unwrap().unwrap();

        assert!(dir.path().join(SEAL_KEY_FILENAME).exists());
        remove_seal_key_file(dir.path()).unwrap();
        assert!(!dir.path().join(SEAL_KEY_FILENAME).exists());
        remove_seal_key_file(dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn the_keystore_and_the_key_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(SEAL_KEY_ENV);
        let (key, _) = resolve_seal_key(dir.path(), true).unwrap().unwrap();
        provision(dir.path(), &key);

        for path in [
            Keystore::path_in(dir.path()),
            dir.path().join(SEAL_KEY_FILENAME),
        ] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{} is {mode:o}", path.display());
        }
    }

    /// The file is meant to be opened by a human debugging a node, so the
    /// identity has to be legible in it — and the secret must not be.
    #[test]
    fn the_keystore_file_is_readable_without_being_revealing() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::generate(SlotKind::File);
        let (store, _) = provision(dir.path(), &key);

        let raw = std::fs::read_to_string(Keystore::path_in(dir.path())).unwrap();
        assert!(raw.contains("\"network\": \"signet\""), "{raw}");
        assert!(raw.contains(&store.public().unwrap().node_id), "{raw}");
        assert!(!raw.contains(key.encode().unwrap().as_str()), "{raw}");
    }

    #[test]
    fn slot_kinds_know_which_can_boot_a_node() {
        assert!(SlotKind::Env.is_unattended());
        assert!(SlotKind::File.is_unattended());
        assert!(!SlotKind::Passphrase.is_unattended());
        assert_eq!(SealKeySource::Env.kind(), SlotKind::Env);
        assert_eq!(SealKeySource::Generated.kind(), SlotKind::File);
        assert_eq!(SealKeySource::File.kind(), SlotKind::File);
    }

    /// Every slot kind seals under its own AAD, so a wrap cannot be moved from
    /// one slot to another inside the same file.
    #[tokio::test]
    async fn slot_wraps_are_bound_to_their_kind() {
        let dir = tempfile::tempdir().unwrap();
        let raw = aead::random_key();
        let file_key = SealKey::raw(SlotKind::File, raw.clone());
        let (mut store, _) = provision(dir.path(), &file_key);

        // The same 32 bytes, presented as an env key, must not open the file slot.
        store
            .add_slot(&file_key, &SealKey::raw(SlotKind::Env, raw.clone()))
            .unwrap();
        let path = Keystore::path_in(dir.path());
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let env_wrap = file["slots"][1].clone();
        file["slots"] = serde_json::json!([{
            "kind": "file",
            "nonce": env_wrap["nonce"],
            "ct": env_wrap["ct"],
        }]);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let store = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert!(store.unseal(&file_key).is_err());
    }
}
