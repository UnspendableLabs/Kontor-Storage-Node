//! BLS key management for onboarding.
//!
//! Handles loading, generating, and encrypting BLS keys.

use crate::crypto::keystore::{self, SealKey, SealKeySource};
use crate::crypto::mnemonic::MNEMONIC_ENV;
use crate::crypto::{
    BlsKeyPair, Keystore, MnemonicIdentity, MnemonicSettings, PublicIdentity, BLS_KEY_FILENAME,
};
use crate::database::default_app_dir;
use anyhow::{anyhow, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable name for providing the BLS password non-interactively.
/// This is useful for automation, testing, and scripted deployments.
pub const BLS_PASSWORD_ENV: &str = "BLS_PASSWORD";

/// Environment variable name for providing the encrypted BLS blob non-interactively.
pub const BLS_BLOB_ENV: &str = "BLS_ENCRYPTED_BLOB";

/// Trait for reading passwords and interactive input from the user.
/// This abstraction enables testing without interactive input.
pub trait PasswordReader {
    /// Read a password (for existing key).
    fn read_password(&self) -> Result<String>;

    /// Read and confirm a new password.
    /// Returns an error if passwords don't match or validation fails.
    fn read_new_password(&self, writer: &mut dyn Write) -> Result<String>;

    /// Read the encrypted BLS key blob (copy-pasted from Horizon Wallet).
    fn read_blob(&self) -> Result<String>;

    /// Wait for the user to press Enter.
    #[allow(dead_code)]
    fn wait_for_enter(&self) -> Result<()>;

    /// Whether reading anything from this reader stops at a human.
    ///
    /// The mnemonic cross-check in [`ensure_node_keys`] opens the legacy key
    /// material to compare it against the derived key. That is worth doing when
    /// it is free, and never worth stopping a node at a password prompt for a
    /// file it is about to ignore — so on a terminal the check is skipped
    /// rather than asked for.
    fn is_interactive(&self) -> bool;
}

/// Default implementation that reads from the terminal using rpassword.
/// This struct is excluded from coverage because it requires interactive terminal input.
// LCOV_EXCL_START
pub struct TerminalPasswordReader;

impl PasswordReader for TerminalPasswordReader {
    fn read_password(&self) -> Result<String> {
        rpassword::prompt_password("Password: ")
            .map_err(|e| anyhow!("failed to read password: {e}"))
    }

    fn read_new_password(&self, writer: &mut dyn Write) -> Result<String> {
        loop {
            let password = rpassword::prompt_password("Enter password: ")
                .map_err(|e| anyhow!("failed to read password: {e}"))?;

            if password.is_empty() {
                writeln!(writer, "Password cannot be empty. Please try again.")?;
                continue;
            }

            if password.len() < 8 {
                writeln!(
                    writer,
                    "Password must be at least 8 characters. Please try again."
                )?;
                continue;
            }

            let confirm = rpassword::prompt_password("Confirm password: ")
                .map_err(|e| anyhow!("failed to read password confirmation: {e}"))?;

            if password != confirm {
                writeln!(writer, "Passwords do not match. Please try again.")?;
                continue;
            }

            return Ok(password);
        }
    }

    fn read_blob(&self) -> Result<String> {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("failed to read encrypted key blob: {e}"))?;
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("encrypted key blob cannot be empty"));
        }
        Ok(trimmed)
    }

    fn wait_for_enter(&self) -> Result<()> {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("failed to read input: {e}"))?;
        Ok(())
    }

    fn is_interactive(&self) -> bool {
        true
    }
}
// LCOV_EXCL_STOP

/// Password reader that reads from the BLS_PASSWORD environment variable.
/// Useful for automation, CI/CD, and testing.
///
/// **Import caveat:** [`Self::read_password`] and [`Self::read_new_password`] both use
/// `BLS_PASSWORD`. For a non-interactive Horizon Wallet import, the wallet export password
/// and the new on-disk password must therefore be the same, or you must use interactive mode.
pub struct EnvPasswordReader;

impl PasswordReader for EnvPasswordReader {
    fn read_password(&self) -> Result<String> {
        std::env::var(BLS_PASSWORD_ENV).map_err(|_| {
            anyhow!(
                "{} environment variable is required in non-interactive mode",
                BLS_PASSWORD_ENV
            )
        })
    }

    fn read_new_password(&self, _writer: &mut dyn Write) -> Result<String> {
        let password = std::env::var(BLS_PASSWORD_ENV).map_err(|_| {
            anyhow!(
                "{} environment variable is required in non-interactive mode",
                BLS_PASSWORD_ENV
            )
        })?;

        // Validate password requirements
        if password.is_empty() {
            return Err(anyhow!("password cannot be empty"));
        }
        if password.len() < 8 {
            return Err(anyhow!("password must be at least 8 characters"));
        }

        Ok(password)
    }

    fn read_blob(&self) -> Result<String> {
        let raw = std::env::var(BLS_BLOB_ENV).map_err(|_| {
            anyhow!("{BLS_BLOB_ENV} environment variable is required in non-interactive mode")
        })?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!(
                "{BLS_BLOB_ENV} is set but empty (after trimming); paste the full encrypted blob"
            ));
        }
        Ok(trimmed)
    }

    fn wait_for_enter(&self) -> Result<()> {
        // In non-interactive mode, we don't wait for user input
        Ok(())
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Returns the appropriate password reader based on environment.
/// Uses [`EnvPasswordReader`] if `BLS_PASSWORD` is set, otherwise [`TerminalPasswordReader`].
/// For non-interactive wallet import, set `BLS_ENCRYPTED_BLOB` as well (see [`EnvPasswordReader`]).
pub fn get_password_reader() -> Box<dyn PasswordReader> {
    if std::env::var(BLS_PASSWORD_ENV).is_ok() {
        Box::new(EnvPasswordReader)
    } else {
        Box::new(TerminalPasswordReader) // LCOV_EXCL_LINE
    }
}

/// Where the legacy `bls_key.enc` lives.
///
/// # Errors
/// If no override is given and no application data directory can be determined.
pub fn get_key_path(configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_path_buf());
    }
    let app_dir = default_app_dir().ok_or_else(|| {
        anyhow!("unable to determine application data directory for storing BLS keys")
    })?;
    Ok(app_dir.join(BLS_KEY_FILENAME))
}

/// A BLS key opened from [`crate::crypto::keystore`], with whatever public
/// identity the keystore filed it under.
///
/// `public` is `None` only for a keystore provisioned from material that never
/// carried a Taproot account — a migrated `bls_key.enc`, a wallet blob. Such a
/// node still runs; it just cannot register itself, and needs the browser flow
/// for that one field.
pub struct SealedKeys {
    pub keypair: BlsKeyPair,
    pub public: Option<PublicIdentity>,
}

/// This node's key material, and where it came from.
///
/// Three sources, and what separates them is not the BLS key — that is the same
/// in all three — but how much of the *Taproot* side came with it:
///
/// - [`Self::Sealed`] is the production path. It has the public identity,
///   including the precomputed Schnorr binding signature, so it can register
///   itself. It does not have the seed, so it cannot derive a sibling account.
/// - [`Self::Derived`] has the seed, and exists now only for the moment the
///   setup wizard holds one and for a node still on the legacy environment
///   variable. It can do everything, including the sibling scan.
/// - [`Self::Imported`] is a bare BLS key from `bls_key.enc`. It needs a browser
///   to supply the Taproot half of a registration.
// The larger variants are boxed: a `MnemonicIdentity` is several times the size
// of a bare keypair, and this value is built once per start, so the indirection
// costs nothing worth measuring.
pub enum NodeKeys {
    /// Derived from a seed phrase. Self-sufficient, and the only variant that
    /// can look at neighbouring accounts.
    Derived(Box<MnemonicIdentity>),
    /// Opened from the keystore. Self-sufficient for everything but the sibling
    /// scan.
    Sealed(Box<SealedKeys>),
    /// Decrypted from Horizon Wallet's export and kept on disk under a password.
    Imported(Box<BlsKeyPair>),
}

impl NodeKeys {
    #[must_use]
    pub fn keypair(&self) -> &BlsKeyPair {
        match self {
            Self::Derived(identity) => &identity.keypair,
            Self::Sealed(sealed) => &sealed.keypair,
            Self::Imported(keypair) => keypair,
        }
    }

    /// What this node can say about its Taproot account without unsealing
    /// anything further.
    ///
    /// # Errors
    /// Only on the [`Self::Derived`] path, if the binding signature cannot be
    /// produced.
    pub fn public(&self) -> Result<Option<PublicIdentity>> {
        match self {
            Self::Derived(identity) => identity.public().map(Some),
            Self::Sealed(sealed) => Ok(sealed.public.clone()),
            Self::Imported(_) => Ok(None),
        }
    }

    /// The seed-backed identity, if this node still holds one.
    ///
    /// The one thing it is for is [`crate::node::registration::find_registered_siblings`],
    /// which has to derive neighbouring accounts. Everything else works from
    /// [`Self::public`], which is why a sealed node needs no seed.
    #[must_use]
    pub fn seed(&self) -> Option<&MnemonicIdentity> {
        match self {
            Self::Derived(identity) => Some(identity),
            Self::Sealed(_) | Self::Imported(_) => None,
        }
    }

    #[must_use]
    pub fn into_keypair(self) -> BlsKeyPair {
        match self {
            Self::Derived(identity) => identity.keypair,
            Self::Sealed(sealed) => sealed.keypair,
            Self::Imported(keypair) => *keypair,
        }
    }
}

impl std::fmt::Debug for NodeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Derived(identity) => f.debug_tuple("Derived").field(identity).finish(),
            Self::Sealed(sealed) => f
                .debug_struct("Sealed")
                .field("public", &sealed.public)
                .field("keypair", &sealed.keypair)
                .finish(),
            Self::Imported(keypair) => f.debug_tuple("Imported").field(keypair).finish(),
        }
    }
}

/// Obtain this node's keys: derived from the mnemonic, loaded from disk, or
/// imported from a Horizon Wallet export.
///
/// The mnemonic is checked first, and deliberately so. Both the key file and the
/// blob exist to get a wallet-held key onto a machine; a mnemonic is that key's
/// source, so once one is configured everything else is a stale copy. Ignoring
/// the file rather than preferring it is also what makes migrating a running
/// node a pure environment change: `bls_key.enc` is still sitting there from the
/// blob era, and with `BLS_PASSWORD` deleted the disk path would stop at a
/// password prompt no container has a terminal to answer.
pub async fn ensure_node_keys(
    key_path: &Path,
    mnemonic: Option<&MnemonicSettings>,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<NodeKeys> {
    if let Some(settings) = mnemonic {
        let identity = MnemonicIdentity::derive(settings)?;

        writeln!(
            writer,
            "✓ Identity derived from {MNEMONIC_ENV} ({}, account {})",
            identity.network, identity.account
        )?;
        writeln!(writer, "  BLS public key:  {}", identity.bls_pubkey())?;
        writeln!(writer, "  Taproot xpub:    {}", identity.xpubkey)?;
        writeln!(
            writer,
            "  Taproot address: {}   <- whitelist this on the Portal",
            identity.taproot_address
        )?;
        writeln!(writer, "  Node id:         {}", identity.node_id)?;

        cross_check_legacy_key(key_path, &identity, writer, password_reader).await?;

        return Ok(NodeKeys::Derived(Box::new(identity)));
    }

    ensure_bls_keypair(key_path, writer, password_reader)
        .await
        .map(|keypair| NodeKeys::Imported(Box::new(keypair)))
}

/// Where this node's keys stand at boot.
pub enum KeySource {
    /// The keystore opened. The node can onboard.
    Open {
        keystore: Box<Keystore>,
        keys: Box<NodeKeys>,
        /// Which slot this boot came in through. `/admin` needs it to know
        /// whether dropping the file slot is safe yet, and it is carried rather
        /// than re-derived so the answer cannot drift from what actually
        /// happened.
        seal_key: SealKey,
        seal_source: SealKeySource,
    },
    /// A keystore exists, but nothing on this machine opened it.
    ///
    /// `reason` is present when something was *tried* and did not work — a
    /// malformed `KONTOR_SEAL_KEY`, a truncated `.seal-key`, a key that simply
    /// is not this keystore's — and absent when there was nothing to try. The
    /// distinction is the whole message: the first is a mistake with a fix, and
    /// the operator reads it on the page that offers the fix.
    Sealed {
        keystore: Box<Keystore>,
        reason: Option<String>,
    },
    /// No keystore and nothing to migrate. The setup wizard has the work.
    Uninitialized,
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open {
                keys, seal_source, ..
            } => f
                .debug_struct("Open")
                .field("keys", keys)
                .field("seal_source", seal_source)
                .finish_non_exhaustive(),
            Self::Sealed { keystore, reason } => f
                .debug_struct("Sealed")
                .field("slots", &keystore.slots())
                .field("reason", reason)
                .finish_non_exhaustive(),
            Self::Uninitialized => f.write_str("Uninitialized"),
        }
    }
}

/// Open the keystore, migrating a legacy node into one on the way if that is
/// what it turns out to be.
///
/// # The three shapes a volume can be in
///
/// 1. **A keystore is there.** It is the answer, unconditionally. A
///    `KONTOR_STORAGE_MNEMONIC` still sitting in the environment is a leftover
///    from before the migration, and honouring it over the file would let a
///    stale variable silently move a running node to another identity. The
///    disagreement is reported loudly and the keystore still wins — refusing to
///    start would strand a working node over a variable somebody forgot to
///    delete.
///
///    If no seal key opens it, that is [`KeySource::Sealed`] and **not** an
///    error. Only the keystore itself being unreadable is fatal, and the two
///    are not the same failure: provisioning over a keystore that merely cannot
///    be parsed would replace an identity, whereas a key that does not open one
///    is a mistake with an obvious fix — the wrong `KONTOR_SEAL_KEY`, most
///    likely, pasted during the two-step hardening flow. Exiting there would
///    take `/admin` down with the node and remove the only channel that could
///    correct it, on the one path this release exists to make recoverable.
/// 2. **No keystore, but something to migrate** — a mnemonic in the
///    environment, or a `bls_key.enc` this process can open. The key is sealed
///    into a keystore on the spot and the node comes up on the new path. The
///    legacy material is left exactly where it is; deleting an operator's key
///    file is not this function's call to make.
/// 3. **Neither.** [`KeySource::Uninitialized`], and `/admin` does the rest.
///
/// # Errors
/// If the keystore is unreadable, or if legacy material is present but cannot
/// be read. A seal key that is malformed or simply wrong is *not* an error —
/// see the note on case 1.
pub async fn open_or_migrate(
    app_dir: &Path,
    key_path: &Path,
    mnemonic: Option<&MnemonicSettings>,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<KeySource> {
    if let Some(keystore) = Keystore::load(app_dir).await? {
        warn_about_a_stale_mnemonic(&keystore, mnemonic);

        let sealed = |reason: Option<String>| KeySource::Sealed {
            keystore: Box::new(keystore.clone()),
            reason,
        };

        // A key that will not parse is a typo in the environment or a truncated
        // file, not a reason to take the node's only repair channel away.
        let resolved = match keystore::resolve_seal_key(app_dir, false) {
            Ok(resolved) => resolved,
            Err(e) => return Ok(sealed(Some(format!("{e:#}")))),
        };

        let Some((seal_key, seal_source)) = resolved else {
            return Ok(sealed(None));
        };

        // And a key that parses but opens nothing is the same mistake one step
        // later — the commonest one there is here, since the hardening flow
        // asks an operator to paste 32 base64 bytes into a platform by hand.
        let keypair = match keystore.unseal(&seal_key) {
            Ok(keypair) => keypair,
            Err(e) => return Ok(sealed(Some(format!("{e:#}")))),
        };
        let public = keystore.public().cloned();

        // A passphrase has no fingerprint to print, and never reaches this
        // path anyway: nothing on the machine can supply one at boot.
        writeln!(
            writer,
            "✓ Keystore opened ({} slot, fingerprint {})",
            seal_source.kind(),
            seal_key.fingerprint().as_deref().unwrap_or("none")
        )?;
        return Ok(KeySource::Open {
            keystore: Box::new(keystore),
            keys: Box::new(NodeKeys::Sealed(Box::new(SealedKeys { keypair, public }))),
            seal_key,
            seal_source,
        });
    }

    // Nothing to migrate is the ordinary case now: a fresh node has an empty
    // volume, and the wizard is how it gets a key. Checking before calling
    // `ensure_node_keys` is what keeps it out of the interactive blob-import
    // prompt, which no unattended container can answer.
    if mnemonic.is_none() && !BlsKeyPair::key_file_exists(key_path).await? {
        return Ok(KeySource::Uninitialized);
    }

    writeln!(
        writer,
        "\nNo keystore yet, but this node has key material from an older release. \
         Migrating it into one."
    )?;

    let keys = ensure_node_keys(key_path, mnemonic, writer, password_reader).await?;
    let public = keys.public()?;
    let secret = keys.keypair().secret_key_hex();

    // Generated here and only here: a node that already has a keystore must
    // never make a fresh key, because a fresh key does not open the old file.
    let (seal_key, seal_source) = keystore::resolve_seal_key(app_dir, true)?
        .ok_or_else(|| anyhow!("no seal key could be resolved or generated"))?;

    let keystore = Keystore::provision(app_dir, &secret, public, &seal_key)?;

    writeln!(
        writer,
        "✓ Sealed into {} ({} slot, fingerprint {})",
        Keystore::path_in(app_dir).display(),
        seal_source.kind(),
        seal_key.fingerprint().as_deref().unwrap_or("none")
    )?;
    if mnemonic.is_some() {
        writeln!(
            writer,
            "  {MNEMONIC_ENV} is no longer needed and should be removed from this \
             deployment. The node now derives nothing: it holds only the sealed BLS key."
        )?;
    }

    Ok(KeySource::Open {
        keystore: Box::new(keystore),
        keys: Box::new(keys),
        seal_key,
        seal_source,
    })
}

/// Report an environment that disagrees with the keystore, without acting on it.
fn warn_about_a_stale_mnemonic(keystore: &Keystore, mnemonic: Option<&MnemonicSettings>) {
    let Some(settings) = mnemonic else { return };
    let Some(recorded) = keystore.public() else {
        tracing::warn!(
            "{MNEMONIC_ENV} is set but this node already has a keystore, which takes \
             precedence. Remove the variable."
        );
        return;
    };

    match MnemonicIdentity::derive(settings) {
        Ok(identity) if identity.node_id == recorded.node_id => tracing::warn!(
            "{MNEMONIC_ENV} is set and derives the identity this node already holds. \
             It is doing nothing; remove it."
        ),
        Ok(identity) => tracing::error!(
            keystore = %recorded.node_id,
            environment = %identity.node_id,
            "{MNEMONIC_ENV} derives a DIFFERENT identity from the one in this node's \
             keystore. The keystore wins and the node keeps its identity, but the \
             variable is now actively misleading — remove it."
        ),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            "{MNEMONIC_ENV} is set but unusable. The keystore is what this node runs on; \
             remove the variable."
        ),
    }
}

/// The BLS key this node used before the mnemonic, when one can be read.
enum LegacyKey {
    /// Opened. Carries the public key it holds and where it came from.
    Found { pubkey: String, source: String },
    /// Present, but not readable here — wrong password, corrupt file, or a
    /// terminal we must not stop at. The comparison did not happen.
    Unreadable { source: String, reason: String },
    /// Nothing to compare against.
    Absent,
}

/// Read whatever BLS key this node held before the mnemonic, without ever
/// blocking on a human.
///
/// The exported blob is tried first: it is the wallet's own output, one
/// decryption away from the key the Portal knows, whereas the file is a local
/// re-encryption of it. Either answers the only question being asked — which
/// key was this node actually using — so a blob that will not open falls
/// through to the file rather than ending the check there.
///
/// That fallback is not hypothetical. Both readers take one password, and for
/// the blob it has to be the wallet's *export* password while the file wants
/// the local one. Whenever those differ — the common case, since the operator
/// chose the second themselves — the blob is undecryptable and the file is
/// sitting right there, readable. Stopping at the blob would skip the only
/// guard that can catch a wrong derivation on exactly the nodes it was written
/// for.
async fn legacy_bls_pubkey(key_path: &Path, reader: &dyn PasswordReader) -> LegacyKey {
    match blob_bls_pubkey(reader) {
        Some(found @ LegacyKey::Found { .. }) => found,
        // Either no blob at all, or one that would not open. Both leave the
        // file as the remaining source; a blob failure is still worth
        // reporting if the file turns out to have nothing to say.
        from_blob => match key_file_bls_pubkey(key_path, reader).await {
            LegacyKey::Absent => from_blob.unwrap_or(LegacyKey::Absent),
            from_file => from_file,
        },
    }
}

/// The key inside `BLS_ENCRYPTED_BLOB`, or `None` when none is configured.
fn blob_bls_pubkey(reader: &dyn PasswordReader) -> Option<LegacyKey> {
    let blob = reader.read_blob().ok()?;
    let source = BLS_BLOB_ENV.to_string();

    Some(
        match reader
            .read_password()
            .and_then(|password| crate::crypto::decrypt_wallet_blob(&blob, &password))
            .and_then(|secret| BlsKeyPair::from_secret_key_hex(&secret))
        {
            Ok(keypair) => LegacyKey::Found {
                pubkey: keypair.public_key_hex(),
                source,
            },
            Err(e) => LegacyKey::Unreadable {
                source,
                reason: format!("{e:#}"),
            },
        },
    )
}

/// The key inside the on-disk key file, or [`LegacyKey::Absent`] if there is no
/// such file.
async fn key_file_bls_pubkey(key_path: &Path, reader: &dyn PasswordReader) -> LegacyKey {
    if !matches!(BlsKeyPair::key_file_exists(key_path).await, Ok(true)) {
        return LegacyKey::Absent;
    }

    let source = key_path.display().to_string();
    match reader.read_password() {
        Ok(password) => match BlsKeyPair::load_encrypted(key_path, &password).await {
            Ok(keypair) => LegacyKey::Found {
                pubkey: keypair.public_key_hex(),
                source,
            },
            Err(e) => LegacyKey::Unreadable {
                source,
                reason: format!("{e:#}"),
            },
        },
        Err(e) => LegacyKey::Unreadable {
            source,
            reason: format!("{e:#}"),
        },
    }
}

/// Compare the derived key against the one this node used before, and refuse to
/// continue if they disagree.
///
/// # Why this is the only guard that can catch a wrong derivation
///
/// Every other check on this path — the `node_id` lookup, the sibling scan —
/// asks the Portal about keys derived from the *same* constants it is trying to
/// validate. If any of them is wrong, the derived identity is simply unknown
/// everywhere, which is indistinguishable from a new node: the node registers a
/// second identity and the original keeps its agreements. The guards are blind
/// to it by construction.
///
/// The legacy key material is the one thing on the machine that does not come
/// from the mnemonic. Comparing against it is the whole compatibility claim in
/// one assertion, checked on exactly the nodes where being wrong is expensive —
/// the ones migrating from a wallet export.
///
/// Best-effort in one direction only: it can refuse, never permit. When the key
/// cannot be read the node says so and carries on, because a guard that did not
/// run must not read like a guard that passed.
///
/// # Errors
/// If the legacy key opens and holds a different public key.
async fn cross_check_legacy_key(
    key_path: &Path,
    identity: &MnemonicIdentity,
    writer: &mut impl Write,
    reader: &dyn PasswordReader,
) -> Result<()> {
    // On a terminal, opening the legacy key means prompting for a password to
    // check a file we are about to ignore. Not worth stopping a start for.
    if reader.is_interactive() {
        if BlsKeyPair::key_file_exists(key_path).await? {
            writeln!(
                writer,
                "  ({} is left untouched; the mnemonic is the key now)",
                key_path.display()
            )?;
        }
        return Ok(());
    }

    match legacy_bls_pubkey(key_path, reader).await {
        LegacyKey::Absent => Ok(()),
        LegacyKey::Found { pubkey, source } if pubkey == identity.bls_pubkey() => {
            writeln!(
                writer,
                "  (matches the key in {source}; the mnemonic is the key now)"
            )?;
            Ok(())
        }
        LegacyKey::Found { pubkey, source } => Err(anyhow!(
            "the key derived from {MNEMONIC_ENV} is not the key this node was using.\n  \
               derived ({}, account {}): {}\n  \
               held by {source}: {pubkey}\n\
             Registering the derived key would create a second node and leave this one's \
             agreements behind.\n\
             Check {} and {}, and that the mnemonic is the wallet this node's key was \
             exported from. Note that Horizon Wallet can also derive a seed by \
             `mnemonicToEntropy` or the legacy counterwallet scheme rather than BIP-39; \
             a wallet created that way cannot be migrated with {MNEMONIC_ENV}.",
            identity.network,
            identity.account,
            identity.bls_pubkey(),
            crate::crypto::mnemonic::ACCOUNT_INDEX_ENV,
            crate::crypto::mnemonic::NETWORK_ENV,
        )),
        LegacyKey::Unreadable { source, reason } => {
            writeln!(
                writer,
                "  (could not open {source} to check the derived key against it: {reason} \
                 — continuing with the mnemonic)"
            )?;
            Ok(())
        }
    }
}

/// Ensure a BLS keypair exists, either by loading it or importing from Horizon Wallet.
pub async fn ensure_bls_keypair(
    key_path: &Path,
    writer: &mut impl Write,
    password_reader: &dyn PasswordReader,
) -> Result<BlsKeyPair> {
    if BlsKeyPair::key_file_exists(key_path).await? {
        writeln!(
            writer,
            "Found existing BLS key, please enter your password:"
        )?;
        let password = password_reader.read_password()?;
        BlsKeyPair::load_encrypted(key_path, &password).await
    } else {
        writeln!(writer, "No BLS key found. Import from Horizon Wallet.")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "Please paste your encrypted BLS key blob from Horizon Wallet:"
        )?;
        writer.flush().ok();

        let blob = password_reader.read_blob()?;

        writeln!(
            writer,
            "Enter the password used to export the key from Horizon Wallet:"
        )?;
        let wallet_password = password_reader.read_password()?;

        let secret_key_hex = crate::crypto::decrypt_wallet_blob(&blob, &wallet_password)?;
        let keypair = BlsKeyPair::from_secret_key_hex(&secret_key_hex)?;

        writeln!(writer, "✓ BLS key successfully decrypted")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "Choose a password to protect the key on this machine."
        )?;
        writeln!(
            writer,
            "This password will be required each time you start the application."
        )?;
        writeln!(writer)?;

        let local_password = password_reader.read_new_password(writer)?;
        keypair.save_encrypted(key_path, &local_password).await?;

        writeln!(writer, "✓ BLS key saved to {}", key_path.display())?;
        Ok(keypair)
    }
}

/// Mock password reader for testing.
/// Returns a pre-configured password without any user interaction.
#[cfg(test)]
pub struct MockPasswordReader {
    password: String,
    blob: Option<String>,
}

#[cfg(test)]
impl MockPasswordReader {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            blob: None,
        }
    }

    pub fn with_blob(password: impl Into<String>, blob: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            blob: Some(blob.into()),
        }
    }
}

#[cfg(test)]
impl PasswordReader for MockPasswordReader {
    fn read_password(&self) -> Result<String> {
        Ok(self.password.clone())
    }

    fn read_new_password(&self, _writer: &mut dyn Write) -> Result<String> {
        Ok(self.password.clone())
    }

    fn read_blob(&self) -> Result<String> {
        self.blob
            .clone()
            .ok_or_else(|| anyhow!("no blob configured in mock"))
    }

    fn wait_for_enter(&self) -> Result<()> {
        Ok(())
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlsKeyPair;
    use std::path::PathBuf;

    /* ---------------- the migration matrix ---------------- */

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon about";

    /// Both variables `open_or_migrate` consults, cleared and restored around a
    /// case. Every test in this group is `#[serial]` for the same reason.
    struct MigrationEnv {
        mnemonic: Option<String>,
        seal: Option<String>,
        password: Option<String>,
    }

    impl MigrationEnv {
        fn capture() -> Self {
            let guard = Self {
                mnemonic: std::env::var(MNEMONIC_ENV).ok(),
                seal: std::env::var(keystore::SEAL_KEY_ENV).ok(),
                password: std::env::var(BLS_PASSWORD_ENV).ok(),
            };
            std::env::remove_var(MNEMONIC_ENV);
            std::env::remove_var(keystore::SEAL_KEY_ENV);
            std::env::remove_var(BLS_PASSWORD_ENV);
            guard
        }
    }

    impl Drop for MigrationEnv {
        fn drop(&mut self) {
            for (name, value) in [
                (MNEMONIC_ENV, self.mnemonic.take()),
                (keystore::SEAL_KEY_ENV, self.seal.take()),
                (BLS_PASSWORD_ENV, self.password.take()),
            ] {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn settings(account: u32) -> MnemonicSettings {
        MnemonicSettings::new(TEST_PHRASE, crate::crypto::BitcoinNetwork::Signet, account)
    }

    async fn migrate(
        app_dir: &Path,
        key_path: &Path,
        mnemonic: Option<&MnemonicSettings>,
    ) -> Result<KeySource> {
        let mut buffer = Vec::new();
        open_or_migrate(
            app_dir,
            key_path,
            mnemonic,
            &mut buffer,
            &MockPasswordReader::new("legacy-password"),
        )
        .await
    }

    /// The ordinary case now: an empty volume is a node waiting for its wizard,
    /// not an error and not something to prompt about.
    #[tokio::test]
    #[serial_test::serial]
    async fn nothing_on_the_volume_means_uninitialized() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();

        let source = migrate(dir.path(), &dir.path().join("bls_key.enc"), None)
            .await
            .unwrap();

        assert!(matches!(source, KeySource::Uninitialized));
        assert!(!Keystore::path_in(dir.path()).exists());
    }

    /// The migration an existing mnemonic node takes: same identity, now sealed,
    /// and the variable is no longer load-bearing.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_mnemonic_node_is_sealed_into_a_keystore() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let expected = MnemonicIdentity::derive(&settings(2)).unwrap();

        let source = migrate(
            dir.path(),
            &dir.path().join("bls_key.enc"),
            Some(&settings(2)),
        )
        .await
        .unwrap();

        let KeySource::Open { keystore, keys, .. } = source else {
            panic!("a mnemonic must migrate into an open keystore");
        };
        let public = keystore.public().expect("the identity must be recorded");
        assert_eq!(public.node_id, expected.node_id);
        assert_eq!(public.account, 2);
        assert_eq!(keys.keypair().public_key_hex(), expected.bls_pubkey());

        // And it comes back the same way on the next boot, with no mnemonic.
        let again = migrate(dir.path(), &dir.path().join("bls_key.enc"), None)
            .await
            .unwrap();
        let KeySource::Open { keystore, keys, .. } = again else {
            panic!("the keystore must reopen on its own");
        };
        assert_eq!(keystore.public().unwrap().node_id, expected.node_id);
        assert!(keys.seed().is_none(), "the seed must not survive migration");
    }

    /// A node from the wallet-blob era. It has no Taproot account, so it
    /// migrates without one and still runs — it just needs a browser to
    /// register.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_legacy_key_file_is_sealed_without_an_identity() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let keypair = BlsKeyPair::generate().unwrap();
        let expected = keypair.public_key_hex();
        keypair
            .save_encrypted(&key_path, "legacy-password")
            .await
            .unwrap();

        let source = migrate(dir.path(), &key_path, None).await.unwrap();

        let KeySource::Open { keystore, keys, .. } = source else {
            panic!("a key file must migrate into an open keystore");
        };
        assert_eq!(keys.keypair().public_key_hex(), expected);
        assert!(keystore.public().is_none());
        // Left where it was: deleting an operator's key file is not this
        // function's call to make.
        assert!(key_path.exists());
    }

    /// The keystore is the answer, unconditionally. A variable left behind must
    /// not be able to move a running node to another identity.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_stale_mnemonic_never_overrides_the_keystore() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");

        migrate(dir.path(), &key_path, Some(&settings(2)))
            .await
            .unwrap();
        let sealed = MnemonicIdentity::derive(&settings(2)).unwrap();

        // A different account entirely, still set in the environment.
        let source = migrate(dir.path(), &key_path, Some(&settings(5)))
            .await
            .unwrap();

        let KeySource::Open { keystore, .. } = source else {
            panic!("the keystore must still open");
        };
        assert_eq!(keystore.public().unwrap().node_id, sealed.node_id);
    }

    /// A keystore with no key to open it is its own state, not a failure and not
    /// an invitation to provision a second identity over the top.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_keystore_with_no_seal_key_reports_itself_sealed() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");

        migrate(dir.path(), &key_path, Some(&settings(2)))
            .await
            .unwrap();
        std::fs::remove_file(dir.path().join(keystore::SEAL_KEY_FILENAME)).unwrap();

        let source = migrate(dir.path(), &key_path, None).await.unwrap();

        let KeySource::Sealed { keystore, reason } = source else {
            panic!("a keystore nothing can open must report itself sealed");
        };
        assert_eq!(keystore.slots(), vec![crate::crypto::SlotKind::File]);
        assert!(
            reason.is_none(),
            "nothing was tried, so there is nothing to explain: {reason:?}"
        );
    }

    /// The mistake the two-step hardening flow invites: paste `KONTOR_SEAL_KEY`
    /// wrong, redeploy. The node must come up **sealed and serving**, not exit.
    /// Exiting would take `/admin` down — the only place the passphrase slot
    /// can be used, and the only place the mistake can be seen.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_seal_key_that_does_not_open_the_keystore_seals_the_node_rather_than_stopping_it() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");

        let source = migrate(dir.path(), &key_path, Some(&settings(2)))
            .await
            .unwrap();
        let KeySource::Open {
            mut keystore,
            seal_key,
            ..
        } = source
        else {
            panic!("the migration must open the keystore it just wrote");
        };

        // Exactly the two-step flow, played out: the operator adds an env slot,
        // sets the variable, redeploys — and pastes the wrong 32 bytes.
        keystore
            .add_slot(&seal_key, &SealKey::generate(crate::crypto::SlotKind::Env))
            .unwrap();
        std::fs::remove_file(dir.path().join(keystore::SEAL_KEY_FILENAME)).unwrap();

        let mistyped = SealKey::generate(crate::crypto::SlotKind::Env);
        std::env::set_var(keystore::SEAL_KEY_ENV, mistyped.encode().unwrap().as_str());
        let source = migrate(dir.path(), &key_path, None).await;
        std::env::remove_var(keystore::SEAL_KEY_ENV);

        let KeySource::Sealed { reason, .. } = source.expect("a wrong key must not be fatal")
        else {
            panic!("a key that opens nothing must leave the node sealed");
        };
        let reason = reason.expect("something was tried, so it has to be explained");
        assert!(reason.contains("did not open"), "{reason}");
    }

    /// The same rule one step earlier: a `KONTOR_SEAL_KEY` that is not even
    /// base64 is a typo, and a typo must not be a node that will not boot.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_malformed_seal_key_seals_the_node_rather_than_stopping_it() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");

        migrate(dir.path(), &key_path, Some(&settings(2)))
            .await
            .unwrap();
        std::fs::remove_file(dir.path().join(keystore::SEAL_KEY_FILENAME)).unwrap();

        std::env::set_var(keystore::SEAL_KEY_ENV, "obviously not base64 ****");
        let source = migrate(dir.path(), &key_path, None).await;
        std::env::remove_var(keystore::SEAL_KEY_ENV);

        let KeySource::Sealed { reason, .. } = source.expect("a typo must not be fatal") else {
            panic!("an unusable key must leave the node sealed");
        };
        let reason = reason.expect("something was tried, so it has to be explained");
        assert!(reason.contains(keystore::SEAL_KEY_ENV), "{reason}");
    }

    /// Hardening, end to end: the env slot opens the same keystore the file slot
    /// sealed, and the node reports which one it came up through.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_env_seal_key_opens_a_keystore_sealed_by_the_file_one() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");

        let source = migrate(dir.path(), &key_path, Some(&settings(2)))
            .await
            .unwrap();
        let KeySource::Open {
            mut keystore,
            seal_key,
            ..
        } = source
        else {
            panic!("the migration must open");
        };

        let env_key = SealKey::generate(crate::crypto::SlotKind::Env);
        keystore.add_slot(&seal_key, &env_key).unwrap();
        std::env::set_var(keystore::SEAL_KEY_ENV, env_key.encode().unwrap().as_str());
        std::fs::remove_file(dir.path().join(keystore::SEAL_KEY_FILENAME)).unwrap();

        let source = migrate(dir.path(), &key_path, None).await.unwrap();
        let KeySource::Open { seal_source, .. } = source else {
            panic!("the env slot must open it");
        };
        assert_eq!(seal_source, SealKeySource::Env);
    }

    /// A corrupt keystore must stop the node rather than look like a fresh one:
    /// provisioning over it would replace a key that is merely unreadable.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_corrupt_keystore_stops_the_node() {
        let _env = MigrationEnv::capture();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(Keystore::path_in(dir.path()), b"{ not json").unwrap();

        let err = migrate(dir.path(), &dir.path().join("bls_key.enc"), None)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("parsing the keystore"),
            "{err:#}"
        );
    }

    #[test]
    fn get_key_path_returns_custom_path_when_configured() {
        let custom_path = PathBuf::from("/custom/path/key.enc");
        assert_eq!(get_key_path(Some(&custom_path)).unwrap(), custom_path);
    }

    #[test]
    fn get_key_path_returns_default_path_when_not_configured() {
        // This test may fail in an environment without a data directory.
        if let Ok(path) = get_key_path(None) {
            assert!(path.to_string_lossy().contains(BLS_KEY_FILENAME));
        }
    }

    #[test]
    fn mock_password_reader_returns_configured_password() {
        let reader = MockPasswordReader::new("testpassword123");
        assert_eq!(reader.read_password().unwrap(), "testpassword123");
    }

    #[test]
    fn mock_password_reader_returns_same_for_new_password() {
        let reader = MockPasswordReader::new("testpassword123");
        let mut buffer = Vec::new();
        assert_eq!(
            reader.read_new_password(&mut buffer).unwrap(),
            "testpassword123"
        );
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_validates_password_length() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "short");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("at least 8 characters"));
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_validates_non_empty() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn get_password_reader_returns_env_reader_when_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "testpassword123");
        let reader = get_password_reader();
        assert_eq!(reader.read_password().unwrap(), "testpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_password_succeeds_when_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "validpassword123");
        let reader = EnvPasswordReader;
        let result = reader.read_password();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "validpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_password_fails_when_not_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        let reader = EnvPasswordReader;
        let err = reader.read_password().unwrap_err();
        assert!(err.to_string().contains("environment variable is required"));
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_new_password_succeeds_with_valid_password() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        std::env::set_var(BLS_PASSWORD_ENV, "validpassword123");
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let result = reader.read_new_password(&mut buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "validpassword123");
        std::env::remove_var(BLS_PASSWORD_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_new_password_fails_when_not_set() {
        std::env::remove_var(BLS_PASSWORD_ENV); // Clean state
        let reader = EnvPasswordReader;
        let mut buffer = Vec::new();
        let err = reader.read_new_password(&mut buffer).unwrap_err();
        assert!(err.to_string().contains("environment variable is required"));
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_blob_trims_and_succeeds() {
        std::env::remove_var(BLS_BLOB_ENV);
        std::env::set_var(BLS_BLOB_ENV, "  ablobvalue  \n");
        let reader = EnvPasswordReader;
        assert_eq!(reader.read_blob().unwrap(), "ablobvalue");
        std::env::remove_var(BLS_BLOB_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_blob_fails_when_unset() {
        std::env::remove_var(BLS_BLOB_ENV);
        let reader = EnvPasswordReader;
        let err = reader.read_blob().unwrap_err();
        assert!(err.to_string().contains(BLS_BLOB_ENV));
        assert!(err.to_string().contains("required"));
    }

    #[test]
    #[serial_test::serial]
    fn env_password_reader_read_blob_fails_when_empty_after_trim() {
        std::env::remove_var(BLS_BLOB_ENV);
        std::env::set_var(BLS_BLOB_ENV, "   \t  ");
        let reader = EnvPasswordReader;
        let err = reader.read_blob().unwrap_err();
        assert!(err.to_string().contains("empty"));
        std::env::remove_var(BLS_BLOB_ENV);
    }

    #[test]
    fn env_password_reader_wait_for_enter_succeeds() {
        let reader = EnvPasswordReader;
        let result = reader.wait_for_enter();
        assert!(result.is_ok());
    }

    #[test]
    fn mock_password_reader_wait_for_enter_succeeds() {
        let reader = MockPasswordReader::new("testpassword");
        let result = reader.wait_for_enter();
        assert!(result.is_ok());
    }

    fn mnemonic_settings(account: u32) -> MnemonicSettings {
        MnemonicSettings::new(TEST_PHRASE, crate::crypto::BitcoinNetwork::Signet, account)
    }

    /// The migration in one test: a node that bootstrapped from a blob still has
    /// `bls_key.enc` on disk, and the password it was written with is gone. The
    /// mnemonic has to win outright — reading the file would stop at a password
    /// prompt no container can answer, and preferring it would ignore the
    /// account index the operator just set.
    ///
    /// The cross-check cannot run here, and that has to be said: a guard that
    /// did not run reads afterwards exactly like a guard that passed.
    #[tokio::test]
    async fn a_mnemonic_wins_over_a_key_file_it_cannot_open() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let stale = BlsKeyPair::generate().unwrap();
        stale
            .save_encrypted(&key_path, "the-password-we-no-longer-have")
            .await
            .unwrap();

        let settings = mnemonic_settings(2);
        let expected = MnemonicIdentity::derive(&settings).unwrap();

        // Any password this reader offers is wrong for the file above, so
        // reaching the file at all would fail rather than pass quietly.
        let reader = MockPasswordReader::new("not-the-password");
        let mut buffer = Vec::new();

        let keys = ensure_node_keys(&key_path, Some(&settings), &mut buffer, &reader)
            .await
            .unwrap();

        assert_eq!(keys.keypair().public_key_hex(), expected.bls_pubkey());
        assert_ne!(keys.keypair().public_key_hex(), stale.public_key_hex());
        let identity = keys.seed().expect("mnemonic mode yields an identity");
        assert_eq!(identity.account, 2);

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains(&expected.taproot_address), "{output}");
        assert!(output.contains("could not open"), "{output}");
    }

    /// The check this exists for. Every other guard on the mnemonic path asks
    /// the Portal about keys derived from the same constants it is validating,
    /// so a wrong derivation is invisible to all of them and the node quietly
    /// registers a second identity. The key file is the one thing on the
    /// machine that did not come from the mnemonic.
    #[tokio::test]
    async fn a_derivation_that_disagrees_with_the_existing_key_is_fatal() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let password = "testpassword123";

        // The key this node is actually registered with — from some other
        // wallet, or the same wallet under a seed derivation the node does not
        // implement. Either way the mnemonic does not reproduce it.
        let registered = BlsKeyPair::generate().unwrap();
        registered
            .save_encrypted(&key_path, password)
            .await
            .unwrap();

        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let err = ensure_node_keys(&key_path, Some(&mnemonic_settings(2)), &mut buffer, &reader)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("is not the key this node was using"), "{err}");
        assert!(err.contains(&registered.public_key_hex()), "{err}");
        assert!(err.contains("second node"), "{err}");
        assert!(
            err.contains(crate::crypto::mnemonic::ACCOUNT_INDEX_ENV),
            "{err}"
        );
    }

    /// The happy migration: the mnemonic reproduces the key the node already
    /// had. Saying so is the whole point — it is the one moment the
    /// compatibility claim is actually tested on the operator's own machine.
    #[tokio::test]
    async fn a_derivation_matching_the_existing_key_is_confirmed() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let password = "testpassword123";

        let settings = mnemonic_settings(2);
        let identity = MnemonicIdentity::derive(&settings).unwrap();
        identity
            .keypair
            .save_encrypted(&key_path, password)
            .await
            .unwrap();

        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let keys = ensure_node_keys(&key_path, Some(&settings), &mut buffer, &reader)
            .await
            .unwrap();

        assert_eq!(keys.keypair().public_key_hex(), identity.bls_pubkey());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("matches the key in"), "{output}");
    }

    /// The same check against the wallet's own export, which is the form the
    /// key arrives in and one decryption away from what the Portal knows.
    #[tokio::test]
    async fn a_derivation_that_disagrees_with_the_wallet_blob_is_fatal() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_password = "walletpass123";
        let foreign_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let blob = crate::crypto::wallet_import::encrypt_test_blob(
            foreign_secret,
            wallet_password,
            &[1u8; 16],
            &[2u8; 16],
        );

        let reader = MockPasswordReader::with_blob(wallet_password, blob);
        let mut buffer = Vec::new();

        let err = ensure_node_keys(
            &dir.path().join("absent.enc"),
            Some(&mnemonic_settings(2)),
            &mut buffer,
            &reader,
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("is not the key this node was using"), "{err}");
        assert!(err.contains(BLS_BLOB_ENV), "{err}");
        // The wallet supports seed derivations this node does not implement,
        // which is a mismatch no amount of re-checking the account index fixes.
        assert!(err.contains("mnemonicToEntropy"), "{err}");
    }

    /// A blob that will not open must not cost the node the check.
    ///
    /// One reader, one password, two different secrets behind it: the blob
    /// wants the wallet's export password and the file wants the local one, so
    /// a node that still has both routinely fails the first and passes the
    /// second. Stopping at the blob would silently skip the only guard that
    /// catches a wrong derivation — on precisely the nodes migrating from a
    /// wallet export, which is what it was written for.
    #[tokio::test]
    async fn an_unopenable_blob_falls_through_to_the_key_file() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let local_password = "localpass123";

        // The key this node is really registered with, readable with the
        // reader's password.
        let registered = BlsKeyPair::generate().unwrap();
        registered
            .save_encrypted(&key_path, local_password)
            .await
            .unwrap();

        // A blob from the same wallet, sealed with a password the reader does
        // not have.
        let blob = crate::crypto::wallet_import::encrypt_test_blob(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "a-different-export-password",
            &[1u8; 16],
            &[2u8; 16],
        );

        let reader = MockPasswordReader::with_blob(local_password, blob);
        let mut buffer = Vec::new();

        let err = ensure_node_keys(&key_path, Some(&mnemonic_settings(2)), &mut buffer, &reader)
            .await
            .unwrap_err()
            .to_string();

        // Fatal, and blamed on the file: proof the fallback ran rather than the
        // blob's failure being taken for the end of the check.
        assert!(err.contains("is not the key this node was using"), "{err}");
        assert!(err.contains(&registered.public_key_hex()), "{err}");
        assert!(err.contains(&key_path.display().to_string()), "{err}");
    }

    /// With nothing to fall through to, the blob's failure is what gets
    /// reported: a check that did not run must not read like one that passed.
    #[tokio::test]
    async fn an_unopenable_blob_is_reported_when_there_is_no_key_file() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let blob = crate::crypto::wallet_import::encrypt_test_blob(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "a-different-export-password",
            &[1u8; 16],
            &[2u8; 16],
        );

        let reader = MockPasswordReader::with_blob("not-the-export-password", blob);
        let mut buffer = Vec::new();

        let keys = ensure_node_keys(
            &dir.path().join("absent.enc"),
            Some(&mnemonic_settings(2)),
            &mut buffer,
            &reader,
        )
        .await
        .unwrap();

        assert!(keys.seed().is_some());
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("could not open"), "{output}");
        assert!(output.contains(BLS_BLOB_ENV), "{output}");
    }

    /// A fresh mnemonic node has nothing to compare against, and that is not a
    /// problem to report — it is the ordinary case.
    #[tokio::test]
    async fn a_node_with_no_previous_key_is_left_alone() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let reader = MockPasswordReader::new("unused");
        let mut buffer = Vec::new();

        let keys = ensure_node_keys(
            &dir.path().join("absent.enc"),
            Some(&mnemonic_settings(2)),
            &mut buffer,
            &reader,
        )
        .await
        .unwrap();

        assert!(keys.seed().is_some());

        let output = String::from_utf8(buffer).unwrap();
        assert!(!output.contains("could not open"), "{output}");
        assert!(!output.contains("matches the key in"), "{output}");
    }

    /// On a terminal the check would cost a password prompt for a file the node
    /// is about to ignore, which is exactly the prompt mnemonic mode exists to
    /// remove. It is skipped, and the file is simply reported as untouched.
    #[tokio::test]
    async fn an_interactive_start_is_never_stopped_by_the_cross_check() {
        use tempfile::tempdir;

        struct InteractiveReader;
        impl PasswordReader for InteractiveReader {
            fn read_password(&self) -> Result<String> {
                panic!("mnemonic mode must never prompt for the legacy key");
            }
            fn read_new_password(&self, _writer: &mut dyn Write) -> Result<String> {
                panic!("mnemonic mode must never prompt");
            }
            fn read_blob(&self) -> Result<String> {
                panic!("mnemonic mode must never prompt");
            }
            fn wait_for_enter(&self) -> Result<()> {
                Ok(())
            }
            fn is_interactive(&self) -> bool {
                true
            }
        }

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        BlsKeyPair::generate()
            .unwrap()
            .save_encrypted(&key_path, "testpassword123")
            .await
            .unwrap();

        let mut buffer = Vec::new();
        let keys = ensure_node_keys(
            &key_path,
            Some(&mnemonic_settings(2)),
            &mut buffer,
            &InteractiveReader,
        )
        .await
        .unwrap();

        assert!(keys.seed().is_some());
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("left untouched"), "{output}");
    }

    /// `NodeKeys` reaches a `tracing` field on the error paths, and both arms
    /// wrap a secret key.
    #[tokio::test]
    async fn node_keys_debug_redacts_either_way() {
        use crate::crypto::BitcoinNetwork;

        let imported = NodeKeys::Imported(Box::new(BlsKeyPair::generate().unwrap()));
        let rendered = format!("{imported:?}");
        assert!(rendered.contains("Imported"), "{rendered}");
        assert!(rendered.contains("BlsKeyPair"), "{rendered}");

        let settings = MnemonicSettings::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon about",
            BitcoinNetwork::Signet,
            2,
        );
        let derived = NodeKeys::Derived(Box::new(MnemonicIdentity::derive(&settings).unwrap()));
        let rendered = format!("{derived:?}");
        assert!(rendered.contains("Derived"), "{rendered}");
        assert!(!rendered.contains("abandon"), "{rendered}");
    }

    /// Without a mnemonic nothing changes: the key file is still the key.
    #[tokio::test]
    async fn without_a_mnemonic_the_key_file_is_still_used() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("bls_key.enc");
        let password = "testpassword123";
        let keypair = BlsKeyPair::generate().unwrap();
        keypair.save_encrypted(&key_path, password).await.unwrap();

        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let keys = ensure_node_keys(&key_path, None, &mut buffer, &reader)
            .await
            .unwrap();

        assert_eq!(keys.keypair().public_key_hex(), keypair.public_key_hex());
        assert!(keys.seed().is_none());
    }

    #[tokio::test]
    async fn ensure_bls_keypair_imports_from_wallet_blob() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("imported_key.enc");

        let bls_hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let wallet_password = "walletpass123";
        let salt = [1u8; 16];
        let iv = [2u8; 16];
        let blob = crate::crypto::wallet_import::encrypt_test_blob(
            bls_hex_key,
            wallet_password,
            &salt,
            &iv,
        );

        let reader = MockPasswordReader::with_blob(wallet_password, blob);
        let mut buffer = Vec::new();

        let keypair = ensure_bls_keypair(&key_path, &mut buffer, &reader)
            .await
            .unwrap();

        let expected = BlsKeyPair::from_secret_key_hex(bls_hex_key).unwrap();
        assert_eq!(keypair.public_key_hex(), expected.public_key_hex());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("No BLS key found"));
        assert!(output.contains("BLS key successfully decrypted"));
        assert!(output.contains("BLS key saved to"));
        assert!(!keypair.public_key_hex().is_empty());
        assert!(BlsKeyPair::key_file_exists(&key_path).await.unwrap());

        let reloaded = BlsKeyPair::load_encrypted(&key_path, wallet_password)
            .await
            .unwrap();
        assert_eq!(reloaded.public_key_hex(), keypair.public_key_hex());
    }

    #[tokio::test]
    async fn ensure_bls_keypair_loads_existing_key() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("existing_key.enc");
        let password = "testpassword123";

        // Create an existing key
        let original = BlsKeyPair::generate().unwrap();
        let original_pk = original.public_key_hex();
        original.save_encrypted(&key_path, password).await.unwrap();

        let reader = MockPasswordReader::new(password);
        let mut buffer = Vec::new();

        let loaded = ensure_bls_keypair(&key_path, &mut buffer, &reader)
            .await
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("Found existing BLS key"));
        assert_eq!(loaded.public_key_hex(), original_pk);
    }
}
