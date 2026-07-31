//! Authenticated encryption and key-derivation primitives shared by everything
//! this node seals.
//!
//! These were written for [`crate::crypto::bls`]'s `bls_key.enc` and are now
//! also what [`crate::crypto::keystore`] is built on. Nothing here is new
//! cryptography: Argon2id to turn a human secret into a key, AES-256-GCM to seal
//! bytes under one, and an atomic 0600 write so a half-written keystore never
//! replaces a good one.
//!
//! Two rules the callers depend on:
//!
//! - **Every seal gets a fresh random nonce.** AES-GCM fails catastrophically on
//!   nonce reuse under the same key, so [`seal`] generates the nonce itself
//!   rather than accepting one. There is no API here that lets a caller supply
//!   it.
//! - **Additional authenticated data is not optional.** [`seal`] and [`open`]
//!   both take `aad`, and every call site passes something that names what the
//!   ciphertext is for. That is what stops a slot wrap from being replayed as a
//!   secret wrap inside the same file.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Salt size for Argon2id (16 bytes recommended).
pub const SALT_SIZE: usize = 16;

/// Nonce size for AES-256-GCM (12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Size of every key this module derives or generates.
pub const KEY_SIZE: usize = 32;

/// Argon2id cost parameters.
///
/// Two profiles exist and the difference is deliberate — see [`Kdf::AT_REST`]
/// and [`Kdf::LOGIN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Kdf {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Kdf {
    /// For material an attacker could carry away and grind offline: a stolen
    /// `bls_key.enc`, a stolen `keystore.json`. OWASP's recommendation for
    /// sensitive keys, and the parameters `bls_key.enc` has always used — they
    /// are load-bearing for reading existing files, not a preference.
    pub const AT_REST: Self = Self {
        m_cost: 65536, // 64 MiB
        t_cost: 3,
        p_cost: 4,
    };

    /// For the admin login hash, which is a different problem. The endpoint is
    /// throttled and the password has a length floor, so the threat is online
    /// guessing rather than an offline grind; 64 MiB per attempt would instead
    /// hand anyone who can reach `/admin` a memory-exhaustion lever. OWASP's
    /// interactive profile.
    pub const LOGIN: Self = Self {
        m_cost: 19456, // 19 MiB
        t_cost: 2,
        p_cost: 1,
    };
}

impl Default for Kdf {
    fn default() -> Self {
        Self::AT_REST
    }
}

/// Derive a 32-byte key-encryption key from a password and salt.
///
/// # Errors
/// If the cost parameters are invalid or Argon2 fails.
pub fn derive_kek(password: &[u8], salt: &[u8], kdf: &Kdf) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_SIZE))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| anyhow!("failed to derive key: {e}"))?;

    Ok(key)
}

/// Seal `plaintext` under `key`, binding it to `aad`.
///
/// Returns the freshly generated nonce alongside the ciphertext; both are needed
/// to [`open`] it again, and neither is secret.
///
/// # Errors
/// If the key is the wrong length or the AEAD refuses the input.
pub fn seal(key: &[u8; KEY_SIZE], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("failed to create cipher: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("failed to encrypt: {e}"))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Open what [`seal`] produced.
///
/// The error is deliberately one message for every failure — wrong key, wrong
/// `aad`, truncated ciphertext, flipped bit. AES-GCM cannot tell them apart
/// before it has verified the tag, and pretending otherwise would be an oracle.
///
/// # Errors
/// If the key or nonce is the wrong length, or authentication fails.
pub fn open(
    key: &[u8; KEY_SIZE],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_SIZE {
        return Err(anyhow!(
            "nonce must be {NONCE_SIZE} bytes, got {}",
            nonce.len()
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("failed to create cipher: {e}"))?;

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed: wrong key or corrupted data"))?;

    Ok(Zeroizing::new(plaintext))
}

/// A short, non-reversible identifier for a secret, so two people can check
/// they hold the same one without either of them saying it.
///
/// One implementation, four callers — the seal key, the setup token, the
/// envelope's public key, and the keystore's own tests. Each passes its own
/// `domain`, which is what stops a fingerprint of one from ever matching a
/// fingerprint of another over the same bytes.
///
/// Four bytes, and that bound is load-bearing rather than arbitrary: this value
/// is published in bodies that are not themselves sealed, so it has to be short
/// enough to narrow nothing. It is only ever safe over material an attacker has
/// no list to try — see [`crate::crypto::keystore::SealKey::fingerprint`] for
/// the one place that rule forced a `None`.
#[must_use]
pub fn fingerprint(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(&hasher.finalize()[..4])
}

/// Refuse a file written by a build that knew something this one does not.
///
/// Shared by every versioned file this node keeps — the keystore and the admin
/// credential — because the two failures are the same failure and the wording
/// is the part worth getting right once: a node that silently read a future
/// format would act on fields it could not see.
///
/// # Errors
/// If `found` is not `expected`.
pub fn check_version(path: &Path, found: u32, expected: u32) -> Result<()> {
    if found == expected {
        return Ok(());
    }

    Err(anyhow!(
        "{} has version {found}, which this node does not understand (it writes \
         version {expected}). It was probably written by a newer build.",
        path.display()
    ))
}

/// A fresh 32-byte random key.
#[must_use]
pub fn random_key() -> Zeroizing<[u8; KEY_SIZE]> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    rand::thread_rng().fill_bytes(key.as_mut());
    key
}

/// A fresh random salt.
#[must_use]
pub fn random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Write a file only the node's own user can read, replacing any previous
/// version atomically.
///
/// Synchronous, and on purpose. The mode has to be set *at creation* — setting
/// it afterwards leaves a window where the keystore is world-readable — and
/// `OpenOptions::mode` is the only way to do that. Everything written through
/// here is well under a kilobyte and written a handful of times per process, so
/// the blocking cost is noise next to getting the permissions wrong.
///
/// The temporary file lives in the destination directory rather than `/tmp` so
/// the rename stays within one filesystem, which is what makes it atomic. Its
/// name is unique per write — see [`temp_path`] — and the directory entry the
/// rename creates is flushed as well as the contents, so a crash lands on
/// either the old file or the new one and never on neither.
///
/// # Errors
/// If the parent directory cannot be created, or the write or rename fails.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let tmp = temp_path(path);
    let result = stage(&tmp, bytes).and_then(|()| {
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    });

    if result.is_err() {
        // The rename never happened, so this is scratch nobody will read. Best
        // effort: a leftover is untidy, not dangerous, and the original error is
        // the one worth reporting.
        let _ = std::fs::remove_file(&tmp);
        return result;
    }

    // The contents were flushed before the rename; this flushes the *name*. A
    // failure here means the new file may not survive a power cut — it does not
    // mean the write failed, and reporting it as one would have a caller undo
    // work that is already visible to every reader.
    if let Some(parent) = parent {
        if let Err(e) = sync_dir(parent) {
            tracing::warn!(
                error = %format!("{e:#}"),
                path = %path.display(),
                "wrote a secret file but could not flush its directory entry"
            );
        }
    }

    Ok(())
}

/// Write the payload to a fresh 0600 file and get it onto the disk.
fn stage(tmp: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    // `create_new`, so a leftover from an interrupted write is never appended to
    // or silently reused as somebody else's scratch space.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut handle = options
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    handle
        .write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    handle
        .sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))
}

/// A scratch name in the destination directory that no other write will pick.
///
/// One fixed `.tmp` is enough for a single writer, and there is more than one:
/// `/admin` can add a seal slot while another request drops one, both rewriting
/// the same keystore. Two writers sharing a scratch file interleave into
/// something that renames perfectly well and is not either version.
///
/// Random rather than a pid and a counter, which is the obvious alternative and
/// is wrong here. In a container the node is pid 1 and its counters start at
/// zero, so a scratch file left by a crash is exactly the name the next boot
/// would choose — and `create_new` would then refuse to write the keystore for
/// the rest of the volume's life.
fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", hex::encode(nonce)));
    path.with_file_name(name)
}

/// Flush a directory, committing the entries renamed into it.
///
/// `sync_all` on a file commits its contents and says nothing about the name
/// pointing at them. Without this, a crash can leave the directory still naming
/// the old file while the new one exists only under a temporary name — which is
/// exactly the outcome writing through a rename is meant to rule out.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .with_context(|| format!("flushing {}", dir.display()))
}

/// Not portable, and not needed: opening a directory as a file is a Unix
/// notion. Production is Linux.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"KONTOR_TEST_AAD";

    #[test]
    fn seal_and_open_round_trip() {
        let key = random_key();
        let (nonce, ct) = seal(&key, AAD, b"the secret").unwrap();

        let opened = open(&key, AAD, &nonce, &ct).unwrap();
        assert_eq!(opened.as_slice(), b"the secret");
    }

    /// The nonce is generated per call, so the same plaintext under the same key
    /// must not produce the same bytes twice. This is the property AES-GCM
    /// cannot survive losing.
    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let key = random_key();
        let (nonce_a, ct_a) = seal(&key, AAD, b"same plaintext").unwrap();
        let (nonce_b, ct_b) = seal(&key, AAD, b"same plaintext").unwrap();

        assert_ne!(nonce_a, nonce_b);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn open_rejects_the_wrong_key() {
        let key = random_key();
        let other = random_key();
        let (nonce, ct) = seal(&key, AAD, b"the secret").unwrap();

        assert!(open(&other, AAD, &nonce, &ct).is_err());
    }

    /// The point of threading `aad` through every call: a ciphertext sealed for
    /// one purpose must not open for another, even under the right key.
    #[test]
    fn open_rejects_the_wrong_aad() {
        let key = random_key();
        let (nonce, ct) = seal(&key, b"purpose-a", b"the secret").unwrap();

        assert!(open(&key, b"purpose-b", &nonce, &ct).is_err());
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = random_key();
        let (nonce, mut ct) = seal(&key, AAD, b"the secret").unwrap();
        ct[0] ^= 0x01;

        assert!(open(&key, AAD, &nonce, &ct).is_err());
    }

    #[test]
    fn open_rejects_a_malformed_nonce() {
        let key = random_key();
        let (_, ct) = seal(&key, AAD, b"the secret").unwrap();

        let err = open(&key, AAD, &[0u8; 4], &ct).unwrap_err();
        assert!(err.to_string().contains("nonce must be"), "{err}");
    }

    /// Every failure mode reports the same thing. Distinguishing them would tell
    /// an attacker which half of the guess was right.
    #[test]
    fn open_does_not_say_why_it_failed() {
        let key = random_key();
        let other = random_key();
        let (nonce, ct) = seal(&key, AAD, b"the secret").unwrap();

        let wrong_key = open(&other, AAD, &nonce, &ct).unwrap_err().to_string();
        let wrong_aad = open(&key, b"other", &nonce, &ct).unwrap_err().to_string();
        assert_eq!(wrong_key, wrong_aad);
    }

    #[test]
    fn derive_kek_is_deterministic_for_the_same_inputs() {
        let salt = random_salt();
        let a = derive_kek(b"password", &salt, &Kdf::LOGIN).unwrap();
        let b = derive_kek(b"password", &salt, &Kdf::LOGIN).unwrap();

        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn derive_kek_separates_passwords_and_salts() {
        let salt = random_salt();
        let other_salt = random_salt();

        let base = derive_kek(b"password", &salt, &Kdf::LOGIN).unwrap();
        let other_password = derive_kek(b"different", &salt, &Kdf::LOGIN).unwrap();
        let other_salt = derive_kek(b"password", &other_salt, &Kdf::LOGIN).unwrap();

        assert_ne!(base.as_slice(), other_password.as_slice());
        assert_ne!(base.as_slice(), other_salt.as_slice());
    }

    /// The two profiles must not collapse into each other — if they ever did,
    /// the login hash would silently inherit the 64 MiB cost.
    #[test]
    fn the_two_kdf_profiles_differ() {
        assert_ne!(Kdf::AT_REST, Kdf::LOGIN);
        assert_eq!(Kdf::default(), Kdf::AT_REST);

        let salt = random_salt();
        let at_rest = derive_kek(b"password", &salt, &Kdf::AT_REST).unwrap();
        let login = derive_kek(b"password", &salt, &Kdf::LOGIN).unwrap();
        assert_ne!(at_rest.as_slice(), login.as_slice());
    }

    #[test]
    fn derive_kek_rejects_invalid_parameters() {
        let kdf = Kdf {
            m_cost: 0,
            t_cost: 0,
            p_cost: 0,
        };
        assert!(derive_kek(b"password", &random_salt(), &kdf).is_err());
    }

    /// Four bytes, stable, and different for different inputs — the three
    /// properties every caller of it relies on.
    #[test]
    fn a_fingerprint_is_short_stable_and_specific() {
        const DOMAIN: &[u8] = b"KONTOR_TEST_FP";

        assert_eq!(fingerprint(DOMAIN, b"secret").len(), 8);
        assert_eq!(
            fingerprint(DOMAIN, b"secret"),
            fingerprint(DOMAIN, b"secret")
        );
        assert_ne!(
            fingerprint(DOMAIN, b"secret"),
            fingerprint(DOMAIN, b"other")
        );
        assert!(!fingerprint(DOMAIN, b"secret").contains("secret"));
    }

    /// The reason every caller passes a domain: the same bytes must fingerprint
    /// differently depending on what they are, so a seal key's identifier can
    /// never be mistaken for a setup token's.
    #[test]
    fn the_domain_separates_fingerprints_of_the_same_bytes() {
        assert_ne!(
            fingerprint(b"KONTOR_A", b"the same bytes"),
            fingerprint(b"KONTOR_B", b"the same bytes")
        );
    }

    #[test]
    fn check_version_accepts_its_own_and_names_anything_else() {
        let path = Path::new("/data/keystore.json");

        assert!(check_version(path, 1, 1).is_ok());

        let err = check_version(path, 99, 1).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
        assert!(err.to_string().contains("keystore.json"), "{err}");
        assert!(err.to_string().contains("newer build"), "{err}");
    }

    #[test]
    fn random_key_and_salt_are_the_expected_sizes() {
        assert_eq!(random_key().len(), KEY_SIZE);
        assert_eq!(random_salt().len(), SALT_SIZE);
        assert_ne!(random_key().as_slice(), random_key().as_slice());
    }

    #[test]
    fn write_secret_file_creates_missing_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deeper").join("secret.json");

        write_secret_file(&path, b"payload").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[test]
    fn write_secret_file_replaces_an_existing_file_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");

        write_secret_file(&path, b"first").unwrap();
        write_secret_file(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");

        write_secret_file(&path, b"payload").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /// A file that already exists with looser permissions must come back owner-
    /// only: the rename brings the temporary file's mode with it.
    #[cfg(unix)]
    #[test]
    fn write_secret_file_tightens_a_loose_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_secret_file(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /// Two writers on one path — `/admin` adding a seal slot while another
    /// request drops one — must not share a scratch file. If they did, the
    /// loser's bytes would interleave with the winner's into something that
    /// renames perfectly well and is neither version.
    #[test]
    fn concurrent_writes_do_not_share_a_scratch_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        let payloads: Vec<Vec<u8>> = (0..8u8).map(|n| vec![n; 4096]).collect();

        std::thread::scope(|scope| {
            for payload in &payloads {
                let path = path.clone();
                scope.spawn(move || write_secret_file(&path, payload).unwrap());
            }
        });

        // Whichever won, the file has to be one of them in full — never a mix.
        let landed = std::fs::read(&path).unwrap();
        assert!(payloads.contains(&landed), "a torn write landed on disk");

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }

    /// Scratch names must not repeat, across writes *or* across restarts. The
    /// second half is why they are random: a container is always pid 1 with its
    /// counters at zero, so a name derived from those would be the same one a
    /// crashed write already left on the volume — and `create_new` would then
    /// refuse to save the keystore for the rest of that volume's life.
    #[test]
    fn scratch_names_are_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");

        let names: std::collections::HashSet<_> = (0..256).map(|_| temp_path(&path)).collect();
        assert_eq!(names.len(), 256, "a scratch name was handed out twice");

        // And debris under those names is stepped over rather than tripped on.
        for name in &names {
            std::fs::write(name, b"debris").unwrap();
        }
        write_secret_file(&path, b"payload").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[test]
    fn write_secret_file_reports_where_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be: the open must fail, not panic.
        let path = dir.path().join("occupied");
        std::fs::create_dir(&path).unwrap();

        let err = write_secret_file(&path, b"payload").unwrap_err();
        assert!(err.to_string().contains("occupied"), "{err}");
    }
}
