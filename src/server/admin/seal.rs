//! `/api/admin/seal/*` — inspect and change how this node's key is sealed.
//!
//! # Every secret here travels sealed
//!
//! Three of these endpoints move something that must not appear in a body a
//! proxy might log, and they move it in both directions:
//!
//! - `POST /seal/env-slot` hands back a key that, together with the volume,
//!   *is* this node's BLS key. It goes out sealed to the browser.
//! - `POST /seal/passphrase` and `POST /unseal` take a passphrase that opens the
//!   keystore. It comes in sealed to this process.
//!
//! [`crate::server::admin::envelope`] is that channel and explains itself. The
//! point worth making here is that it would be incoherent to protect the
//! mnemonic at setup and then post the key that replaces it in the clear: an
//! edge that logs the one logs the other.
//!
//! # The hardening flow, and why it is two steps
//!
//! A zero-configuration node seals its key under a random key written next to
//! the keystore. That defends against the environment leaking and not against
//! the volume leaking, so an operator who wants the other half moves the key
//! into `KONTOR_SEAL_KEY`.
//!
//! The obvious way to do that — show the key, delete the file — is a one-way
//! door. A mistyped paste, a variable set on the wrong service, a deploy that
//! did not pick it up, and the only thing that could open the keystore is gone.
//!
//! So it is two steps with a redeploy in between:
//!
//! 1. `POST /seal/env-slot` adds an env slot and returns the key **once**. The
//!    file slot is untouched, so the node still comes up exactly as before.
//! 2. The operator sets `KONTOR_SEAL_KEY` and redeploys. On the way up the node
//!    records which slot it actually opened through — see
//!    [`crate::app::lifecycle::SealStatus`].
//! 3. Only when that record says `env` does `POST /seal/drop-file-slot` agree to
//!    remove the file. By then the env slot is not a claim, it is something the
//!    node has demonstrably booted on.
//!
//! [`crate::crypto::Keystore::remove_slot`] enforces the other half of the same
//! rule — never leave a node with nothing a machine can supply — so a mistake
//! here is refused twice.
//!
//! # Why the Argon2 work is not done on this thread
//!
//! A passphrase slot is wrapped under [`crate::crypto::aead::Kdf::AT_REST`] —
//! 64 MiB and four lanes, deliberately, because it guards material an attacker
//! holding the keystore can grind offline. That is most of a second of solid
//! CPU. Running it inline would park a `tokio` worker for the whole of it and
//! stall every unrelated request that worker was multiplexing, so it goes to
//! `spawn_blocking` where a long, CPU-bound job belongs.

use anyhow::Result;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::app::lifecycle::{Activation, Phase, SealStatus};
use crate::crypto::keystore::{self, Keystore, SealKey, SealKeySource, SlotKind};
use crate::server::admin::envelope::{self, EnvelopeSession, SealedRequest};
use crate::server::admin::{error_codes, ApiError};
use crate::server::state::DownloadServerState;

/// Minimum length of a seal passphrase.
///
/// Higher than the admin password's floor, and for a different reason: this one
/// is not behind a login throttle. It guards material an attacker who has the
/// keystore file can grind offline, so length is the only thing standing between
/// them and the key. Argon2id at [`crate::crypto::aead::Kdf::AT_REST`] buys time,
/// not immunity.
pub const MIN_PASSPHRASE_LEN: usize = 20;

/// `GET /api/admin/seal` — how this node is sealed right now.
#[must_use]
pub fn status(state: &DownloadServerState) -> Value {
    render(&state.runtime.seal())
}

/// The body of [`status`], over the seal status alone.
///
/// Split out so the tests below drive the real thing. A test that rebuilt this
/// object to assert on it would pass for as long as the copy agreed with
/// itself, which is exactly as long as nobody changed either.
///
/// Nothing here is secret. Which slots exist and which one this boot came up on
/// are facts an operator needs before deciding anything, and `fingerprint` is
/// absent for the one kind of key that could be narrowed by publishing four
/// bytes of a hash of it — see [`SealKey::fingerprint`].
#[must_use]
fn render(seal: &SealStatus) -> Value {
    // Every offer below is gated on the node holding the key that opened its
    // keystore, because every one of them has to unwrap the data key with it.
    // `slots` alone is not enough: a node in `Phase::Failed`, or one caught
    // between provisioning and its first activation, reports slots it cannot
    // currently open — and offering a change there is offering a button whose
    // only possible answer is an error.
    let open = seal.is_open();

    json!({
        "slots": seal.slots.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "opened_with": seal.opened_with.map(|kind| kind.to_string()),
        "fingerprint": seal.fingerprint,
        "can_add_env_slot": open && !seal.slots.contains(&SlotKind::Env),
        "can_drop_file_slot": open && seal.can_drop_file_slot(),
        // A sealed node is the one that most wants a passphrase and is the one
        // place it cannot be added, which is why the page has to say so.
        "can_add_passphrase_slot": open,
        "has_passphrase_slot": seal.slots.contains(&SlotKind::Passphrase),
        "min_passphrase_len": MIN_PASSPHRASE_LEN,
        "env_var": keystore::SEAL_KEY_ENV,
    })
}

/// Request body for the seal mutations that need confirming.
///
/// Not sealed, and it does not need to be: a confirmation phrase is a typed
/// intent, not a secret.
#[derive(Debug, Default, Deserialize)]
pub struct SealRequest {
    #[serde(default)]
    pub confirm: String,
}

/// What the browser seals when it sends a passphrase.
#[derive(Deserialize)]
struct PassphrasePayload {
    #[serde(default)]
    passphrase: String,
}

/// What the node seals back when it hands out a key.
///
/// The key is `Zeroizing` rather than a bare `String`, and the difference is
/// not decorative: `SealKey::encode` hands back a zeroizing buffer, and copying
/// it into a plain field to be serialized would leave the base64 of this node's
/// seal key in a heap allocation nothing ever wipes — in the one struct on this
/// path whose whole purpose is to carry it.
#[derive(Serialize)]
struct EnvSlotReply {
    env_var: &'static str,
    key: Zeroizing<String>,
}

/// The phrase a destructive seal change has to carry, mirroring the reset.
pub const CONFIRMATION_PHRASE: &str = "DROP";

/// `POST /api/admin/seal/env-slot` — generate a key for `KONTOR_SEAL_KEY`.
///
/// The key is returned **once**, sealed to the browser that asked, and never
/// stored anywhere this node can read it back from. If the operator loses it
/// before pasting it in, the fix is to call this again: the previous env slot is
/// simply replaced.
///
/// # Errors
/// - `400 INVALID_ENVELOPE` when the envelope is unknown, expired, or its
///   payload does not authenticate.
/// - `409 SEAL_UNAVAILABLE` when there is no open keystore to add a slot to.
/// - `500` when the keystore cannot be written.
pub async fn add_env_slot(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    // Opened before anything is written. The request carries nothing this
    // endpoint needs, but a browser that cannot produce a ciphertext this
    // process opens is a browser that will not be able to read the reply — and
    // finding that out *after* committing a slot to it is the wrong order.
    let (session, _) = envelope::open(request, state)?;

    let _guard = state.admin.lock_keystore().await;
    let (mut keystore, unlock) = open_keystore(state).await?;

    let new = SealKey::generate(SlotKind::Env);
    keystore
        .add_slot(&unlock, &new)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    state.runtime.set_slots(keystore.slots());

    // A generated raw key always has one; the type is `Option` for the sake of
    // passphrases, which must never be fingerprinted.
    let fingerprint = new.fingerprint();
    tracing::info!(
        fingerprint = ?fingerprint,
        "Added an env seal slot from /admin; the key was sealed to the browser once and not retained"
    );

    Ok(json!({
        "env_var": keystore::SEAL_KEY_ENV,
        // Not the key: the operator compares this against the node's logs after
        // the redeploy, and it reveals nothing on its own.
        "fingerprint": fingerprint,
        "sealed": seal_reply(
            &session,
            &request.client_pubkey,
            &EnvSlotReply {
                env_var: keystore::SEAL_KEY_ENV,
                key: new.encode(),
            },
        )?,
        "next": format!(
            "Set {}=<key> on this deployment and restart. Once the node reports that it \
             opened through the env slot, the file slot can be removed.",
            keystore::SEAL_KEY_ENV
        ),
    }))
}

/// `POST /api/admin/seal/drop-file-slot` — remove `.seal-key`.
///
/// # Errors
/// - `400 CONFIRMATION_REQUIRED` without the confirmation phrase.
/// - `409 SEAL_UNAVAILABLE` when this boot did not come up through the env slot.
/// - `500` when the keystore cannot be written.
pub async fn drop_file_slot(
    request: &SealRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    if request.confirm != CONFIRMATION_PHRASE {
        return Err(ApiError::bad_request(
            error_codes::CONFIRMATION_REQUIRED,
            format!("Type {CONFIRMATION_PHRASE} to confirm removing the file seal slot."),
        ));
    }

    let _guard = state.admin.lock_keystore().await;

    // The whole point of the two-step flow. `slots` alone would say "there is an
    // env slot"; `opened_with` says "this process came up on it", which is the
    // only version of that claim anybody has tested.
    if !state.runtime.seal().can_drop_file_slot() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::SEAL_UNAVAILABLE,
            format!(
                "This node did not start through the env slot, so removing the file slot \
                 could leave it unopenable. Set {} and restart first.",
                keystore::SEAL_KEY_ENV
            ),
        ));
    }

    let (mut keystore, _) = open_keystore(state).await?;
    keystore
        .remove_slot(SlotKind::File)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;
    keystore::remove_seal_key_file(state.admin.app_dir())
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    state.runtime.set_slots(keystore.slots());

    tracing::info!(
        "Removed the file seal slot from /admin; this node now opens only from the environment"
    );

    Ok(json!({
        "slots": keystore.slots().iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
}

/// `POST /api/admin/seal/passphrase` — add a slot only a human can open.
///
/// Added *alongside* the machine-supplied slots, never instead of them, which is
/// what keeps unattended restarts working. Its purpose is the case this design
/// would otherwise have no answer for: a node whose seal key is lost. Without a
/// passphrase slot, a lost `.seal-key` and an unset `KONTOR_SEAL_KEY` leave a
/// keystore nobody can ever open again.
///
/// # Errors
/// - `400 INVALID_ENVELOPE` when the sealed payload does not authenticate.
/// - `400 WEAK_PASSWORD` when the passphrase is too short.
/// - `409 SEAL_UNAVAILABLE` when there is no open keystore.
/// - `500` when the keystore cannot be written.
pub async fn add_passphrase_slot(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    let passphrase = sealed_passphrase(request, state)?;

    let _guard = state.admin.lock_keystore().await;
    let (mut keystore, unlock) = open_keystore(state).await?;

    // Off the executor: see the note on this module.
    let keystore = tokio::task::spawn_blocking(move || {
        keystore
            .add_slot(&unlock, &SealKey::passphrase(passphrase.as_str()))
            .map(|()| keystore)
    })
    .await
    .map_err(|e| ApiError::server_error(format!("sealing task failed: {e}")))?
    .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    state.runtime.set_slots(keystore.slots());

    tracing::info!("Added a passphrase seal slot from /admin");

    Ok(json!({
        "slots": keystore.slots().iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
}

/// `POST /api/admin/unseal` — open a sealed node with a passphrase.
///
/// This is the exit from [`Phase::Sealed`], and without it that phase is a dead
/// end: a node whose seal key went missing would serve `/admin` forever with
/// nothing an operator could do from it.
///
/// # Errors
/// - `400 INVALID_ENVELOPE` when the sealed payload does not authenticate.
/// - `409 SEAL_UNAVAILABLE` when the node is not sealed.
/// - `401 INVALID_PASSWORD` when the passphrase does not open it.
pub async fn unseal(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    if state.runtime.phase() != Phase::Sealed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::SEAL_UNAVAILABLE,
            "This node is not sealed.",
        ));
    }

    let passphrase = sealed_passphrase(request, state)?;

    let keystore = Keystore::load(state.admin.app_dir())
        .await
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                error_codes::SEAL_UNAVAILABLE,
                "This node has no keystore to unseal.",
            )
        })?;

    let key = SealKey::passphrase(passphrase.as_str());

    // Opened here, before the supervisor is asked to do anything, so a wrong
    // passphrase is an error the operator sees rather than a phase change that
    // fails somewhere they are not looking. Off the executor for the same reason
    // as the slot addition above: this is an Argon2 derivation.
    let attempt = {
        let keystore = keystore.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || keystore.unseal(&key))
            .await
            .map_err(|e| ApiError::server_error(format!("unsealing task failed: {e}")))?
    };
    attempt.map_err(|e| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            error_codes::INVALID_PASSWORD,
            "That passphrase does not open this node's keystore.",
        )
        .with_detail(format!("{e:#}"))
    })?;

    tracing::info!("Node unsealed from /admin with a passphrase");

    state.runtime.request(Activation::Open {
        keystore: Box::new(keystore),
        seal_key: key,
        // Not `Env` or `File`: nothing on this machine supplied it, so the node
        // must not go on to report that it could restart unattended.
        source: SealKeySource::Passphrase,
    });

    Ok(json!({ "unsealing": true }))
}

/// Open a sealed passphrase payload and check it is long enough to be one.
///
/// The length floor is applied here, on the plaintext, rather than anywhere the
/// passphrase could still be in a request body.
fn sealed_passphrase(
    request: &SealedRequest,
    state: &DownloadServerState,
) -> Result<Zeroizing<String>, ApiError> {
    let (_session, payload) = envelope::open_as::<PassphrasePayload>(request, state)?;
    let passphrase = Zeroizing::new(payload.passphrase);

    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(ApiError::bad_request(
            error_codes::WEAK_PASSWORD,
            format!(
                "A seal passphrase must be at least {MIN_PASSPHRASE_LEN} characters. It is \
                 not behind a login throttle: anyone holding the keystore file can try it \
                 offline as fast as their hardware allows."
            ),
        ));
    }

    Ok(passphrase)
}

/// Seal a reply to the browser that opened this envelope.
fn seal_reply<T: Serialize>(
    session: &EnvelopeSession,
    client_pubkey: &str,
    reply: &T,
) -> Result<Value, ApiError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(reply)
            .map_err(|e| ApiError::server_error(format!("encoding the sealed reply: {e}")))?,
    );

    session
        .seal_for_client(client_pubkey, &plaintext)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))
}

/// Read the keystore back off disk, along with the key this boot opened it with.
///
/// The *file* is re-read rather than held: the supervisor owns the copy it
/// activated from, and two independently mutated copies of one file is how a
/// slot silently disappears. Callers hold [`AdminState::lock_keystore`] across
/// this and the write that follows, which is what stops two requests from both
/// reading before either wrote.
///
/// The *key* is the opposite — taken from what this boot actually opened with
/// rather than resolved again from the environment. Re-resolving is wrong in
/// both directions and the failures are not hypothetical:
///
/// - A node unsealed from `/admin` with a passphrase has nothing on the machine
///   to resolve, so every reseal would answer "no open keystore" on a node whose
///   keystore is demonstrably open.
/// - An operator who pastes `KONTOR_SEAL_KEY` in *before* calling
///   `POST /seal/env-slot` — the natural order to try — would have that key
///   resolved, find no env slot to unwrap, and get a 500 for it.
///
/// The environment is still the fallback, for the window between the server
/// binding and the supervisor's first tick.
///
/// [`AdminState::lock_keystore`]: crate::server::admin::AdminState::lock_keystore
async fn open_keystore(state: &DownloadServerState) -> Result<(Keystore, SealKey), ApiError> {
    let unavailable = || {
        ApiError::new(
            StatusCode::CONFLICT,
            error_codes::SEAL_UNAVAILABLE,
            "This node has no open keystore, so there is nothing to reseal.",
        )
    };

    let app_dir = state.admin.app_dir();
    let keystore = Keystore::load(app_dir)
        .await
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?
        .ok_or_else(unavailable)?;

    let key = match state.runtime.seal_key() {
        Some(key) => key,
        None => {
            keystore::resolve_seal_key(app_dir, false)
                .map_err(|e| ApiError::server_error(format!("{e:#}")))?
                .ok_or_else(unavailable)?
                .0
        }
    };

    Ok((keystore, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::lifecycle::{NodeRuntime, SealStatus};
    use crate::app::restart::RestartHandle;
    use crate::app::tasks::downloadagreements::StorageBackend;
    use crate::crypto::BlsKeyPair;
    use crate::server::admin::credentials::AdminCredential;
    use crate::server::admin::envelope::testing::Client;
    use crate::server::admin::AdminState;
    use crate::testutils::{setup_in_memory_db, tempdir};

    const PASSPHRASE: &str = "a passphrase long enough to be accepted";

    /// A node with a sealed keystore on disk and a runtime that knows what
    /// opened it — the state every seal mutation is written against.
    async fn node_sealed_with(
        boot_key: &SealKey,
        source: SealKeySource,
    ) -> (DownloadServerState, tempfile::TempDir) {
        let dir = tempdir();
        let keypair = BlsKeyPair::generate().unwrap();
        let keystore =
            Keystore::provision(dir.path(), &keypair.secret_key_hex(), None, boot_key).unwrap();

        let runtime = NodeRuntime::for_tests(Some("NODE-seal"), None);
        runtime.opened(&keystore, boot_key, source);

        let state = DownloadServerState {
            db: setup_in_memory_db().await,
            storage_dir: dir.path().to_path_buf(),
            storage_backend: StorageBackend::local(),
            runtime: runtime.clone(),
            admin: AdminState::new(
                AdminCredential::Disabled,
                dir.path().to_path_buf(),
                RestartHandle::new(),
                runtime,
            ),
        };
        (state, dir)
    }

    /// Fetch an envelope and seal a payload against it, as the page does.
    /// Returns the client too, because half these endpoints answer sealed.
    fn sealed(state: &DownloadServerState, payload: &Value) -> (Client, SealedRequest) {
        let env = envelope::issue(state);
        let session_id = env["session_id"].as_str().unwrap();
        let client = Client::greet(env["node_pubkey"].as_str().unwrap(), session_id);
        let request = client.seal(session_id, &serde_json::to_vec(payload).unwrap());
        (client, request)
    }

    fn sealed_passphrase_request(
        state: &DownloadServerState,
        passphrase: &str,
    ) -> (Client, SealedRequest) {
        sealed(state, &json!({ "passphrase": passphrase }))
    }

    /// The key an env slot hands out is the one secret this API produces, and it
    /// must reach the browser without ever being a field in a loggable body.
    #[tokio::test]
    async fn the_env_slot_key_comes_back_sealed_and_nowhere_else() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (client, request) = sealed(&state, &json!({}));

        let body = add_env_slot(&request, &state).await.unwrap();

        // Nothing in the clear: the rendered body must not contain the key.
        let opened = client.open(&body["sealed"]);
        let reply: Value = serde_json::from_slice(&opened).unwrap();
        let key = reply["key"].as_str().unwrap();
        assert!(
            !body.to_string().contains(key),
            "the seal key must not appear outside the sealed reply"
        );
        assert_eq!(reply["env_var"], keystore::SEAL_KEY_ENV);

        // And it is the key that actually opens the new slot.
        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        let handed_out = SealKey::decode(SlotKind::Env, key).expect("valid base64");
        assert_eq!(body["fingerprint"], json!(handed_out.fingerprint()));
        reloaded.unseal(&handed_out).expect("the env slot opens it");
    }

    /// A browser that cannot produce a ciphertext this node opens will not be
    /// able to read the reply either. Finding that out before a slot is
    /// committed is the whole reason this endpoint takes an envelope at all.
    #[tokio::test]
    async fn an_env_slot_is_not_written_for_an_envelope_that_does_not_open() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (_, request) = sealed(&state, &json!({}));

        let tampered = SealedRequest {
            ciphertext: format!("ff{}", &request.ciphertext[2..]),
            ..request
        };
        let err = add_env_slot(&tampered, &state).await.unwrap_err();
        assert_eq!(err.code, error_codes::INVALID_ENVELOPE);

        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(reloaded.slots(), vec![SlotKind::File]);
    }

    /// The exit from [`Phase::Sealed`] must not be a dead end for hardening.
    /// Nothing on the machine can re-derive a passphrase, so a node that came up
    /// through one has to be resealed with the key it actually holds — not with
    /// whatever the environment happens to answer.
    #[tokio::test]
    async fn a_node_unsealed_by_passphrase_can_still_add_an_env_slot() {
        let passphrase = SealKey::passphrase(PASSPHRASE);
        let (state, dir) = node_sealed_with(&passphrase, SealKeySource::Passphrase).await;

        // No `.seal-key`, no `KONTOR_SEAL_KEY`: exactly the node that reached
        // `/admin` sealed and was opened by hand.
        std::fs::remove_file(dir.path().join(keystore::SEAL_KEY_FILENAME)).ok();

        let (client, request) = sealed(&state, &json!({}));
        let body = add_env_slot(&request, &state)
            .await
            .expect("the key this node was opened with must be enough to reseal it");
        assert_eq!(body["env_var"], keystore::SEAL_KEY_ENV);

        // And the slot really landed in the file, openable by the key handed out.
        let reply: Value = serde_json::from_slice(&client.open(&body["sealed"])).unwrap();
        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert!(reloaded.slots().contains(&SlotKind::Env));
        let handed_out =
            SealKey::decode(SlotKind::Env, reply["key"].as_str().unwrap()).expect("valid base64");
        reloaded.unseal(&handed_out).expect("the env slot opens it");
    }

    /// The natural order to try the hardening flow in is the wrong one: paste
    /// `KONTOR_SEAL_KEY` first, then ask for the slot. Resolving the key from
    /// the environment would find that variable, look for an env slot that does
    /// not exist yet, and answer 500 to an operator doing nothing wrong.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_seal_key_pasted_in_ahead_of_its_slot_does_not_break_the_flow() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (client, request) = sealed(&state, &json!({}));

        let stray = SealKey::generate(SlotKind::Env);
        std::env::set_var(keystore::SEAL_KEY_ENV, stray.encode().as_str());
        let body = add_env_slot(&request, &state).await;
        std::env::remove_var(keystore::SEAL_KEY_ENV);

        let body = body.expect("the boot key opens the keystore regardless of the environment");
        let reply: Value = serde_json::from_slice(&client.open(&body["sealed"])).unwrap();
        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert!(reloaded.slots().contains(&SlotKind::Env));

        // The slot belongs to the generated key, not to whatever was in the
        // environment — that one was never part of this keystore.
        let handed_out = SealKey::decode(SlotKind::Env, reply["key"].as_str().unwrap()).unwrap();
        reloaded.unseal(&handed_out).unwrap();
        assert!(reloaded.unseal(&stray).is_err());
    }

    /// Adding a slot changes which ways in exist and nothing else. In
    /// particular it must not read as "this boot came up through the env slot",
    /// which is what would let the file slot be dropped before the operator has
    /// proved the new one works.
    #[tokio::test]
    async fn adding_a_slot_does_not_change_which_one_this_boot_used() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, _dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (_, request) = sealed(&state, &json!({}));

        add_env_slot(&request, &state).await.unwrap();

        let seal = state.runtime.seal();
        assert!(seal.slots.contains(&SlotKind::Env));
        assert_eq!(seal.opened_with, Some(SlotKind::File));
        assert!(!seal.can_drop_file_slot());

        let refused = drop_file_slot(
            &SealRequest {
                confirm: CONFIRMATION_PHRASE.to_string(),
            },
            &state,
        )
        .await
        .expect_err("the file slot must survive until the env slot has booted the node");
        assert_eq!(refused.code, error_codes::SEAL_UNAVAILABLE);
    }

    /// The end of the hardening flow, on the one node it is allowed on: a boot
    /// that came up through the env slot.
    #[tokio::test]
    async fn the_file_slot_goes_once_the_node_has_booted_on_the_env_slot() {
        let env_key = SealKey::generate(SlotKind::Env);
        let (state, dir) = node_sealed_with(&env_key, SealKeySource::Env).await;

        // Provisioning wrote a file slot's worth of state; give the keystore
        // both slots and tell the runtime this boot used the env one.
        let mut keystore = Keystore::load(dir.path()).await.unwrap().unwrap();
        let file_key = SealKey::generate(SlotKind::File);
        keystore.add_slot(&env_key, &file_key).unwrap();
        state
            .runtime
            .opened(&keystore, &env_key, SealKeySource::Env);
        assert!(state.runtime.seal().can_drop_file_slot());

        let body = drop_file_slot(
            &SealRequest {
                confirm: CONFIRMATION_PHRASE.to_string(),
            },
            &state,
        )
        .await
        .unwrap();

        assert_eq!(body["slots"], json!(["env"]));
        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(reloaded.slots(), vec![SlotKind::Env]);
        assert!(reloaded.unseal(&file_key).is_err());
        // The key file goes with the slot; leaving it would be a key on the
        // volume that opens nothing, which is only ever confusing.
        assert!(!dir.path().join(keystore::SEAL_KEY_FILENAME).exists());
    }

    /// Destructive, so it needs the phrase — and without it nothing must change.
    #[tokio::test]
    async fn dropping_the_file_slot_needs_its_confirmation() {
        let env_key = SealKey::generate(SlotKind::Env);
        let (state, dir) = node_sealed_with(&env_key, SealKeySource::Env).await;

        let err = drop_file_slot(&SealRequest::default(), &state)
            .await
            .unwrap_err();
        assert_eq!(err.code, error_codes::CONFIRMATION_REQUIRED);
        assert!(Keystore::load(dir.path()).await.unwrap().is_some());
    }

    /// A passphrase slot is the answer to a lost seal key, so it has to be
    /// added alongside the machine slots and open the keystore afterwards.
    #[tokio::test]
    async fn a_passphrase_slot_is_added_beside_the_machine_slot() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (_, request) = sealed_passphrase_request(&state, PASSPHRASE);

        let body = add_passphrase_slot(&request, &state).await.unwrap();
        assert_eq!(body["slots"], json!(["file", "passphrase"]));

        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        reloaded
            .unseal(&SealKey::passphrase(PASSPHRASE))
            .expect("the passphrase opens it");
        // And the node can still come back from a restart on its own.
        assert!(keystore::slots_can_boot_unattended(&reloaded.slots()));
    }

    /// The floor is checked on the plaintext, after the envelope — so a short
    /// passphrase is refused by name rather than sealed away into a slot.
    #[tokio::test]
    async fn a_short_passphrase_is_refused_by_name() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        let (_, request) = sealed_passphrase_request(&state, "too short");

        let err = add_passphrase_slot(&request, &state).await.unwrap_err();
        assert_eq!(err.code, error_codes::WEAK_PASSWORD);
        assert!(err.message.contains(&MIN_PASSPHRASE_LEN.to_string()));

        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(reloaded.slots(), vec![SlotKind::File]);
    }

    /// A passphrase must never arrive in the clear. The endpoint takes only the
    /// four envelope fields, so a body carrying `passphrase` at the top level
    /// deserialises into an envelope that opens nothing.
    #[tokio::test]
    async fn a_bare_passphrase_body_is_not_a_request_this_endpoint_understands() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, _dir) = node_sealed_with(&file_key, SealKeySource::File).await;

        let bare: SealedRequest =
            serde_json::from_value(json!({ "passphrase": PASSPHRASE })).unwrap();
        assert!(bare.ciphertext.is_empty());

        let err = add_passphrase_slot(&bare, &state).await.unwrap_err();
        assert_eq!(err.code, error_codes::INVALID_ENVELOPE);
    }

    /// The exit from [`Phase::Sealed`], and the one endpoint where a wrong
    /// guess must not look like anything else.
    #[tokio::test]
    async fn a_sealed_node_opens_on_the_right_passphrase_and_not_another() {
        let passphrase = SealKey::passphrase(PASSPHRASE);
        let (state, _dir) = node_sealed_with(&passphrase, SealKeySource::Passphrase).await;
        state.runtime.enter(Phase::Sealed);

        let (_, wrong) = sealed_passphrase_request(&state, "an entirely different passphrase");
        let err = unseal(&wrong, &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, error_codes::INVALID_PASSWORD);
        assert_eq!(state.runtime.phase(), Phase::Sealed);

        let (_, right) = sealed_passphrase_request(&state, PASSPHRASE);
        let body = unseal(&right, &state).await.unwrap();
        assert_eq!(body["unsealing"], true);
    }

    /// Unsealing a node that is not sealed is a mistake worth naming rather
    /// than a passphrase check nobody asked for.
    #[tokio::test]
    async fn unsealing_a_running_node_is_refused_before_the_passphrase_is_read() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, _dir) = node_sealed_with(&file_key, SealKeySource::File).await;
        state.runtime.enter(Phase::Running);

        let (_, request) = sealed_passphrase_request(&state, PASSPHRASE);
        let err = unseal(&request, &state).await.unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, error_codes::SEAL_UNAVAILABLE);
    }

    /// Two seal mutations on one node must not lose a slot between them. Each
    /// loads, changes one thing and writes back, so without the lock the second
    /// read would predate the first write and the file would end up holding
    /// whichever change finished last.
    #[tokio::test]
    async fn concurrent_slot_changes_do_not_lose_one() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, dir) = node_sealed_with(&file_key, SealKeySource::File).await;

        // Two envelopes cannot be live at once — one slot, by design — so the
        // race being tested is the keystore rewrite, staged against a node whose
        // env slot is added while a passphrase slot is being added too.
        let (_, passphrase) = sealed_passphrase_request(&state, PASSPHRASE);
        add_passphrase_slot(&passphrase, &state).await.unwrap();
        let (_, env) = sealed(&state, &json!({}));
        add_env_slot(&env, &state).await.unwrap();

        let reloaded = Keystore::load(dir.path()).await.unwrap().unwrap();
        assert_eq!(
            reloaded.slots(),
            vec![SlotKind::File, SlotKind::Passphrase, SlotKind::Env],
            "every slot written must still be there"
        );
        assert_eq!(state.runtime.seal().slots, reloaded.slots());
    }

    fn seal_status(slots: Vec<SlotKind>, opened_with: Option<SlotKind>) -> SealStatus {
        SealStatus {
            slots,
            opened_with,
            fingerprint: Some("abc12345".to_string()),
            ..SealStatus::default()
        }
    }

    #[tokio::test]
    async fn status_reports_the_live_seal_without_the_key() {
        let file_key = SealKey::generate(SlotKind::File);
        let (state, _dir) = node_sealed_with(&file_key, SealKeySource::File).await;

        let value = status(&state);
        assert_eq!(value["slots"], json!(["file"]));
        assert_eq!(value["opened_with"], "file");
        assert_eq!(value["fingerprint"], json!(file_key.fingerprint()));
        assert_eq!(value["env_var"], keystore::SEAL_KEY_ENV);
        assert!(
            !value.to_string().contains(file_key.encode().as_str()),
            "the seal key must not be in a status response"
        );
    }

    #[test]
    fn status_offers_the_env_slot_only_while_there_is_none() {
        let seal = seal_status(vec![SlotKind::File], Some(SlotKind::File));
        let value = render(&seal);

        assert_eq!(value["can_add_env_slot"], true);
        assert_eq!(value["can_drop_file_slot"], false);
        assert_eq!(value["opened_with"], "file");
        assert_eq!(value["slots"], json!(["file"]));
    }

    #[test]
    fn status_offers_the_drop_only_after_booting_through_the_env_slot() {
        let via_file = render(&seal_status(
            vec![SlotKind::File, SlotKind::Env],
            Some(SlotKind::File),
        ));
        assert_eq!(via_file["can_add_env_slot"], false);
        assert_eq!(via_file["can_drop_file_slot"], false);

        let via_env = render(&seal_status(
            vec![SlotKind::File, SlotKind::Env],
            Some(SlotKind::Env),
        ));
        assert_eq!(via_env["can_drop_file_slot"], true);
    }

    /// Every offer needs the data key, so a node that cannot open its own
    /// keystore must be offered none of them. The page reveals the seal card in
    /// every phase but `uninitialized` and `sealed` — which includes `failed`,
    /// and the moment between a wizard provisioning a keystore and the
    /// supervisor opening it — so "there is a slot" must not read as "a slot
    /// can be changed".
    #[test]
    fn a_node_that_cannot_open_its_keystore_is_offered_nothing() {
        let value = render(&seal_status(vec![SlotKind::File, SlotKind::Env], None));

        assert_eq!(value["slots"], json!(["file", "env"]));
        assert_eq!(value["can_add_env_slot"], false);
        assert_eq!(value["can_drop_file_slot"], false);
        assert_eq!(value["can_add_passphrase_slot"], false);

        // And the same node with nothing recorded at all — a keystore that has
        // not been read yet — is equally inert.
        let nothing = render(&SealStatus::default());
        assert_eq!(nothing["can_add_env_slot"], false);
        assert_eq!(nothing["can_add_passphrase_slot"], false);
    }

    /// The one key kind with no fingerprint to publish. `GET /api/admin/seal`
    /// is not sealed, so four bytes of a hash of an operator's passphrase would
    /// be an offline confirmation oracle for anyone who saw the body.
    #[tokio::test]
    async fn a_node_opened_by_passphrase_publishes_no_fingerprint() {
        let passphrase = SealKey::passphrase(PASSPHRASE);
        let (state, _dir) = node_sealed_with(&passphrase, SealKeySource::Passphrase).await;

        let value = status(&state);

        assert_eq!(value["opened_with"], "passphrase");
        assert_eq!(value["fingerprint"], Value::Null);
        assert!(
            !value.to_string().contains(PASSPHRASE),
            "the passphrase must not be in a status response in any form"
        );
    }

    /// A passphrase slot needs the data key, so it can only be added while the
    /// node holds what opened the keystore. The page has to be told, because a
    /// sealed node is both the one that most wants a passphrase and the one
    /// place it cannot be added — the moment to do it is before the seal key
    /// goes missing.
    #[test]
    fn status_offers_a_passphrase_slot_only_on_an_open_node() {
        let open = render(&seal_status(vec![SlotKind::File], Some(SlotKind::File)));
        assert_eq!(open["can_add_passphrase_slot"], true);
        assert_eq!(open["has_passphrase_slot"], false);
        assert_eq!(open["min_passphrase_len"], MIN_PASSPHRASE_LEN);

        let sealed = render(&seal_status(vec![SlotKind::File], None));
        assert_eq!(sealed["can_add_passphrase_slot"], false);

        let with_one = render(&seal_status(
            vec![SlotKind::File, SlotKind::Passphrase],
            Some(SlotKind::File),
        ));
        assert_eq!(with_one["has_passphrase_slot"], true);
        // Still offered: `add_slot` replaces a slot of the same kind, so this
        // is also how a passphrase gets changed.
        assert_eq!(with_one["can_add_passphrase_slot"], true);
    }
}
