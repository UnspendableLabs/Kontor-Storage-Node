//! `/api/admin/seal/*` — inspect and change how this node's key is sealed.
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

use anyhow::Result;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::lifecycle::{Activation, Phase};
use crate::crypto::keystore::{self, Keystore, SealKey, SealKeySource, SlotKind};
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
    let seal = state.runtime.seal();
    json!({
        "slots": seal.slots.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "opened_with": seal.opened_with.map(|kind| kind.to_string()),
        "fingerprint": seal.fingerprint,
        "can_add_env_slot": !seal.slots.contains(&SlotKind::Env),
        "can_drop_file_slot": seal.can_drop_file_slot(),
        "env_var": keystore::SEAL_KEY_ENV,
    })
}

/// Request body for the seal mutations that need confirming.
#[derive(Debug, Default, Deserialize)]
pub struct SealRequest {
    #[serde(default)]
    pub confirm: String,
}

/// The phrase a destructive seal change has to carry, mirroring the reset.
pub const CONFIRMATION_PHRASE: &str = "DROP";

/// `POST /api/admin/seal/env-slot` — generate a key for `KONTOR_SEAL_KEY`.
///
/// The key is returned **once** and never stored anywhere this node can read it
/// back from. If the operator loses it before pasting it in, the fix is to call
/// this again: the previous env slot is simply replaced.
///
/// # Errors
/// - `409 SEAL_UNAVAILABLE` when there is no open keystore to add a slot to.
/// - `500` when the keystore cannot be written.
pub async fn add_env_slot(state: &DownloadServerState) -> Result<Value, ApiError> {
    let (mut keystore, unlock) = open_keystore(state).await?;

    let new = SealKey::generate(SlotKind::Env);
    keystore
        .add_slot(&unlock, &new)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    let mut seal = state.runtime.seal();
    seal.slots = keystore.slots();
    state.runtime.set_seal(seal);

    tracing::info!(
        fingerprint = %new.fingerprint(),
        "Added an env seal slot from /admin; the key was shown once and not retained"
    );

    Ok(json!({
        "env_var": keystore::SEAL_KEY_ENV,
        "key": new.encode().to_string(),
        "fingerprint": new.fingerprint(),
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

    let mut seal = state.runtime.seal();
    seal.slots = keystore.slots();
    state.runtime.set_seal(seal);

    tracing::info!(
        "Removed the file seal slot from /admin; this node now opens only from the environment"
    );

    Ok(json!({
        "slots": keystore.slots().iter().map(ToString::to_string).collect::<Vec<_>>(),
    }))
}

/// Request body for the passphrase endpoints.
#[derive(Debug, Default, Deserialize)]
pub struct PassphraseRequest {
    #[serde(default)]
    pub passphrase: String,
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
/// - `400 WEAK_PASSWORD` when the passphrase is too short.
/// - `409 SEAL_UNAVAILABLE` when there is no open keystore.
/// - `500` when the keystore cannot be written.
pub async fn add_passphrase_slot(
    request: &PassphraseRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    if request.passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(ApiError::bad_request(
            error_codes::WEAK_PASSWORD,
            format!(
                "A seal passphrase must be at least {MIN_PASSPHRASE_LEN} characters. It is \
                 not behind a login throttle: anyone holding the keystore file can try it \
                 offline as fast as their hardware allows."
            ),
        ));
    }

    let (mut keystore, unlock) = open_keystore(state).await?;
    keystore
        .add_slot(&unlock, &SealKey::passphrase(request.passphrase.clone()))
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?;

    let mut seal = state.runtime.seal();
    seal.slots = keystore.slots();
    state.runtime.set_seal(seal);

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
/// - `409 SEAL_UNAVAILABLE` when the node is not sealed.
/// - `401 INVALID_PASSWORD` when the passphrase does not open it.
pub async fn unseal(
    request: &PassphraseRequest,
    state: &DownloadServerState,
) -> Result<Value, ApiError> {
    if state.runtime.phase() != Phase::Sealed {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            error_codes::SEAL_UNAVAILABLE,
            "This node is not sealed.",
        ));
    }

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

    let key = SealKey::passphrase(request.passphrase.clone());

    // Opened here, before the supervisor is asked to do anything, so a wrong
    // passphrase is an error the operator sees rather than a phase change that
    // fails somewhere they are not looking.
    keystore.unseal(&key).map_err(|e| {
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

/// Read the keystore back off disk, along with the key this boot opened it with.
///
/// Re-read rather than held: the supervisor owns the copy it activated from, and
/// two independently mutated copies of one file is how a slot silently
/// disappears.
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

    let (key, _) = keystore::resolve_seal_key(app_dir, false)
        .map_err(|e| ApiError::server_error(format!("{e:#}")))?
        .ok_or_else(unavailable)?;

    Ok((keystore, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::app::lifecycle::SealStatus;

    fn seal_status(slots: Vec<SlotKind>, opened_with: Option<SlotKind>) -> SealStatus {
        SealStatus {
            slots,
            opened_with,
            fingerprint: Some("abc12345".to_string()),
            ..SealStatus::default()
        }
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

    /// The rendering half of [`status`], without needing a whole server state.
    fn render(seal: &SealStatus) -> Value {
        json!({
            "slots": seal.slots.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "opened_with": seal.opened_with.map(|kind| kind.to_string()),
            "fingerprint": seal.fingerprint,
            "can_add_env_slot": !seal.slots.contains(&SlotKind::Env),
            "can_drop_file_slot": seal.can_drop_file_slot(),
            "env_var": keystore::SEAL_KEY_ENV,
        })
    }
}
