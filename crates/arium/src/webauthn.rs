//! WebAuthn / passkeys: registration + authentication ceremonies and
//! credential storage.
//!
//! This module is the server half of the passkey feature. It wraps
//! [`webauthn_rs`] and persists credentials in the `webauthn_credentials`
//! table (migration `0009`). The browser half — calling
//! `navigator.credentials.create()/.get()` — lives in the framework adapters.
//!
//! It deliberately mirrors the TOTP MFA code in [`crate::auth`]: small,
//! free-standing `async fn`s that take `&Pool` and a few scalars. The one new
//! wrinkle is that each ceremony is two round-trips, so the in-progress state
//! (`PasskeyRegistration` / `PasskeyAuthentication` / `DiscoverableAuthentication`)
//! is serde-serialized and stashed in the session between calls — exactly the
//! pattern [`crate::oauth`] uses for the OAuth CSRF `state`.
//!
//! We never store a private key: the credential's private half never leaves
//! the user's authenticator. The stored `Passkey` blob holds the public key,
//! the signature counter, and transports.

use crate::pool::Pool;
use webauthn_rs::prelude::*;

// Re-export the ceremony types that framework adapters must name when they
// bridge JSON from the browser/session into these functions, so they can refer
// to them as `arium::webauthn::*` without depending on `webauthn-rs` directly.
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
    Webauthn,
};

/// One enrolled passkey, as surfaced to the account-settings UI.
pub struct PasskeyRecord {
    /// base64url of the credential id — the handle used to revoke it.
    pub credential_id: String,
    /// User-supplied label, if any.
    pub nickname: Option<String>,
    /// Unix seconds the credential was registered.
    pub created_at: i64,
    /// Unix seconds it was last used to authenticate, if ever.
    pub last_used_at: Option<i64>,
}

/// Build the shared [`Webauthn`] instance from the relying-party config.
/// Called once from [`crate::install`]; the result is wrapped in an `Arc`
/// extension that server fns extract.
pub fn build_webauthn(rp_id: &str, rp_origin: &url::Url, rp_name: &str) -> anyhow::Result<Webauthn> {
    let builder = WebauthnBuilder::new(rp_id, rp_origin)
        .map_err(|e| anyhow::anyhow!("webauthn builder init failed: {e}"))?
        .rp_name(rp_name);
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("webauthn build failed: {e}"))
}

/// Fetch (minting + persisting if absent) the stable per-user WebAuthn handle.
/// This `Uuid` is the credential's user id; discoverable login resolves it back
/// to a local account, so it must be stable across a user's passkeys.
pub async fn ensure_user_handle(db: &Pool, user_id: i64) -> anyhow::Result<Uuid> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT webauthn_user_handle FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    if let Some((Some(handle),)) = row
        && let Ok(uuid) = Uuid::parse_str(&handle)
    {
        return Ok(uuid);
    }
    let fresh = Uuid::new_v4();
    sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(fresh.to_string())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(fresh)
}

/// Begin enrollment: returns the creation challenge to hand to the browser and
/// the in-progress state to stash in the session. Existing credentials are
/// passed as `exclude_credentials` so the same authenticator can't double-enrol.
pub async fn start_registration(
    db: &Pool,
    wa: &Webauthn,
    user_id: i64,
    user_name: &str,
    display_name: &str,
) -> anyhow::Result<(CreationChallengeResponse, PasskeyRegistration)> {
    let handle = ensure_user_handle(db, user_id).await?;
    let existing = load_user_passkeys(db, user_id).await?;
    let exclude: Vec<CredentialID> = existing.iter().map(|p| p.cred_id().clone()).collect();
    let exclude = if exclude.is_empty() {
        None
    } else {
        Some(exclude)
    };
    wa.start_passkey_registration(handle, user_name, display_name, exclude)
        .map_err(|e| anyhow::anyhow!("start_passkey_registration failed: {e}"))
}

/// Complete enrollment: verify the attestation against the stashed state and
/// persist the resulting [`Passkey`].
pub async fn finish_registration(
    db: &Pool,
    wa: &Webauthn,
    user_id: i64,
    reg: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
    nickname: Option<&str>,
) -> anyhow::Result<()> {
    let passkey = wa
        .finish_passkey_registration(reg, state)
        .map_err(|e| anyhow::anyhow!("finish_passkey_registration failed: {e}"))?;
    let credential_id = base64url(passkey.cred_id().as_ref());
    let passkey_json = serde_json::to_string(&passkey)?;
    sqlx::query(
        "INSERT INTO webauthn_credentials \
         (user_id, credential_id, passkey_json, nickname, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(&credential_id)
    .bind(&passkey_json)
    .bind(nickname)
    .bind(unix_now())
    .execute(db)
    .await?;
    Ok(())
}

/// Begin a second-factor (or re-auth) ceremony for a *known* user: challenge is
/// scoped to that user's enrolled credentials.
pub async fn start_authentication(
    db: &Pool,
    wa: &Webauthn,
    user_id: i64,
) -> anyhow::Result<(RequestChallengeResponse, PasskeyAuthentication)> {
    let passkeys = load_user_passkeys(db, user_id).await?;
    if passkeys.is_empty() {
        anyhow::bail!("user has no enrolled passkeys");
    }
    wa.start_passkey_authentication(&passkeys)
        .map_err(|e| anyhow::anyhow!("start_passkey_authentication failed: {e}"))
}

/// Complete a known-user ceremony, bumping the stored signature counter.
pub async fn finish_authentication(
    db: &Pool,
    wa: &Webauthn,
    user_id: i64,
    cred: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> anyhow::Result<()> {
    let result = wa
        .finish_passkey_authentication(cred, state)
        .map_err(|e| anyhow::anyhow!("finish_passkey_authentication failed: {e}"))?;
    persist_auth_result(db, user_id, &result).await
}

/// Begin a *discoverable* (usernameless / passwordless) ceremony. No user is
/// known yet — the authenticator picks the credential and the assertion carries
/// the user handle.
pub fn start_discoverable(
    wa: &Webauthn,
) -> anyhow::Result<(RequestChallengeResponse, DiscoverableAuthentication)> {
    wa.start_discoverable_authentication()
        .map_err(|e| anyhow::anyhow!("start_discoverable_authentication failed: {e}"))
}

/// Complete a discoverable ceremony: identify the user from the assertion,
/// verify against that user's keys, and return the resolved local user id.
pub async fn finish_discoverable(
    db: &Pool,
    wa: &Webauthn,
    cred: &PublicKeyCredential,
    state: DiscoverableAuthentication,
) -> anyhow::Result<i64> {
    // The assertion names a user handle + credential id before we verify it.
    let (user_handle, _cred_id) = wa
        .identify_discoverable_authentication(cred)
        .map_err(|e| anyhow::anyhow!("identify_discoverable_authentication failed: {e}"))?;

    // Resolve the handle to a live local user. A handle with no user (e.g. the
    // account was deleted) is an auth failure, not a server error.
    let user_id = user_id_by_handle(db, &user_handle)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no account for that passkey"))?;

    let passkeys = load_user_passkeys(db, user_id).await?;
    let keys: Vec<DiscoverableKey> = passkeys.iter().map(DiscoverableKey::from).collect();
    let result = wa
        .finish_discoverable_authentication(cred, state, &keys)
        .map_err(|e| anyhow::anyhow!("finish_discoverable_authentication failed: {e}"))?;
    persist_auth_result(db, user_id, &result).await?;
    Ok(user_id)
}

/// List a user's enrolled passkeys for the account-settings UI.
pub async fn list_credentials(db: &Pool, user_id: i64) -> anyhow::Result<Vec<PasskeyRecord>> {
    let rows: Vec<(String, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT credential_id, nickname, created_at, last_used_at \
         FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(credential_id, nickname, created_at, last_used_at)| PasskeyRecord {
                credential_id,
                nickname,
                created_at,
                last_used_at,
            },
        )
        .collect())
}

/// Remove one passkey by its base64url credential id. Returns whether a row
/// was deleted (so the caller can 404 a bogus id).
pub async fn revoke_credential(
    db: &Pool,
    user_id: i64,
    credential_id: &str,
) -> anyhow::Result<bool> {
    let res = sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2")
        .bind(user_id)
        .bind(credential_id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Whether the user has at least one passkey enrolled (drives the login branch).
pub async fn user_has_passkey(db: &Pool, user_id: i64) -> anyhow::Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(db)
            .await?;
    Ok(count > 0)
}

// ---- internals ----

async fn load_user_passkeys(db: &Pool, user_id: i64) -> anyhow::Result<Vec<Passkey>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT passkey_json FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (json,) in rows {
        out.push(serde_json::from_str::<Passkey>(&json)?);
    }
    Ok(out)
}

async fn user_id_by_handle(db: &Pool, handle: &Uuid) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM users WHERE webauthn_user_handle = $1")
            .bind(handle.to_string())
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(id,)| id))
}

/// Update the stored counter for the credential just used, and stamp
/// `last_used_at`. A counter that went *backwards* signals a cloned
/// authenticator — reject it rather than silently accepting.
async fn persist_auth_result(
    db: &Pool,
    user_id: i64,
    result: &AuthenticationResult,
) -> anyhow::Result<()> {
    let credential_id = base64url(result.cred_id().as_ref());

    if result.needs_update() {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT passkey_json FROM webauthn_credentials \
             WHERE user_id = $1 AND credential_id = $2",
        )
        .bind(user_id)
        .bind(&credential_id)
        .fetch_optional(db)
        .await?;
        if let Some((json,)) = row {
            let mut passkey: Passkey = serde_json::from_str(&json)?;
            match passkey.update_credential(result) {
                Some(true) => {
                    let updated = serde_json::to_string(&passkey)?;
                    sqlx::query(
                        "UPDATE webauthn_credentials SET passkey_json = $1 \
                         WHERE user_id = $2 AND credential_id = $3",
                    )
                    .bind(&updated)
                    .bind(user_id)
                    .bind(&credential_id)
                    .execute(db)
                    .await?;
                }
                Some(false) => anyhow::bail!(
                    "authenticator signature counter went backwards — possible cloned credential"
                ),
                None => {}
            }
        }
    }

    sqlx::query("UPDATE webauthn_credentials SET last_used_at = $1 WHERE user_id = $2 AND credential_id = $3")
        .bind(unix_now())
        .bind(user_id)
        .bind(&credential_id)
        .execute(db)
        .await?;
    Ok(())
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
