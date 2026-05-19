//! The code here is pulled from the `axum-session-auth` crate examples, requiring little to no
//! modification to work with dioxus fullstack.

use async_trait::async_trait;
use axum_session_auth::*;
use axum_session_sqlx::SessionSqlitePool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::collections::HashSet;

pub(crate) type Session = axum_session_auth::AuthSession<User, i64, SessionSqlitePool, SqlitePool>;
pub(crate) type AuthLayer =
    axum_session_auth::AuthSessionLayer<User, i64, SessionSqlitePool, SqlitePool>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
    pub permissions: HashSet<String>,
}

#[derive(sqlx::FromRow, Clone)]
pub(crate) struct SqlPermissionTokens {
    pub token: String,
}

#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
        let db = pool.unwrap();

        #[derive(sqlx::FromRow, Clone)]
        struct SqlUser {
            id: i32,
            anonymous: bool,
            username: String,
            name: Option<String>,
            email: Option<String>,
            avatar_url: Option<String>,
            html_url: Option<String>,
        }

        let sqluser = sqlx::query_as::<_, SqlUser>(
            "SELECT id, anonymous, username, name, email, avatar_url, html_url \
             FROM users WHERE id = $1",
        )
        .bind(userid)
        .fetch_one(db)
        .await
        .unwrap();

        let sql_user_perms = sqlx::query_as::<_, SqlPermissionTokens>(
            "SELECT token FROM user_permissions WHERE user_id = $1;",
        )
        .bind(userid)
        .fetch_all(db)
        .await
        .unwrap();

        Ok(User {
            id: sqluser.id,
            anonymous: sqluser.anonymous,
            username: sqluser.username,
            name: sqluser.name,
            email: sqluser.email,
            avatar_url: sqluser.avatar_url,
            html_url: sqluser.html_url,
            permissions: sql_user_perms.into_iter().map(|x| x.token).collect(),
        })
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

#[async_trait]
impl HasPermission<SqlitePool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&SqlitePool>) -> bool {
        self.permissions.contains(perm)
    }
}

#[derive(Clone)]
pub(crate) struct OAuthClients {
    pub db: SqlitePool,
    pub http: reqwest::Client,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_url: String,
}

impl OAuthClients {
    /// Build `OAuthClients` from env vars.
    ///
    /// Returns `Ok(Some(_))` when GitHub credentials are configured (both
    /// `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` set and non-empty), or
    /// `Ok(None)` when they're absent — the caller should then skip
    /// registering the OAuth routes and the UI should hide the provider
    /// button. Errors are reserved for genuine misconfiguration (e.g. failure
    /// to build the HTTP client).
    pub fn from_env(db: SqlitePool) -> anyhow::Result<Option<Self>> {
        let id = std::env::var("GITHUB_CLIENT_ID").ok().filter(|s| !s.is_empty());
        let secret = std::env::var("GITHUB_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty());

        let (github_client_id, github_client_secret) = match (id, secret) {
            (Some(i), Some(s)) => (i, s),
            (None, None) => return Ok(None),
            _ => {
                eprintln!(
                    "[startup] WARN: partial GitHub OAuth config — both \
                     GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required. \
                     Disabling GitHub sign-in."
                );
                return Ok(None);
            }
        };

        let github_redirect_url = std::env::var("GITHUB_REDIRECT_URL")
            .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

        // Disable automatic redirect following per oauth2 crate guidance (SSRF mitigation).
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Some(Self {
            db,
            http,
            github_client_id,
            github_client_secret,
            github_redirect_url,
        }))
    }
}

/// The subset of GitHub's `/user` response we persist locally.
pub(crate) struct GithubProfile<'a> {
    pub id: u64,
    pub login: &'a str,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub html_url: Option<&'a str>,
}

/// Find-or-create-or-link a local user row for the given GitHub identity.
///
/// Three branches, tried in order:
///
/// 1. **Repeat OAuth login** — `oauth_accounts` already has a row for this
///    GitHub id. Refresh the cached GitHub profile fields and return the
///    existing local user id.
/// 2. **First GitHub login, but a local account already exists with the same
///    email** — link by inserting only an `oauth_accounts` row pointing at
///    that user; refresh display fields (name/avatar/html_url) but preserve
///    `username`, `email`, and `password_hash` so the account's password
///    sign-in keeps working unchanged.
/// 3. **Brand-new user** — insert a new `users` row, link via
///    `oauth_accounts`, and seed default permissions.
///
/// GitHub's `/user` only returns `email` when the user has made it public,
/// so the link branch is best-effort. Linking is safe because the email on
/// `GithubProfile` came from an authenticated GitHub session — i.e. the
/// caller already controls that mailbox.
pub(crate) async fn upsert_github_user(
    db: &SqlitePool,
    profile: GithubProfile<'_>,
) -> anyhow::Result<i64> {
    let github_id_str = profile.id.to_string();

    // 1) Already linked → refresh + return.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = ?",
    )
    .bind(&github_id_str)
    .fetch_optional(db)
    .await?;

    if let Some((user_id,)) = existing {
        sqlx::query(
            "UPDATE users SET username = ?, name = ?, email = ?, avatar_url = ?, html_url = ? \
             WHERE id = ?",
        )
        .bind(profile.login)
        .bind(profile.name)
        .bind(profile.email)
        .bind(profile.avatar_url)
        .bind(profile.html_url)
        .bind(user_id)
        .execute(db)
        .await?;
        return Ok(user_id);
    }

    // 2) Email matches an existing local account → link rather than duplicate.
    if let Some(email) = profile.email {
        let matched: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1",
        )
        .bind(email)
        .fetch_optional(db)
        .await?;

        if let Some((user_id,)) = matched {
            sqlx::query(
                "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) \
                 VALUES ('github', ?, ?)",
            )
            .bind(&github_id_str)
            .bind(user_id)
            .execute(db)
            .await?;

            sqlx::query(
                "UPDATE users SET name = ?, avatar_url = ?, html_url = ? WHERE id = ?",
            )
            .bind(profile.name)
            .bind(profile.avatar_url)
            .bind(profile.html_url)
            .bind(user_id)
            .execute(db)
            .await?;

            return Ok(user_id);
        }
    }

    // 3) Brand-new user. GitHub already verifies the address, so we mark
    //    `email_verified_at` now to skip the verification email flow.
    let (user_id,): (i64,) = sqlx::query_as(
        "INSERT INTO users (anonymous, username, name, email, avatar_url, html_url, email_verified_at) \
         VALUES (false, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(profile.login)
    .bind(profile.name)
    .bind(profile.email)
    .bind(profile.avatar_url)
    .bind(profile.html_url)
    .bind(unix_now())
    .fetch_one(db)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_accounts (provider, provider_user_id, user_id) VALUES ('github', ?, ?)",
    )
    .bind(&github_id_str)
    .bind(user_id)
    .execute(db)
    .await?;

    seed_default_permissions(db, user_id).await?;

    Ok(user_id)
}

/// Grant the baseline permissions every newly-created account starts with.
/// Phase 3's `create_password_user` should also call this.
pub(crate) async fn seed_default_permissions(
    db: &SqlitePool,
    user_id: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO user_permissions (user_id, token) VALUES (?, 'Category::View')",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Create a new email/password account.
///
/// Returns the new user's id on success. The error is a user-facing message
/// (server fn can surface it verbatim) — we deliberately avoid distinguishing
/// "no such user" from "wrong password" anywhere to prevent enumeration.
pub(crate) async fn create_password_user(
    db: &SqlitePool,
    email: &str,
    password: &str,
) -> anyhow::Result<i64> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        anyhow::bail!("Please enter a valid email address.");
    }
    if password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string();

    let username = email.split('@').next().unwrap_or(email);

    let inserted: Result<(i64,), sqlx::Error> = sqlx::query_as(
        "INSERT INTO users (anonymous, username, email, password_hash) \
         VALUES (false, ?, ?, ?) RETURNING id",
    )
    .bind(username)
    .bind(email)
    .bind(&hash)
    .fetch_one(db)
    .await;

    let (user_id,) = match inserted {
        Ok(row) => row,
        Err(sqlx::Error::Database(dberr)) if dberr.is_unique_violation() => {
            anyhow::bail!("An account with that email already exists.");
        }
        Err(e) => return Err(e.into()),
    };

    seed_default_permissions(db, user_id).await?;
    Ok(user_id)
}

/// Issue a one-hour password reset token for the account with the given email.
///
/// Returns `Some(token)` when the account exists and has a password set.
/// Returns `None` when no such account exists — the server fn deliberately
/// surfaces the same "we sent it if the address was valid" response in both
/// cases to avoid revealing which emails are registered.
pub(crate) async fn request_password_reset(
    db: &SqlitePool,
    email: &str,
) -> anyhow::Result<Option<String>> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    let user: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER(?) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = user else {
        return Ok(None);
    };

    // 16 random bytes = 128 bits of entropy, plenty for short-lived
    // single-use tokens. Hex-encoded that's 32 chars, which keeps the
    // resulting reset/verify URL under 76 chars so the plain-text email body
    // stays in 7bit transfer encoding (clean URLs in raw `.eml` views).
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now() + 3600;

    sqlx::query(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at)
    .execute(db)
    .await?;

    Ok(Some(token))
}

/// Consume a reset token: validate, hash the new password, set it, and delete
/// all outstanding tokens for the same user (so a leaked older token can't be
/// re-used after a successful reset).
pub(crate) async fn consume_password_reset(
    db: &SqlitePool,
    token: &str,
    new_password: &str,
) -> anyhow::Result<()> {
    if new_password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters.");
    }

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM password_reset_tokens WHERE token = ? AND expires_at > ? LIMIT 1",
    )
    .bind(token)
    .bind(unix_now())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = row else {
        anyhow::bail!("This reset link has expired or already been used.");
    };

    let hash = hash_password(new_password)?;

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(())
}

fn hash_password(plaintext: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Result of a password verification attempt.
///
/// The UI distinguishes `Unverified` so it can offer "Resend verification
/// email"; `Invalid` collapses the "no such account" and "wrong password"
/// cases into one to avoid user enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    Verified(i64),
    Unverified,
    Invalid,
}

/// Verify an email/password pair and the account's email-verified status.
pub(crate) async fn verify_password_user(
    db: &SqlitePool,
    email: &str,
    password: &str,
) -> anyhow::Result<VerifyOutcome> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let row: Option<(i64, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, password_hash, email_verified_at FROM users \
         WHERE LOWER(email) = LOWER(?) AND password_hash IS NOT NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;

    let Some((user_id, stored_hash, verified_at)) = row else {
        return Ok(VerifyOutcome::Invalid);
    };

    let Ok(parsed) = PasswordHash::new(&stored_hash) else {
        return Ok(VerifyOutcome::Invalid);
    };

    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_err()
    {
        return Ok(VerifyOutcome::Invalid);
    }

    if verified_at.is_none() {
        return Ok(VerifyOutcome::Unverified);
    }

    Ok(VerifyOutcome::Verified(user_id))
}

/// Issue a 24-hour email verification token for the given user.
pub(crate) async fn issue_verification_token(
    db: &SqlitePool,
    user_id: i64,
) -> anyhow::Result<String> {
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    // 16 random bytes = 128 bits of entropy, plenty for short-lived
    // single-use tokens. Hex-encoded that's 32 chars, which keeps the
    // resulting reset/verify URL under 76 chars so the plain-text email body
    // stays in 7bit transfer encoding (clean URLs in raw `.eml` views).
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let expires_at = unix_now() + 24 * 3600;

    sqlx::query(
        "INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at)
    .execute(db)
    .await?;

    Ok(token)
}

/// Consume an email verification token: mark the user verified, delete all
/// outstanding tokens for them, and return the user id. Returns `None` when
/// the token is unknown or expired.
pub(crate) async fn consume_verification_token(
    db: &SqlitePool,
    token: &str,
) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM email_verification_tokens WHERE token = ? AND expires_at > ? LIMIT 1",
    )
    .bind(token)
    .bind(unix_now())
    .fetch_optional(db)
    .await?;

    let Some((user_id,)) = row else {
        return Ok(None);
    };

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET email_verified_at = ? WHERE id = ?")
        .bind(unix_now())
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_verification_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Some(user_id))
}

// =============== TOTP MFA ==================

const MFA_ISSUER: &str = "dx-auth example";
const RECOVERY_CODE_COUNT: usize = 10;

/// Result of `setup_mfa_secret`: secret bytes (so the user can manually
/// type them if their scanner is broken), a data-URL-ready PNG QR code,
/// and the freshly-minted plaintext recovery codes (shown ONCE — only the
/// hashes hit the DB).
pub(crate) struct MfaSetupInfo {
    pub secret_base32: String,
    pub qr_png_base64: String,
    pub recovery_codes: Vec<String>,
}

/// High-level status of MFA on a single account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MfaStatus {
    /// No secret stored.
    Disabled,
    /// Secret stored but the user hasn't confirmed enrollment yet.
    Pending,
    /// Secret stored AND `mfa_enabled_at` set.
    Enabled,
}

/// Start MFA enrollment: generate a fresh secret + 10 recovery codes,
/// persist the pending secret on the user (mfa_enabled_at stays NULL until
/// they confirm a TOTP), and store Argon2 hashes of the recovery codes.
/// Re-running on a still-pending or enabled account wipes the old data.
pub(crate) async fn setup_mfa_secret(
    db: &SqlitePool,
    user_id: i64,
    account_label: &str,
) -> anyhow::Result<MfaSetupInfo> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret = Secret::generate_secret();
    let secret_base32 = match &secret {
        Secret::Encoded(s) => s.clone(),
        Secret::Raw(_) => secret.to_encoded().to_string(),
    };

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes()?,
        Some(MFA_ISSUER.to_string()),
        account_label.to_string(),
    )?;
    let qr_png_base64 = totp
        .get_qr_base64()
        .map_err(|e| anyhow::anyhow!("QR generation failed: {e}"))?;

    let mut rng = OsRng;
    let mut recovery_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut recovery_hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_recovery_code(&mut rng);
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(code.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hashing recovery code failed: {e}"))?
            .to_string();
        recovery_codes.push(code);
        recovery_hashes.push(hash);
    }

    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET mfa_secret = ?, mfa_enabled_at = NULL WHERE id = ?")
        .bind(&secret_base32)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for hash in &recovery_hashes {
        sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)")
            .bind(user_id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    Ok(MfaSetupInfo {
        secret_base32,
        qr_png_base64,
        recovery_codes,
    })
}

/// Confirm enrollment by validating a current TOTP from the pending secret.
/// Returns `true` when the code matched and `mfa_enabled_at` is now set.
pub(crate) async fn enable_mfa(
    db: &SqlitePool,
    user_id: i64,
    totp_code: &str,
) -> anyhow::Result<bool> {
    let Some(secret) = load_mfa_secret(db, user_id).await? else {
        return Ok(false);
    };
    if !check_totp(&secret, totp_code) {
        return Ok(false);
    }
    sqlx::query("UPDATE users SET mfa_enabled_at = ? WHERE id = ?")
        .bind(unix_now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(true)
}

/// Login-time second-factor check. Accepts a 6-digit TOTP code or one of
/// the user's unused recovery codes (marked used on success).
pub(crate) async fn verify_mfa_challenge(
    db: &SqlitePool,
    user_id: i64,
    code: &str,
) -> anyhow::Result<bool> {
    let code = code.trim();

    if let Some(secret) = load_mfa_secret(db, user_id).await? {
        if check_totp(&secret, code) {
            return Ok(true);
        }
    }

    consume_recovery_code(db, user_id, code).await
}

/// Fully turn off MFA: clear the secret, the enabled timestamp, and any
/// recovery codes.
pub(crate) async fn disable_mfa(db: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET mfa_secret = NULL, mfa_enabled_at = NULL WHERE id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Returns true iff the user has fully completed enrollment.
pub(crate) async fn user_has_mfa(db: &SqlitePool, user_id: i64) -> anyhow::Result<bool> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT mfa_enabled_at FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(t,)| t).is_some())
}

/// Used by the /account/mfa page to decide which actions to render.
pub(crate) async fn mfa_status(db: &SqlitePool, user_id: i64) -> anyhow::Result<MfaStatus> {
    let row: Option<(Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT mfa_secret, mfa_enabled_at FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(match row {
        Some((Some(_), Some(_))) => MfaStatus::Enabled,
        Some((Some(_), None)) => MfaStatus::Pending,
        _ => MfaStatus::Disabled,
    })
}

async fn load_mfa_secret(db: &SqlitePool, user_id: i64) -> anyhow::Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT mfa_secret FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(s,)| s))
}

fn check_totp(secret_base32: &str, code: &str) -> bool {
    use totp_rs::{Algorithm, Secret, TOTP};
    let Ok(bytes) = Secret::Encoded(secret_base32.to_string()).to_bytes() else {
        return false;
    };
    let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "".to_string()) else {
        return false;
    };
    totp.check_current(code).unwrap_or(false)
}

async fn consume_recovery_code(
    db: &SqlitePool,
    user_id: i64,
    candidate: &str,
) -> anyhow::Result<bool> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT code_hash FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    for (hash,) in rows {
        if let Ok(parsed) = PasswordHash::new(&hash) {
            if Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok()
            {
                sqlx::query(
                    "UPDATE mfa_recovery_codes SET used_at = ? \
                     WHERE user_id = ? AND code_hash = ?",
                )
                .bind(unix_now())
                .bind(user_id)
                .bind(&hash)
                .execute(db)
                .await?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn generate_recovery_code<R: argon2::password_hash::rand_core::RngCore>(rng: &mut R) -> String {
    // Crockford-style alphabet (no ambiguous chars). 10 chars × ~5 bits ≈ 50
    // bits per code — plenty for one-time backups.
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 10];
    rng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Look up a still-unverified password account by email. Used by the
/// "resend verification email" endpoint.
pub(crate) async fn find_unverified_user_id(
    db: &SqlitePool,
    email: &str,
) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM users \
         WHERE LOWER(email) = LOWER(?) \
           AND password_hash IS NOT NULL \
           AND email_verified_at IS NULL \
         LIMIT 1",
    )
    .bind(email.trim())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id,)| id))
}
