//! Types that cross the client/server boundary. Kept feature-flag-free so
//! they compile on both targets without bringing in any server-only deps.

use serde::{Deserialize, Serialize};

/// Result of a sign-in or sign-up attempt.
///
/// `EmailUnverified` and `MfaRequired` are *not* errors: they're successful
/// auth states that need an additional step before the user is fully signed
/// in (open the verification email; submit a TOTP code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginOutcome {
    LoggedIn,
    EmailUnverified,
    MfaRequired,
}

/// Third-party identity providers the server knows how to handle. Each
/// entry returned by the `available_providers` server fn gets mapped to a
/// `LoginProvider` button on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderId {
    Github,
}

/// Profile fields safe to expose to the client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserProfile {
    pub is_authenticated: bool,
    pub username: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub html_url: Option<String>,
}

/// Setup payload returned to the client when starting MFA enrollment.
/// `recovery_codes` is the only time these appear in plaintext anywhere —
/// the server only persists Argon2 hashes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MfaSetupView {
    pub secret_base32: String,
    pub qr_png_base64: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MfaStatusView {
    #[default]
    Disabled,
    /// Secret stored but the user hasn't confirmed enrollment with a TOTP yet.
    Pending,
    Enabled,
}
