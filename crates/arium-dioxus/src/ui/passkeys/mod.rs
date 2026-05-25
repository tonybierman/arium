//! Passkey (WebAuthn) UI screens and the browser bridge.

/// Browser bridge to `navigator.credentials` (wasm) / stubs (server).
pub mod webauthn_client;

/// Passkey second-factor challenge shown mid-login.
pub mod challenge;
/// Background conditional-UI (autofill) passwordless sign-in.
pub mod conditional;
/// Passkey management screen (list / add / remove), for account settings.
pub mod setup;
/// Self-contained passwordless passkey sign-in button (modal; desktop-leaning).
pub mod sign_in_button;

pub use challenge::PasskeyChallenge;
pub use conditional::PasskeyConditionalSignIn;
pub use setup::PasskeySetup;
pub use sign_in_button::PasskeySignInButton;
