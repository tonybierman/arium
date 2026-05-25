use dioxus::prelude::*;

use crate::server::{begin_passkey_discoverable, finish_passkey_discoverable};
use crate::ui::passkeys::webauthn_client;
use crate::wire::{LoginOutcome, PasskeyCredentialResponse};

/// Background conditional-UI ("autofill") passwordless sign-in. Renders nothing.
///
/// On mount it fetches a discoverable challenge and runs a `mediation:
/// conditional` `get()`. The browser then surfaces enrolled passkeys in the
/// **autofill menu** of any field marked `autocomplete="… webauthn"` — e.g.
/// [`LoginPanel`](crate::ui::LoginPanel) with `passkey_autofill: true`. When the
/// user picks one, the assertion completes and `on_logged_in` fires.
///
/// This is the passwordless trigger that works reliably on Safari/iOS (where a
/// modal `get()` from a button tends to stall). Mount it on the login screen
/// alongside the `LoginPanel`. Failures are intentionally silent: conditional
/// UI is a background enhancement, not a user-initiated action, so an
/// unsupported browser or an ignored prompt simply does nothing.
#[component]
pub fn PasskeyConditionalSignIn(
    on_logged_in: EventHandler<()>,
    #[props(default = false)] remember_me: bool,
) -> Element {
    use_future(move || async move {
        let Ok(challenge) = begin_passkey_discoverable().await else {
            return;
        };
        let Ok(credential_json) =
            webauthn_client::get_credential_conditional(&challenge.options_json).await
        else {
            return;
        };
        let resp = PasskeyCredentialResponse { credential_json };
        if let Ok(LoginOutcome::LoggedIn) = finish_passkey_discoverable(resp, remember_me).await {
            on_logged_in.call(());
        }
    });

    rsx! {}
}
