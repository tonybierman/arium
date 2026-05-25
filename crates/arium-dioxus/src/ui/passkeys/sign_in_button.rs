use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{begin_passkey_discoverable, finish_passkey_discoverable};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::passkeys::webauthn_client;
use crate::wire::{LoginOutcome, PasskeyCredentialResponse};

const PASSKEY_CSS: Asset = asset!("/src/ui/passkeys/style.css", AssetOptions::css_module());

#[css_module("/src/ui/passkeys/style.css")]
struct Styles;

/// Self-contained passwordless ("discoverable") passkey sign-in button.
///
/// Runs the full ceremony on click —
/// [`begin_passkey_discoverable`](crate::server::begin_passkey_discoverable) →
/// the browser `navigator.credentials.get()` bridge →
/// [`finish_passkey_discoverable`](crate::server::finish_passkey_discoverable)
/// — and fires `on_logged_in` on success. Drop it next to a `LoginPanel` (or
/// wire it to the panel's `on_passkey` prop) for a no-password sign-in option.
#[component]
pub fn PasskeySignInButton(
    on_logged_in: EventHandler<()>,
    #[props(default = false)] remember_me: bool,
    #[props(default = "Sign in with a passkey")] label: &'static str,
) -> Element {
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    rsx! {
        document::Stylesheet { href: PASSKEY_CSS }
        if !error().is_empty() {
            div { class: Styles::dx_auth_error, role: "alert", "{error}" }
        }
        Button {
            variant: ButtonVariant::Outline,
            class: Styles::dx_auth_submit,
            onclick: move |_| {
                error.set(String::new());
                submitting.set(true);
                spawn(async move {
                    match begin_passkey_discoverable().await {
                        Ok(challenge) => {
                            match webauthn_client::get_credential(&challenge.options_json).await {
                                Ok(credential_json) => {
                                    let resp = PasskeyCredentialResponse { credential_json };
                                    match finish_passkey_discoverable(resp, remember_me).await {
                                        Ok(LoginOutcome::LoggedIn) => on_logged_in.call(()),
                                        Ok(_) => {
                                            error.set("Unexpected response from server.".to_string())
                                        }
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                }
                                Err(msg) => error.set(msg),
                            }
                        }
                        Err(e) => error.set(friendly_server_error(e)),
                    }
                    submitting.set(false);
                });
            },
            if submitting() { "Waiting for your device…" } else { "{label}" }
        }
    }
}
