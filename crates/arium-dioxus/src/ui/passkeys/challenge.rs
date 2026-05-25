use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{begin_passkey_login, finish_passkey_login};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::passkeys::webauthn_client;
use crate::wire::{LoginOutcome, PasskeyCredentialResponse};

const PASSKEY_CSS: Asset = asset!("/src/ui/passkeys/style.css", AssetOptions::css_module());

#[css_module("/src/ui/passkeys/style.css")]
struct Styles;

/// Drop-in passkey second-factor challenge shown after
/// [`login_with_password`](crate::server::login_with_password) returns
/// [`LoginOutcome::PasskeyRequired`](crate::wire::LoginOutcome::PasskeyRequired).
///
/// The request challenge is fetched up front so the actual
/// `navigator.credentials.get()` call fires directly inside the button's click
/// — browsers require a transient user activation for a WebAuthn assertion. On
/// success fires `on_logged_in`; `on_cancel` backs out (the consumer should
/// call [`cancel_passkey_login`](crate::server::cancel_passkey_login) to clear
/// the half-authenticated session).
#[component]
pub fn PasskeyChallenge(
    on_logged_in: EventHandler<()>,
    on_cancel: EventHandler<()>,
    #[props(default = "Passkey sign-in")] title: &'static str,
) -> Element {
    let challenge = use_resource(begin_passkey_login);
    let mut error = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let options = challenge().and_then(|r| r.ok());
    let ready = options.is_some();

    rsx! {
        document::Stylesheet { href: PASSKEY_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
                        CardDescription { "Confirm it's you with your passkey." }
                    }
                    CardContent {
                        if !error().is_empty() {
                            div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            class: Styles::dx_auth_submit,
                            onclick: {
                                let options = options.clone();
                                move |_| {
                                    let Some(opts) = options.clone() else {
                                        return;
                                    };
                                    error.set(String::new());
                                    submitting.set(true);
                                    spawn(async move {
                                        match webauthn_client::get_credential(&opts.options_json).await {
                                            Ok(credential_json) => {
                                                let resp = PasskeyCredentialResponse { credential_json };
                                                match finish_passkey_login(resp).await {
                                                    Ok(LoginOutcome::LoggedIn) => on_logged_in.call(()),
                                                    Ok(_) => error
                                                        .set("Unexpected response from server.".to_string()),
                                                    Err(e) => error.set(friendly_server_error(e)),
                                                }
                                            }
                                            Err(msg) => error.set(msg),
                                        }
                                        submitting.set(false);
                                    });
                                }
                            },
                            if submitting() {
                                "Waiting for your device…"
                            } else if ready {
                                "Use your passkey"
                            } else {
                                "Preparing…"
                            }
                        }
                        p { class: Styles::dx_auth_aux,
                            a {
                                href: "#",
                                onclick: move |evt| {
                                    evt.prevent_default();
                                    on_cancel.call(());
                                },
                                "Cancel sign in"
                            }
                        }
                    }
                }
            }
        }
    }
}
