use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{
    begin_passkey_registration, finish_passkey_registration, get_current_user_profile,
    list_passkeys, revoke_passkey,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::ui::components::input::Input;
use crate::ui::components::label::Label;
use crate::ui::passkeys::webauthn_client;
use crate::wire::{PasskeyCredentialResponse, PasskeyInfo};

const PASSKEY_CSS: Asset = asset!("/src/ui/passkeys/style.css", AssetOptions::css_module());

#[css_module("/src/ui/passkeys/style.css")]
struct Styles;

/// Drop-in passkey management screen, intended to be mounted at e.g.
/// `/account/passkeys` (the parallel of [`crate::ui::mfa::MfaSetup`]).
///
/// Lists the user's enrolled passkeys (with a per-row remove button) and an
/// "Add a passkey" button that runs the full registration ceremony:
/// [`begin_passkey_registration`](crate::server::begin_passkey_registration) →
/// the browser `navigator.credentials.create()` bridge →
/// [`finish_passkey_registration`](crate::server::finish_passkey_registration).
///
/// Renders a sign-in-required card if the visitor isn't authenticated.
#[component]
pub fn PasskeySetup(
    #[props(default = "Passkeys")] title: &'static str,
    #[props(default = "/")] back_href: &'static str,
) -> Element {
    let profile = use_resource(get_current_user_profile);
    let mut passkeys = use_resource(list_passkeys);
    let mut nickname = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut info_message = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let current = profile().and_then(|r| r.ok()).unwrap_or_default();
    if !current.is_authenticated {
        return rsx! {
            document::Stylesheet { href: PASSKEY_CSS }
            div { class: Styles::dx_auth_screen,
                div { class: Styles::dx_auth_card,
                    Card {
                        CardHeader { CardTitle { "Sign in required" } }
                        CardContent {
                            p { "You need to be signed in to manage passkeys." }
                            p { class: Styles::dx_auth_aux,
                                a { href: "{back_href}", "Back to sign in" }
                            }
                        }
                    }
                }
            }
        };
    }

    let enrolled: Vec<PasskeyInfo> = passkeys().and_then(|r| r.ok()).unwrap_or_default();

    rsx! {
        document::Stylesheet { href: PASSKEY_CSS }
        div { class: Styles::dx_auth_screen,
            div { class: Styles::dx_auth_card,
                Card {
                    CardHeader {
                        CardTitle { "{title}" }
                        CardDescription {
                            "Sign in with your fingerprint, face, or a security key — there's no password for an attacker to phish."
                        }
                    }
                    CardContent {
                        if !info_message().is_empty() {
                            p { class: Styles::dx_auth_success, "{info_message}" }
                        }
                        if !error().is_empty() {
                            div { class: Styles::dx_auth_error, role: "alert", "{error}" }
                        }

                        if enrolled.is_empty() {
                            p { "You don't have any passkeys yet." }
                        } else {
                            ul { class: Styles::dx_passkey_list,
                                for pk in enrolled.iter() {
                                    li {
                                        key: "{pk.credential_id}",
                                        class: Styles::dx_passkey_item,
                                        div { class: Styles::dx_passkey_meta,
                                            span { class: Styles::dx_passkey_name,
                                                {pk.nickname.clone().unwrap_or_else(|| "Passkey".to_string())}
                                            }
                                            span { class: Styles::dx_passkey_sub, "Added {pk.created_at_iso}" }
                                            if let Some(used) = pk.last_used_at_iso.clone() {
                                                span { class: Styles::dx_passkey_sub, "Last used {used}" }
                                            }
                                        }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            onclick: {
                                                let cred_id = pk.credential_id.clone();
                                                move |_| {
                                                    let cred_id = cred_id.clone();
                                                    error.set(String::new());
                                                    info_message.set(String::new());
                                                    spawn(async move {
                                                        match revoke_passkey(cred_id).await {
                                                            Ok(()) => {
                                                                info_message.set("Passkey removed.".to_string());
                                                                passkeys.restart();
                                                            }
                                                            Err(e) => error.set(friendly_server_error(e)),
                                                        }
                                                    });
                                                }
                                            },
                                            "Remove"
                                        }
                                    }
                                }
                            }
                        }

                        div { class: Styles::dx_auth_field,
                            Label {
                                html_for: "dx-passkey-nickname",
                                class: Styles::dx_auth_label,
                                "Nickname (optional)"
                            }
                            Input {
                                id: "dx-passkey-nickname",
                                r#type: "text",
                                placeholder: "e.g. MacBook Touch ID",
                                value: "{nickname}",
                                oninput: move |evt: FormEvent| nickname.set(evt.value()),
                            }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            class: Styles::dx_auth_submit,
                            onclick: move |_| {
                                error.set(String::new());
                                info_message.set(String::new());
                                busy.set(true);
                                let nick = nickname.read().trim().to_string();
                                spawn(async move {
                                    match begin_passkey_registration().await {
                                        Ok(challenge) => {
                                            match webauthn_client::create_credential(&challenge.options_json)
                                                .await
                                            {
                                                Ok(credential_json) => {
                                                    let resp = PasskeyCredentialResponse { credential_json };
                                                    match finish_passkey_registration(resp, nick).await {
                                                        Ok(()) => {
                                                            info_message
                                                                .set("Passkey added.".to_string());
                                                            nickname.set(String::new());
                                                            passkeys.restart();
                                                        }
                                                        Err(e) => error.set(friendly_server_error(e)),
                                                    }
                                                }
                                                Err(msg) => error.set(msg),
                                            }
                                        }
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                    busy.set(false);
                                });
                            },
                            if busy() { "Waiting for your device…" } else { "Add a passkey" }
                        }

                        p { class: Styles::dx_auth_aux, a { href: "{back_href}", "Back to account" } }
                    }
                }
            }
        }
    }
}
