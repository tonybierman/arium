//! Example consumer of the `arium` library.
//!
//! All auth primitives — password / OAuth / MFA / email / sessions / rate
//! limiting — live in the library. This binary only owns app-specific bits:
//! the Home / ProfileCard / Forgot / Reset / Verify / MFA UI pages and the
//! `get_permissions` server fn (which uses app-specific permission tokens).

use std::collections::HashSet;

use dioxus::prelude::*;

use arium_dioxus::server::*;
use arium_dioxus::ui::components::avatar::{Avatar, AvatarFallback, AvatarImage};
use arium_dioxus::ui::components::button::{Button, ButtonVariant};
use arium_dioxus::ui::components::card::{
    Card, CardContent, CardDescription, CardHeader, CardTitle,
};
use arium_dioxus::ui::components::input::Input;
use arium_dioxus::ui::components::label::Label;
use arium_dioxus::ui::components::tabs::{TabContent, TabList, TabTrigger, Tabs};
use arium_dioxus::ui::{
    ApiTokens, ForgotPassword, LoginPanel, LoginSubmit, MfaChallenge, MfaSetup,
    OAuthProvidersProvider, PasskeyChallenge, PasskeyConditionalSignIn, PasskeySetup,
    PermissionGate, PermissionsProvider, Policy, RequirePermission, ResetPassword, SubmitKind,
    VerifyEmail, use_oauth_providers, use_permissions,
};
use arium_dioxus::{LoginOutcome, UserProfile, friendly_server_error};

const APP_CSS: Asset = asset!("/assets/app.css");

/// Permission tokens guarding each tab inside `/admin`. Defined as
/// constants so neither `admin_policy` nor the per-tab visibility checks
/// inside `AdminPage` hard-code the strings independently.
const TOKEN_ADMIN_USERS: &str = "admin:users:read";
const TOKEN_ADMIN_AUDIT: &str = "admin:audit:read";
const TOKEN_ADMIN_ROLES: &str = "admin:roles:read";

/// Admission policy for `/admin`. Anyone with at least one admin-tab
/// token is admitted; individual tabs further filter by their specific
/// token. Adding a new admin tab is a one-place edit: add a const above,
/// reference it here and in `AdminPage`.
fn admin_policy() -> Policy {
    Policy::any_of([TOKEN_ADMIN_USERS, TOKEN_ADMIN_AUDIT, TOKEN_ADMIN_ROLES])
}

fn main() {
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        // Backend is chosen at compile time (the `sqlite` / `postgres` cargo
        // features, which also flip arium's backend). Each branch builds the
        // matching sqlx pool; everything below this point is backend-agnostic.
        #[cfg(feature = "sqlite")]
        let pool = {
            use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
            use std::str::FromStr;

            // DB location: `DATABASE_URL` when set (e.g. the Docker image passes
            // `sqlite:///app/data/auth.db?mode=rwc`), otherwise a dev default
            // under the workspace `target/` dir (already gitignored), keeping it
            // out of the example's cwd. CARGO_MANIFEST_DIR is resolved at
            // compile time; `../../target` is the workspace target relative to
            // this crate at `examples/dioxus-fullstack-example`.
            let connect_opts = match std::env::var("DATABASE_URL") {
                Ok(url) if !url.trim().is_empty() => SqliteConnectOptions::from_str(&url)?,
                _ => SqliteConnectOptions::new()
                    .filename(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/auth.db"))
                    .create_if_missing(true),
            };
            SqlitePoolOptions::new()
                .max_connections(20)
                .connect_with(connect_opts)
                .await?
        };
        #[cfg(feature = "postgres")]
        let pool = {
            use sqlx::postgres::PgPoolOptions;

            // Postgres has no sensible file default, so `DATABASE_URL` is
            // required (the compose overlay sets it to the `db` service). The
            // server creates the schema via the migrator below.
            let url = std::env::var("DATABASE_URL").map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "DATABASE_URL must be set for the postgres backend, e.g. \
                     postgres://user:pass@host:5432/dbname",
                )
            })?;
            PgPoolOptions::new()
                .max_connections(20)
                .connect(&url)
                .await?
        };
        // arium owns the schema for `users`, `oauth_accounts`, `roles`,
        // `audit_events`, `api_keys`, ... — they're embedded in the arium
        // crate. App-specific migrations (none yet) would run after this.
        arium_dioxus::migrator().run(&pool).await?;

        let mailer = arium_dioxus::Mailer::from_env()?;
        println!("[startup] mailer backend: {}", mailer.describe());

        let builder = arium_dioxus::AuthConfig::builder(pool, mailer);
        let builder = match arium_dioxus::oauth::github::GithubProvider::from_env()? {
            Some(gh) => {
                println!("[startup] GitHub OAuth: enabled");
                builder.oauth_provider(gh)?
            }
            None => {
                println!(
                    "[startup] GitHub OAuth: disabled (set GITHUB_CLIENT_ID + \
                     GITHUB_CLIENT_SECRET to enable)"
                );
                builder
            }
        };
        // Google sign-in via the OIDC engine (build with `--features oauth-google`).
        // `from_env` is async — it runs OIDC discovery against accounts.google.com.
        #[cfg(feature = "oauth-google")]
        let builder = match arium_dioxus::oauth::google::GoogleProvider::from_env().await? {
            Some(google) => {
                println!("[startup] Google OAuth: enabled");
                builder.oauth_provider(google)?
            }
            None => {
                println!(
                    "[startup] Google OAuth: disabled (set GOOGLE_CLIENT_ID + \
                     GOOGLE_CLIENT_SECRET to enable)"
                );
                builder
            }
        };

        // WebAuthn / passkeys. The relying-party origin must match the URL the
        // app is served from; default to the dev `dx serve` origin and allow an
        // override for other deployments.
        let webauthn_origin = std::env::var("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        let builder = match url::Url::parse(&webauthn_origin) {
            Ok(origin) => {
                let rp_id = origin.host_str().unwrap_or("localhost").to_string();
                println!("[startup] WebAuthn: enabled (rp_id={rp_id}, origin={origin})");
                builder.webauthn(rp_id, origin, "arium example")
            }
            Err(e) => {
                println!("[startup] WebAuthn: disabled (invalid WEBAUTHN_ORIGIN: {e})");
                builder
            }
        };

        // HTTPS hardening. When we're actually served over https (inferred from
        // WEBAUTHN_ORIGIN), exercise arium's "Deploying behind HTTPS" knobs: a
        // Secure session cookie, HSTS, and a CSP. Gated so plain-http localhost
        // dev isn't broken — a Secure cookie or HSTS there would lock you out.
        let builder = if webauthn_origin.starts_with("https://") {
            let hsts = std::env::var("HSTS").unwrap_or_default();
            // A Dioxus app hydrates from wasm + an inline bootstrap script, so
            // the policy must permit them; override via env to tune further.
            let csp = std::env::var("CONTENT_SECURITY_POLICY").unwrap_or_else(|_| {
                "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; \
                 connect-src 'self'"
                    .to_string()
            });
            println!(
                "[startup] HTTPS hardening: cookie_secure=on, csp=on, hsts={}",
                if hsts.trim().is_empty() {
                    "off"
                } else {
                    hsts.as_str()
                }
            );
            let mut b = builder.cookie_secure(true).content_security_policy(csp);
            if !hsts.trim().is_empty() {
                b = b.hsts(hsts);
            }
            b
        } else {
            builder
        };

        let cfg = builder.build()?;

        arium_dioxus::install(dioxus::server::router(app), cfg).await
    });
}

#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[route("/")]
    Home,
    #[route("/auth/forgot")]
    ForgotPassword,
    #[route("/auth/reset?:token")]
    ResetPassword { token: String },
    #[route("/auth/verify?:token")]
    VerifyEmail { token: String },
    #[route("/account/mfa")]
    MfaSetup,
    #[route("/account/settings")]
    AccountSettingsPage,
    #[route("/admin")]
    AdminPage,
}

fn app() -> Element {
    rsx! {
        // Catalog theme tokens straight from the library — the canonical way
        // for a consumer to pull these in (no vendored copy).
        document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }
        document::Stylesheet { href: APP_CSS }

        // Pre-mount the catalog widgets that only appear inside LoginPanel /
        // MfaSetup so their css_module assets are registered during the
        // initial render. Without this, a logged-in user signing out
        // triggers a client-side mount whose OnceLock + queue_effect link-
        // insertion path can race against the paint and leave the form
        // unstyled until refresh.
        div { style: "display: none", aria_hidden: "true",
            Input {}
            Label { html_for: "__preload" }
        }

        PermissionsProvider {
            OAuthProvidersProvider {
                Router::<Route> {}
            }
        }
    }
}

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let mut logout = use_action(logout);

    // Provider list comes from a single use_resource at the app root via
    // OAuthProvidersProvider — using use_resource here too would re-fire
    // (and briefly return empty) every time the LoginPanel branch
    // unmounts and re-mounts during the login/logout transition, leaving
    // the GitHub button missing right after sign-out.
    let providers = use_oauth_providers();

    let current: UserProfile = perms.profile().unwrap_or_default();
    let logged_in = current.is_authenticated;

    let mut auth_error = use_signal(String::new);
    let mut pending_email = use_signal::<Option<String>>(|| None);
    let mut pending_mfa = use_signal(|| false);
    let mut pending_passkey = use_signal(|| false);

    let on_login_submit = move |submission: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = submission;
        let email_for_pending = email.clone();
        spawn(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_for_pending)),
                Ok(LoginOutcome::MfaRequired) => pending_mfa.set(true),
                Ok(LoginOutcome::PasskeyRequired) => pending_passkey.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        main { class: "app-shell",
            if logged_in {
                {
                    let profile_for_tab = current.clone();
                    rsx! {
                        Tabs {
                            default_value: "account".to_string(),
                            TabList {
                                TabTrigger { index: 0_usize, value: "account".to_string(), "Account" }
                                TabTrigger { index: 1_usize, value: "mfa".to_string(),     "Two-factor auth" }
                                TabTrigger { index: 2_usize, value: "tokens".to_string(),  "API tokens" }
                                PermissionGate {
                                    policy: admin_policy(),
                                    // The TabTrigger primitive doesn't forward arbitrary
                                    // attributes onto its inner button, so wrap it and let
                                    // the click bubble into a navigation handler. The
                                    // primitive's own click toggles tab state, but Home
                                    // unmounts before that's visible.
                                    span {
                                        onclick: move |_| { navigator().push(Route::AdminPage); },
                                        TabTrigger { index: 3_usize, value: "admin".to_string(), "Admin" }
                                    }
                                }
                            }
                            TabContent { index: 0_usize, value: "account".to_string(),
                                ProfileCard { profile: profile_for_tab }
                                arium_dioxus::ui::AccountSettings {}
                            }
                            TabContent { index: 1_usize, value: "mfa".to_string(),
                                MfaSetup {}
                                PasskeySetup {}
                            }
                            TabContent { index: 2_usize, value: "tokens".to_string(),
                                ApiTokens {}
                            }
                        }
                        div { class: "app-actions-buttons",
                            Button {
                                variant: ButtonVariant::Outline,
                                onclick: move |_| async move {
                                    logout.call().await;
                                    perms.refresh();
                                },
                                "Sign out"
                            }
                        }
                    }
                }
            } else if pending_mfa() {
                MfaChallenge {
                    on_logged_in: move |_| {
                        pending_mfa.set(false);
                        perms.refresh();
                    },
                    on_cancel: move |_| {
                        pending_mfa.set(false);
                        auth_error.set(String::new());
                        spawn(async move {
                            let _ = cancel_mfa_challenge().await;
                        });
                    },
                }
            } else if pending_passkey() {
                PasskeyChallenge {
                    on_logged_in: move |_| {
                        pending_passkey.set(false);
                        perms.refresh();
                    },
                    on_cancel: move |_| {
                        pending_passkey.set(false);
                        auth_error.set(String::new());
                        spawn(async move {
                            let _ = cancel_passkey_login().await;
                        });
                    },
                }
            } else if let Some(email) = pending_email() {
                VerificationPending {
                    email,
                    on_back: move |_| {
                        pending_email.set(None);
                        auth_error.set(String::new());
                    },
                }
            } else {
                LoginPanel {
                    providers: providers.clone(),
                    title: "Welcome back",
                    description: "Sign in to your workspace.",
                    forgot_href: "/auth/forgot",
                    // Mark the email field for passkey autofill; the conditional
                    // component below runs the background ceremony.
                    passkey_autofill: true,
                    error: {
                        let e = auth_error();
                        if e.is_empty() { None } else { Some(e) }
                    },
                    on_submit: on_login_submit,
                }
                // Conditional-UI (autofill) passwordless sign-in — the reliable
                // trigger on Safari/iOS. Renders nothing; surfaces passkeys in
                // the email field's autofill menu.
                PasskeyConditionalSignIn { on_logged_in: move |_| perms.refresh() }
            }
        }
    }
}

#[component]
fn ProfileCard(profile: UserProfile) -> Element {
    // `display()` resolves the chosen display name, falling back to the
    // @username handle — call it instead of poking at the fields directly.
    let display_name = profile.display().to_string();
    let handle = profile.username.clone();
    let avatar_url = profile.avatar_url.clone();
    let email = profile.email.clone();
    let html_url = profile.html_url.clone();

    rsx! {
        div { class: "profile-card",
            div { class: "profile-card-identity",
                Avatar {
                    if let Some(url) = avatar_url.as_ref() {
                        AvatarImage { src: "{url}", alt: "{display_name}" }
                    }
                    AvatarFallback { "{initials(&display_name)}" }
                }
                div { class: "profile-card-text",
                    div { class: "profile-card-name", "{display_name}" }
                    div { class: "profile-card-handle", "@{handle}" }
                    if let Some(addr) = email {
                        div { class: "profile-card-email", "{addr}" }
                    }
                    if let Some(url) = html_url {
                        a {
                            class: "profile-card-link",
                            href: "{url}",
                            target: "_blank",
                            "{url}"
                        }
                    }
                }
            }
        }
    }
}

fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

#[component]
fn VerificationPending(email: String, on_back: EventHandler<()>) -> Element {
    let mut resending = use_signal(|| false);
    let mut resent = use_signal(|| false);
    let email_for_resend = email.clone();

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Check your inbox" }
                CardDescription {
                    "We sent a verification link to "
                    strong { "{email}" }
                    ". Click it to finish signing in."
                }
            }
            CardContent {
                div { class: "auth-form",
                    if resent() {
                        p { class: "auth-success", "Sent another link." }
                    }
                    Button {
                        variant: ButtonVariant::Outline,
                        onclick: move |_| {
                            let email = email_for_resend.clone();
                            resending.set(true);
                            spawn(async move {
                                let _ = resend_verification_email(email).await;
                                resending.set(false);
                                resent.set(true);
                            });
                        },
                        if resending() { "Sending…" } else { "Resend verification email" }
                    }
                    p { class: "auth-aux",
                        a {
                            href: "#",
                            onclick: move |evt| {
                                evt.prevent_default();
                                on_back.call(());
                            },
                            "Back to sign in"
                        }
                    }
                }
            }
        }
    }
}

// `ForgotPassword`, `ResetPassword`, `VerifyEmail`, `MfaChallenge`, and
// `MfaSetup` are all drop-in components shipped by the library at
// `arium_dioxus::ui::*` (imported above). The Route enum entries above pick
// them up automatically.

// ---- App-specific server fn: which permissions the current user has. ----

/// Demo permission check using the seed `Category::View` token the library's
/// helpers grant new accounts. Real apps would seed via their own hook (a
/// future API improvement) rather than depending on the library's default.
#[get("/api/user/permissions", auth: arium_dioxus::auth::Session)]
pub async fn get_permissions() -> Result<HashSet<String>> {
    use arium_dioxus::auth::User;
    use axum_session_auth::{Auth, Rights};

    let user = auth.current_user.unwrap();

    Auth::<User, i64, arium_dioxus::pool::Pool>::build([axum::http::Method::GET], false)
        .requires(Rights::any([
            Rights::permission("Category::View"),
            Rights::permission("Admin::View"),
        ]))
        .validate(&user, &axum::http::Method::GET, None)
        .await
        .or_unauthorized("You do not have permission to view categories")?;

    Ok(user.permissions)
}

#[component]
fn AccountSettingsPage() -> Element {
    rsx! {
        main { class: "app-shell",
            arium_dioxus::ui::AccountSettings {}
            p { class: "auth-aux", a { href: "/", "← Back to home" } }
        }
    }
}

/// Admin console: its own route, its own tabset. The whole page is gated
/// behind `any_of` so a user with either users:read OR audit:read can land
/// here; individual tab triggers are then pruned to the specific permission
/// each surface needs.
#[component]
fn AdminPage() -> Element {
    let perms = use_permissions();
    let can_users = perms.has(TOKEN_ADMIN_USERS);
    let can_audit = perms.has(TOKEN_ADMIN_AUDIT);
    let can_roles = perms.has(TOKEN_ADMIN_ROLES);

    let mut selected = use_signal::<Option<i64>>(|| None);
    // Role pane state: None = list, Some(None) = new, Some(Some(id)) = edit.
    let mut role_pane = use_signal::<Option<Option<i64>>>(|| None);

    let default_tab = if can_users {
        "users"
    } else if can_audit {
        "audit"
    } else {
        "roles"
    }
    .to_string();

    rsx! {
        RequirePermission {
            policy: admin_policy(),
            redirect_to: "/".to_string(),
            main { class: "app-shell",
                Tabs {
                    default_value: default_tab,
                    TabList {
                        if can_users {
                            TabTrigger { index: 0_usize, value: "users".to_string(), "Users" }
                        }
                        if can_audit {
                            TabTrigger { index: 1_usize, value: "audit".to_string(), "Audit log" }
                        }
                        if can_roles {
                            TabTrigger { index: 2_usize, value: "roles".to_string(), "Roles" }
                        }
                    }
                    if can_users {
                        TabContent { index: 0_usize, value: "users".to_string(),
                            if let Some(uid) = selected() {
                                arium_dioxus::ui::AdminUserDetail {
                                    user_id: uid,
                                    on_back: move |_| selected.set(None),
                                }
                            } else {
                                arium_dioxus::ui::AdminUserList {
                                    on_select: move |id: i64| selected.set(Some(id)),
                                }
                            }
                        }
                    }
                    if can_audit {
                        TabContent { index: 1_usize, value: "audit".to_string(),
                            arium_dioxus::ui::AuditLog {}
                        }
                    }
                    if can_roles {
                        TabContent { index: 2_usize, value: "roles".to_string(),
                            match role_pane() {
                                Some(rid_opt) => rsx! {
                                    arium_dioxus::ui::AdminRoleEditor {
                                        role_id: rid_opt,
                                        on_back: move |_| role_pane.set(None),
                                    }
                                },
                                None => rsx! {
                                    arium_dioxus::ui::AdminRoleList {
                                        on_select: move |id: i64| role_pane.set(Some(Some(id))),
                                        on_new: move |_| role_pane.set(Some(None)),
                                    }
                                },
                            }
                        }
                    }
                }
                p { class: "auth-aux", a { href: "/", "← Back to home" } }
            }
        }
    }
}
