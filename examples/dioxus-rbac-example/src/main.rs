//! Smallest faithful demo of arium's **global RBAC** authorization in Dioxus.
//!
//! Global RBAC answers "what is this user *across the whole app?*" — flat,
//! app-wide capability *tokens* (`"newsletter:publish"`) checked against the
//! session's permission set. (Its sibling, *per-resource membership* — "what is
//! this user with respect to *this one* document?" — is in
//! `../dioxus-authz-example`.)
//!
//! Three pieces, and only these three:
//!
//! 1. A demo **role** — `"editor"` — seeded at startup carrying one permission
//!    token, [`CAP_PUBLISH`]. Roles are how RBAC grants tokens: hold the role,
//!    hold its tokens. The "Grant me the editor role" toggle calls
//!    [`grant_editor_role`] / [`revoke_editor_role`] and stands in for an admin
//!    assigning the role — so one freshly-registered account can flip itself
//!    between "has the capability" and "doesn't" and watch everything respond.
//! 2. [`PermissionGate`] — a **cosmetic** UI gate. It shows the publish form
//!    only while the caller holds [`CAP_PUBLISH`]. Hiding a control is not
//!    security.
//! 3. [`publish_newsletter`] — the gated server fn. It re-checks the token
//!    *first*, per request, against the live permission set — that is the real
//!    boundary. The "Attempt publish anyway" button proves it: the request
//!    reaches the server and is rejected there, gate or no gate.
//!
//! Run with `dx serve` and register any account (signup logs you straight in —
//! no `mail` feature, so no verification round-trip).

use dioxus::prelude::*;

use arium_dioxus::server::*;
use arium_dioxus::ui::components::button::{Button, ButtonVariant};
use arium_dioxus::ui::{
    LoginPanel, LoginSubmit, PermissionGate, PermissionsProvider, SubmitKind, use_permissions,
};
use arium_dioxus::{LoginOutcome, friendly_server_error};

const APP_CSS: Asset = asset!("/assets/app.css");

/// The one app-wide capability token this demo gates on. Lives at the crate
/// root (not behind `#[cfg(server)]`) because both the client — the
/// [`PermissionGate`] and the badge list — and the server boundary name it.
const CAP_PUBLISH: &str = "newsletter:publish";

/// The demo role that carries [`CAP_PUBLISH`]. Seeded once at startup; granted
/// to / revoked from the current user by the toggle. Real apps manage roles
/// from an admin console (see `../dioxus-fullstack-example`).
const DEMO_ROLE: &str = "editor";

fn main() {
    #[cfg(not(feature = "server"))]
    dioxus::launch(app);

    #[cfg(feature = "server")]
    dioxus::serve(|| async {
        // Dev SQLite DB under the workspace `target/` dir (gitignored), unless
        // DATABASE_URL is set. arium owns this schema; the migrator creates it.
        let pool = {
            use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
            use std::str::FromStr;

            let connect_opts = match std::env::var("DATABASE_URL") {
                Ok(url) if !url.trim().is_empty() => SqliteConnectOptions::from_str(&url)?,
                _ => SqliteConnectOptions::new()
                    .filename(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/rbac.db"))
                    .create_if_missing(true),
            };
            SqlitePoolOptions::new()
                .max_connections(20)
                .connect_with(connect_opts)
                .await?
        };
        arium_dioxus::migrator().run(&pool).await?;

        // Seed the demo role (idempotent across restarts). This is the only
        // RBAC-specific setup: a role that carries the capability token. arium
        // already seeds `admin` / `member` / `guest`; every new account gets
        // `member`, which carries no tokens — so a fresh user starts with the
        // gate closed until they grant themselves `editor` below.
        let roles = arium_dioxus::auth::list_roles(&pool).await?;
        if !roles.iter().any(|r| r.name == DEMO_ROLE) {
            arium_dioxus::auth::create_role(
                &pool,
                DEMO_ROLE,
                Some("Demo role: may publish the newsletter"),
                &[CAP_PUBLISH.to_string()],
            )
            .await?;
        }

        // No `ResourceAuthority` to register — global RBAC reads the session's
        // own permission set, not any app-supplied per-resource lookup.
        let cfg = arium_dioxus::AuthConfig::builder(pool).build()?;
        arium_dioxus::install(dioxus::server::router(app), cfg).await
    });
}

// ============================================================
// Server-side RBAC boundary + role management
// ============================================================

#[cfg(feature = "server")]
type DbExt = axum::Extension<arium_dioxus::pool::Pool>;

/// The RBAC boundary: resolve the signed-in caller, load their *live*
/// permission set, and require `token`. This is what `PermissionGate` only
/// pretends to do client-side — here it actually gates the action. Returns the
/// acting user id on success.
///
/// arium derives the set from the user's roles (plus any direct grants) on
/// every call, so a role revoked a moment ago is denied immediately — the
/// client's cached snapshot is never trusted.
#[cfg(feature = "server")]
async fn require_permission(
    auth: &arium_dioxus::auth::Session,
    db: &arium_dioxus::pool::Pool,
    token: &str,
) -> Result<i64> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in.").into());
    }
    let user_id = user.id as i64;
    let held = arium_dioxus::auth::list_permissions_for_user(db, user_id).await?;
    if held.iter().any(|t| t == token) {
        Ok(user_id)
    } else {
        Err(ServerFnError::new("You don't have permission for this action.").into())
    }
}

/// The signed-in caller's id, or a "not signed in" error. Shared by the two
/// toggle server fns below.
#[cfg(feature = "server")]
fn current_user_id(auth: &arium_dioxus::auth::Session) -> Result<i64> {
    match auth.current_user.as_ref() {
        Some(u) if !u.anonymous => Ok(u.id as i64),
        _ => Err(ServerFnError::new("Not signed in.").into()),
    }
}

/// Resolve the seeded [`DEMO_ROLE`]'s id (it's created at startup).
#[cfg(feature = "server")]
async fn demo_role_id(db: &arium_dioxus::pool::Pool) -> Result<i64> {
    let roles = arium_dioxus::auth::list_roles(db).await?;
    roles
        .iter()
        .find(|r| r.name == DEMO_ROLE)
        .map(|r| r.id)
        .ok_or_else(|| ServerFnError::new("demo role is not seeded").into())
}

/// Grant the current user the demo `editor` role (and thus [`CAP_PUBLISH`]).
/// Stands in for an admin assigning a role; a real app gates *this* behind
/// `admin:roles:write`.
#[post("/api/demo/grant-editor", auth: arium_dioxus::auth::Session, db: DbExt)]
pub async fn grant_editor_role() -> Result<()> {
    let user_id = current_user_id(&auth)?;
    let role_id = demo_role_id(&db.0).await?;
    arium_dioxus::auth::grant_role(&db.0, user_id, role_id).await?;
    Ok(())
}

/// Revoke the demo `editor` role from the current user.
#[post("/api/demo/revoke-editor", auth: arium_dioxus::auth::Session, db: DbExt)]
pub async fn revoke_editor_role() -> Result<()> {
    let user_id = current_user_id(&auth)?;
    let role_id = demo_role_id(&db.0).await?;
    arium_dioxus::auth::revoke_role(&db.0, user_id, role_id).await?;
    Ok(())
}

/// Publish the newsletter — gated on [`CAP_PUBLISH`]. The
/// [`require_permission`] call is the security boundary; the [`PermissionGate`]
/// in the UI only decides whether the button is *shown*. Nothing is persisted —
/// the example just proves the check passed (or, for "Attempt publish anyway",
/// that it was rejected).
#[post("/api/newsletter/publish", auth: arium_dioxus::auth::Session, db: DbExt)]
pub async fn publish_newsletter() -> Result<String> {
    require_permission(&auth, &db.0, CAP_PUBLISH).await?;
    Ok(format!(
        "✓ Server accepted — you hold `{CAP_PUBLISH}`, so the newsletter is published."
    ))
}

// ============================================================
// UI
// ============================================================

fn app() -> Element {
    rsx! {
        // Catalog theme tokens straight from the adapter (no vendored copy).
        document::Stylesheet { href: arium_dioxus::DEFAULT_THEME_CSS }
        document::Stylesheet { href: APP_CSS }

        // PermissionsProvider gives a shared profile resource (`.profile()` /
        // `.has(token)` / `.refresh()`) and pins the auth stylesheets so the
        // LoginPanel stays styled across sign-in/out re-mounts.
        PermissionsProvider {
            Home {}
        }
    }
}

#[component]
fn Home() -> Element {
    let perms = use_permissions();
    let mut auth_error = use_signal(String::new);

    let on_submit = move |submission: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = submission;
        spawn(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(_) => auth_error.set("Unexpected sign-in outcome.".to_string()),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        main { class: "app-shell",
            h1 { class: "title", "arium · global RBAC" }

            if perms.is_loading() {
                p { class: "muted", "Loading…" }
            } else if perms.is_authenticated() {
                Console {}
            } else {
                LoginPanel {
                    title: "Sign in",
                    description: "Register or sign in — any account works; you'll grant yourself the demo role next.",
                    error: {
                        let e = auth_error();
                        if e.is_empty() { None } else { Some(e) }
                    },
                    on_submit,
                }
            }
        }
    }
}

/// The signed-in view: who you are, the tokens you currently hold, the role
/// toggle, and the gated capability.
#[component]
fn Console() -> Element {
    let perms = use_permissions();

    let name = perms
        .profile()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let tokens = perms.profile().map(|p| p.permissions).unwrap_or_default();
    let holds_publish = perms.has(CAP_PUBLISH);

    // Flip the demo role on/off, then refresh the snapshot so the gate and the
    // badge list re-render against the new grants.
    let toggle = move |_| {
        spawn(async move {
            let _ = if perms.has(CAP_PUBLISH) {
                revoke_editor_role().await
            } else {
                grant_editor_role().await
            };
            perms.refresh();
        });
    };

    rsx! {
        p { class: "muted",
            "Signed in as "
            strong { "{name}" }
            ". RBAC is decided server-side from the roles you hold."
        }

        // The live permission snapshot — RBAC made tangible.
        div { class: "perms",
            span { class: "perms-label", "Your permission tokens:" }
            if tokens.is_empty() {
                span { class: "badge badge-empty", "none yet" }
            } else {
                for t in tokens.iter() {
                    span { key: "{t}", class: "badge", "{t}" }
                }
            }
        }

        // Stand-in for an admin assigning the `editor` role.
        div { class: "toggle-row",
            Button {
                variant: if holds_publish { ButtonVariant::Outline } else { ButtonVariant::Primary },
                onclick: toggle,
                if holds_publish { "Revoke the editor role" } else { "Grant me the editor role" }
            }
            span { class: "muted",
                "the "
                code { "{DEMO_ROLE}" }
                " role carries "
                code { "{CAP_PUBLISH}" }
            }
        }

        CapabilityCard {}

        div { class: "signout",
            Button {
                variant: ButtonVariant::Outline,
                onclick: move |_| async move {
                    let _ = logout().await;
                    perms.refresh();
                },
                "Sign out"
            }
        }
    }
}

/// The gated capability. Editors (anyone holding [`CAP_PUBLISH`]) see the
/// publish button; everyone else sees a locked note plus a button that calls
/// the server fn anyway — to show the boundary, not the gate, is what rejects
/// it.
#[component]
fn CapabilityCard() -> Element {
    let mut result = use_signal(String::new);

    let publish = move || {
        spawn(async move {
            match publish_newsletter().await {
                Ok(msg) => result.set(msg),
                Err(e) => result.set(friendly_server_error(e)),
            }
        });
    };

    rsx! {
        div { class: "cap-card",
            div { class: "cap-head",
                span { class: "cap-title", "Publish the newsletter" }
                span { class: "cap-token", "{CAP_PUBLISH}" }
            }

            PermissionGate {
                token: CAP_PUBLISH.to_string(),
                // Shown when the caller does NOT hold the token.
                fallback: rsx! {
                    div { class: "cap-actions",
                        span { class: "locked", "🔒 You don't hold this permission" }
                        Button {
                            variant: ButtonVariant::Outline,
                            onclick: move |_| publish(),
                            "Attempt publish anyway"
                        }
                    }
                },
                // Shown when the caller holds the token.
                div { class: "cap-actions",
                    Button { onclick: move |_| publish(), "Publish newsletter" }
                }
            }

            if !result().is_empty() {
                p { class: "cap-result", "{result}" }
            }
        }
    }
}
