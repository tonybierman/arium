//! The global-RBAC demo: router, login wiring, the live permission snapshot,
//! the self-service role toggle, and the permission-gated server fn.
//!
//! Three pieces, mirroring the dioxus example:
//!
//! 1. A demo **role** — [`DEMO_ROLE`] — seeded in `main.rs` carrying one
//!    permission token, [`CAP_PUBLISH`]. Roles are how RBAC grants tokens. The
//!    "Grant me the editor role" toggle calls [`grant_editor_role`] /
//!    [`revoke_editor_role`] and stands in for an admin assigning the role.
//! 2. [`PermissionGate`] is a **cosmetic** UI gate — it only decides whether the
//!    publish button is shown, by checking the client's cached token snapshot.
//! 3. [`publish_newsletter`] re-checks the token *first*, per request, against
//!    the user's live permission set — the real boundary. The "Attempt publish
//!    anyway" button proves the server rejects it, gate or no gate.

use arium_leptos::server::{login_with_password, logout, register_with_password};
use arium_leptos::ui::components::button::{Button, ButtonVariant};
use arium_leptos::ui::{
    LoginPanel, LoginSubmit, PermissionGate, PermissionsProvider, SubmitKind, use_permissions,
};
use arium_leptos::{LoginOutcome, friendly_server_error};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

/// The one app-wide capability token this demo gates on. `pub` because both the
/// client (the [`PermissionGate`] + badge list) and `main.rs` (seeding) name it.
pub const CAP_PUBLISH: &str = "newsletter:publish";

/// The demo role that carries [`CAP_PUBLISH`]. Seeded at startup; granted to /
/// revoked from the current user by the toggle. Real apps manage roles from an
/// admin console (see `../leptos-fullstack-example`).
pub const DEMO_ROLE: &str = "editor";

/// A little app-shell + card CSS. The dx-components theme (linked by the
/// adapter's auth stylesheets) supplies the color tokens used via `var(...)`.
const EXAMPLE_CSS: &str = r#"
html { --dark: initial; --light: ; color-scheme: dark; }
.app-shell { max-width: 34rem; margin: 3.5rem auto; padding: 0 1rem;
  display: flex; flex-direction: column; gap: 1.25rem;
  font-family: system-ui, sans-serif; color: var(--secondary-color-1); }
.title { font-size: 1.25rem; font-weight: 600; margin: 0; }
.muted { color: var(--secondary-color-7, #9aa0a6); font-size: 0.9rem; line-height: 1.4; margin: 0; }
.muted code, .cap-card code, .toggle-row code { font-size: 0.85em; }
.perms { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
.perms-label { font-size: 0.85rem; color: var(--secondary-color-7, #9aa0a6); }
.badge { font-size: 0.72rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: 0.15rem 0.5rem; border-radius: 999px; border: 1px solid var(--secondary-color-5, #444);
  color: var(--secondary-color-8, #c0c4c9); }
.badge-empty { font-style: italic; opacity: 0.7; }
.toggle-row { display: flex; align-items: center; gap: 0.625rem; flex-wrap: wrap; }
.cap-card { border: 1px solid var(--secondary-color-4, #333); border-radius: 0.5rem;
  padding: 0.875rem 1rem; display: flex; flex-direction: column; gap: 0.625rem; }
.cap-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.cap-title { font-weight: 600; }
.cap-token { font-size: 0.7rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: 0.15rem 0.5rem; border-radius: 999px; border: 1px solid var(--secondary-color-5, #444);
  color: var(--secondary-color-8, #c0c4c9); }
.cap-actions { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.locked { font-size: 0.85rem; color: var(--secondary-color-7, #9aa0a6); }
.cap-result { margin: 0; font-size: 0.85rem; color: var(--secondary-color-8, #c0c4c9); }
.signout { margin-top: 0.5rem; }
"#;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title text="arium · global RBAC (Leptos)" />
        <style inner_html=EXAMPLE_CSS></style>
        // PermissionsProvider gives a shared profile resource
        // (`.profile()` / `.has(token)` / `.refresh()`) and pins the auth
        // stylesheets so the LoginPanel stays styled across re-mounts.
        <PermissionsProvider>
            <Router>
                <Routes fallback=|| view! { <p class="app-shell">"Not found."</p> }>
                    <Route path=path!("/") view=Home />
                </Routes>
            </Router>
        </PermissionsProvider>
    }
}

#[component]
fn Home() -> impl IntoView {
    let perms = use_permissions();
    let auth_error = RwSignal::new(String::new());

    let on_login = Callback::new(move |sub: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = sub;
        spawn_local(async move {
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
    });

    view! {
        <main class="app-shell">
            <h1 class="title">"arium · global RBAC"</h1>
            {move || {
                if perms.is_loading() {
                    view! { <p class="muted">"Loading…"</p> }.into_any()
                } else if perms.is_authenticated() {
                    view! { <Console /> }.into_any()
                } else {
                    view! {
                        <LoginPanel
                            title="Sign in"
                            description="Register or sign in — any account works; you'll grant yourself the demo role next."
                            error=Signal::derive(move || {
                                let e = auth_error.get();
                                if e.is_empty() { None } else { Some(e) }
                            })
                            on_submit=on_login
                        />
                    }
                        .into_any()
                }
            }}
        </main>
    }
}

/// The signed-in view: who you are, the tokens you currently hold, the role
/// toggle, and the gated capability.
#[component]
fn Console() -> impl IntoView {
    let perms = use_permissions();

    let name = move || {
        perms
            .profile()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    };

    // Flip the demo role on/off, then refresh the snapshot so the gate and the
    // badge list re-render against the new grants.
    let toggle = Callback::new(move |_| {
        spawn_local(async move {
            let _ = if perms.has(CAP_PUBLISH) {
                revoke_editor_role().await
            } else {
                grant_editor_role().await
            };
            perms.refresh();
        });
    });

    let sign_out = Callback::new(move |_| {
        spawn_local(async move {
            let _ = logout().await;
            perms.refresh();
        });
    });

    view! {
        <p class="muted">
            "Signed in as " <strong>{name}</strong>
            ". RBAC is decided server-side from the roles you hold."
        </p>

        // The live permission snapshot — RBAC made tangible.
        <div class="perms">
            <span class="perms-label">"Your permission tokens:"</span>
            {move || {
                let toks = perms.profile().map(|p| p.permissions).unwrap_or_default();
                if toks.is_empty() {
                    view! { <span class="badge badge-empty">"none yet"</span> }.into_any()
                } else {
                    toks.into_iter()
                        .map(|t| view! { <span class="badge">{t}</span> })
                        .collect_view()
                        .into_any()
                }
            }}
        </div>

        // Stand-in for an admin assigning the `editor` role.
        <div class="toggle-row">
            {move || {
                let holds = perms.has(CAP_PUBLISH);
                let label = if holds {
                    "Revoke the editor role"
                } else {
                    "Grant me the editor role"
                };
                let variant = if holds { ButtonVariant::Outline } else { ButtonVariant::Primary };
                view! { <Button variant=variant on_click=toggle>{label}</Button> }
            }}
            <span class="muted">
                "the " <code>{DEMO_ROLE}</code> " role carries " <code>{CAP_PUBLISH}</code>
            </span>
        </div>

        <CapabilityCard />

        <div class="signout">
            <Button variant=ButtonVariant::Outline on_click=sign_out>"Sign out"</Button>
        </div>
    }
}

/// The gated capability. Editors (anyone holding [`CAP_PUBLISH`]) see the
/// publish button; everyone else sees a locked note plus a button that calls
/// the server fn anyway — to show the boundary, not the gate, is what rejects
/// it.
#[component]
fn CapabilityCard() -> impl IntoView {
    let result = RwSignal::new(String::new());

    let publish = Callback::new(move |_| {
        spawn_local(async move {
            match publish_newsletter().await {
                Ok(msg) => result.set(msg),
                Err(e) => result.set(friendly_server_error(e)),
            }
        });
    });

    view! {
        <div class="cap-card">
            <div class="cap-head">
                <span class="cap-title">"Publish the newsletter"</span>
                <span class="cap-token">{CAP_PUBLISH}</span>
            </div>
            <PermissionGate
                token=CAP_PUBLISH.to_string()
                // Shown when the caller does NOT hold the token.
                fallback=ViewFn::from(move || {
                    view! {
                        <div class="cap-actions">
                            <span class="locked">"🔒 You don't hold this permission"</span>
                            <Button variant=ButtonVariant::Outline on_click=publish>
                                "Attempt publish anyway"
                            </Button>
                        </div>
                    }
                })
            >
                // Shown when the caller holds the token.
                <div class="cap-actions">
                    <Button on_click=publish>"Publish newsletter"</Button>
                </div>
            </PermissionGate>
            <Show when=move || !result.get().is_empty()>
                <p class="cap-result">{move || result.get()}</p>
            </Show>
        </div>
    }
}

// ============================================================
// Server fns: the RBAC boundary + role management
// ============================================================

/// Grant the current user the demo `editor` role (and thus [`CAP_PUBLISH`]).
/// Stands in for an admin assigning a role; a real app gates *this* behind
/// `admin:roles:write`.
#[server(endpoint = "demo/grant-editor")]
pub async fn grant_editor_role() -> Result<(), ServerFnError> {
    let auth: arium_leptos::auth::Session = leptos_axum::extract().await?;
    let db: axum::Extension<arium_leptos::pool::Pool> = leptos_axum::extract().await?;
    let user_id = current_user_id(&auth)?;
    let role_id = demo_role_id(&db.0).await?;
    arium_leptos::auth::grant_role(&db.0, user_id, role_id)
        .await
        .map_err(sfn)?;
    Ok(())
}

/// Revoke the demo `editor` role from the current user.
#[server(endpoint = "demo/revoke-editor")]
pub async fn revoke_editor_role() -> Result<(), ServerFnError> {
    let auth: arium_leptos::auth::Session = leptos_axum::extract().await?;
    let db: axum::Extension<arium_leptos::pool::Pool> = leptos_axum::extract().await?;
    let user_id = current_user_id(&auth)?;
    let role_id = demo_role_id(&db.0).await?;
    arium_leptos::auth::revoke_role(&db.0, user_id, role_id)
        .await
        .map_err(sfn)?;
    Ok(())
}

/// Publish the newsletter — gated on [`CAP_PUBLISH`]. The [`require_permission`]
/// call is the security boundary; the [`PermissionGate`] in the UI only decides
/// whether the button is *shown*. Nothing is persisted — the example just
/// proves the check passed (or, for "Attempt publish anyway", that it was
/// rejected).
#[server(endpoint = "newsletter/publish")]
pub async fn publish_newsletter() -> Result<String, ServerFnError> {
    let auth: arium_leptos::auth::Session = leptos_axum::extract().await?;
    let db: axum::Extension<arium_leptos::pool::Pool> = leptos_axum::extract().await?;
    require_permission(&auth, &db.0, CAP_PUBLISH).await?;
    Ok(format!(
        "✓ Server accepted — you hold `{CAP_PUBLISH}`, so the newsletter is published."
    ))
}

/// Map any server-side error into a `ServerFnError` with its message preserved.
/// Keeps `?` ergonomic across the engine's `anyhow` / `sqlx` error types, which
/// don't convert into `ServerFnError` on their own.
#[cfg(feature = "ssr")]
fn sfn<E: std::fmt::Display>(e: E) -> ServerFnError {
    ServerFnError::new(e.to_string())
}

/// The signed-in caller's id, or a "not signed in" error.
#[cfg(feature = "ssr")]
fn current_user_id(auth: &arium_leptos::auth::Session) -> Result<i64, ServerFnError> {
    match auth.current_user.as_ref() {
        Some(u) if !u.anonymous => Ok(u.id as i64),
        _ => Err(ServerFnError::new("Not signed in.")),
    }
}

/// Resolve the seeded [`DEMO_ROLE`]'s id (it's created at startup).
#[cfg(feature = "ssr")]
async fn demo_role_id(db: &arium_leptos::pool::Pool) -> Result<i64, ServerFnError> {
    let roles = arium_leptos::auth::list_roles(db).await.map_err(sfn)?;
    roles
        .iter()
        .find(|r| r.name == DEMO_ROLE)
        .map(|r| r.id)
        .ok_or_else(|| ServerFnError::new("demo role is not seeded"))
}

/// The RBAC boundary: resolve the signed-in caller, load their *live* permission
/// set, and require `token`. arium derives the set from the user's roles (plus
/// any direct grants) on every call, so a role revoked a moment ago is denied
/// immediately — the client's cached snapshot is never trusted.
#[cfg(feature = "ssr")]
async fn require_permission(
    auth: &arium_leptos::auth::Session,
    db: &arium_leptos::pool::Pool,
    token: &str,
) -> Result<i64, ServerFnError> {
    let user = auth
        .current_user
        .as_ref()
        .ok_or_else(|| ServerFnError::new("Not signed in."))?;
    if user.anonymous {
        return Err(ServerFnError::new("Not signed in."));
    }
    let user_id = user.id as i64;
    let held = arium_leptos::auth::list_permissions_for_user(db, user_id)
        .await
        .map_err(sfn)?;
    if held.iter().any(|t| t == token) {
        Ok(user_id)
    } else {
        Err(ServerFnError::new(
            "You don't have permission for this action.",
        ))
    }
}
