//! The example application: router, pages, and login wiring. Everything
//! auth-related (server fns, screens, guards) comes from `arium_leptos`.

use arium_leptos::server::{
    login_with_password, logout, register_with_password, resend_verification_email,
};
use arium_leptos::ui::components::avatar::{Avatar, AvatarFallback, AvatarImage};
use arium_leptos::ui::components::button::{Button, ButtonVariant};
use arium_leptos::ui::components::card::{
    Card, CardContent, CardDescription, CardHeader, CardTitle,
};
use arium_leptos::ui::{
    AccountSettings, AdminRoleEditor, AdminRoleList, AdminUserDetail, AdminUserList, ApiTokens,
    AuditLog, ForgotPassword, LoginPanel, LoginSubmit, MfaChallenge, MfaSetup,
    OAuthProvidersProvider, PermissionGate, PermissionsProvider, Policy, RequirePermission,
    ResetPassword, SubmitKind, VerifyEmail, use_oauth_providers, use_permissions,
};
use arium_leptos::wire::UserProfile;
use arium_leptos::{LoginOutcome, friendly_server_error};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;

const TOKEN_ADMIN_USERS: &str = "admin:users:read";
const TOKEN_ADMIN_AUDIT: &str = "admin:audit:read";
const TOKEN_ADMIN_ROLES: &str = "admin:roles:read";

/// Anyone with at least one admin-tab token may reach `/admin`; individual tabs
/// filter further by their specific token.
fn admin_policy() -> Policy {
    Policy::any_of([TOKEN_ADMIN_USERS, TOKEN_ADMIN_AUDIT, TOKEN_ADMIN_ROLES])
}

/// Small bit of example-only CSS for the app shell + the account screens'
/// app-level `auth-*` classes (the library leaves these to the consumer).
const EXAMPLE_CSS: &str = r#"
.app-shell { max-width: 40rem; margin: 3rem auto; padding: 0 1rem;
  font-family: system-ui, sans-serif; color: var(--secondary-color-1); }
.auth-form { display: flex; flex-direction: column; gap: 0.75rem; }
.auth-field { display: flex; flex-direction: column; gap: 0.375rem; }
.auth-label { font-size: 0.875rem; font-weight: 500; }
.auth-submit { margin-top: 0.5rem; }
.auth-error { color: var(--primary-error-color, #c0392b); font-size: 0.875rem; }
.auth-success { color: var(--secondary-color-4); font-size: 0.875rem; }
.profile-card { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1.5rem; }
.profile-card-identity { display: flex; gap: 0.75rem; align-items: flex-start; }
.profile-card-text { display: flex; flex-direction: column; gap: 0.125rem; min-width: 0; line-height: 1.3; }
.profile-card-name { font-weight: 600; font-size: 0.95rem; }
.profile-card-handle { color: var(--secondary-color-5); font-size: 0.8125rem; }
.profile-card-email { font-size: 0.8125rem; margin-top: 0.125rem; overflow-wrap: anywhere; }
.profile-card-link { font-size: 0.8125rem; color: inherit; text-decoration: underline;
  text-underline-offset: 0.2rem; overflow-wrap: anywhere; }
.app-actions-buttons { margin-top: 1.5rem; }
.app-admin-link { margin-top: 1rem; }

/* Admin console layout: sticky sidebar on desktop, hamburger-toggled slide-in
   drawer on phones. Mobile-first — base rules describe the phone (drawer)
   state; the >=48rem media query promotes the sidebar to a sticky grid column.
   Ported verbatim from the Dioxus example's app.css. */
.admin-layout { position: relative; max-width: 64rem; margin: 2rem auto; padding: 0 1rem; }
.admin-hamburger { display: inline-flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;
  padding: 0.5rem 0.875rem; font-size: 0.9375rem; color: var(--secondary-color-2);
  background: var(--primary-color-4); border: 1px solid var(--primary-color-7);
  border-radius: 0.5rem; cursor: pointer; }
.admin-scrim { position: fixed; inset: 0; z-index: 40; background: rgba(0, 0, 0, 0.5); }
.admin-sidebar { position: fixed; top: 0; left: 0; bottom: 0; z-index: 50; width: 15rem;
  display: flex; flex-direction: column; gap: 1rem; padding: 1.5rem 1rem;
  background: var(--primary-color-3); border-right: 1px solid var(--primary-color-7);
  overflow-y: auto; transform: translateX(-100%); transition: transform 0.2s ease; }
.admin-sidebar--open { transform: translateX(0); }
.admin-brand { margin: 0; font-size: 1.125rem; color: var(--secondary-color); }
.admin-nav { display: flex; flex-direction: column; gap: 0.25rem; }
.admin-nav-item { text-align: left; padding: 0.5rem 0.75rem; font-size: 0.9375rem;
  color: var(--secondary-color-3); background: transparent; border: 1px solid transparent;
  border-radius: 0.5rem; cursor: pointer; }
.admin-nav-item:hover { background: var(--primary-color-5); }
.admin-nav-item.is-active { color: var(--secondary-color); background: var(--primary-color-5);
  border-color: var(--primary-color-7); }
.admin-sidebar .auth-aux, .admin-sidebar .app-actions-buttons { margin-top: auto; }
.admin-content { min-width: 0; }
@media (min-width: 48rem) {
  .admin-hamburger, .admin-scrim { display: none; }
  .admin-layout { display: grid; grid-template-columns: 15rem 1fr; gap: 2rem; align-items: start; }
  .admin-sidebar { position: sticky; top: 2rem; z-index: auto; width: auto; transform: none;
    border-right: none; border: 1px solid var(--primary-color-7); border-radius: 0.75rem; }
}
"#;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title text="arium · Leptos example" />
        <style inner_html=EXAMPLE_CSS></style>
        <PermissionsProvider>
            <OAuthProvidersProvider>
                <Router>
                    <Routes fallback=|| view! { <p class="app-shell">"Not found."</p> }>
                        <Route path=path!("/") view=Home />
                        <Route path=path!("/auth/forgot") view=|| view! { <ForgotPassword /> } />
                        <Route path=path!("/auth/reset") view=ResetRoute />
                        <Route path=path!("/auth/verify") view=VerifyRoute />
                        <Route path=path!("/account/mfa") view=|| view! { <MfaSetup /> } />
                        <Route path=path!("/account/settings") view=AccountPage />
                        <Route path=path!("/admin") view=AdminPage />
                    </Routes>
                </Router>
            </OAuthProvidersProvider>
        </PermissionsProvider>
    }
}

/// Which account surface the signed-in home sidebar has selected. Mirrors
/// `AdminSection` — the logged-in home view uses the same sticky-sidebar /
/// mobile-drawer console layout instead of a tabset.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HomeSection {
    Account,
    Mfa,
    Tokens,
}

#[component]
fn Home() -> impl IntoView {
    let perms = use_permissions();
    let providers = use_oauth_providers();
    let auth_error = RwSignal::new(String::new());
    let pending_email = RwSignal::new(None::<String>);
    let pending_mfa = RwSignal::new(false);
    // Signed-in console state: active sidebar section + mobile drawer open.
    let section = RwSignal::new(HomeSection::Account);
    let nav_open = RwSignal::new(false);

    let on_login = Callback::new(move |sub: LoginSubmit| {
        auth_error.set(String::new());
        let LoginSubmit {
            kind,
            email,
            password,
            remember,
        } = sub;
        let email_pending = email.clone();
        spawn_local(async move {
            let result = match kind {
                SubmitKind::SignIn => login_with_password(email, password, remember).await,
                SubmitKind::SignUp => register_with_password(email, password).await,
            };
            match result {
                Ok(LoginOutcome::LoggedIn) => perms.refresh(),
                Ok(LoginOutcome::EmailUnverified) => pending_email.set(Some(email_pending)),
                Ok(LoginOutcome::MfaRequired) => pending_mfa.set(true),
                Err(e) => auth_error.set(friendly_server_error(e)),
            }
        });
    });

    let sign_out = Callback::new(move |_| {
        spawn_local(async move {
            let _ = logout().await;
            perms.refresh();
        });
    });

    view! {
        {move || {
            if perms.is_authenticated() {
                let profile = perms.profile().unwrap_or_default();
                view! {
                    <div class="admin-layout">
                        <button
                            class="admin-hamburger"
                            aria-label="Toggle navigation"
                            on:click=move |_| nav_open.update(|o| *o = !*o)
                        >
                            "☰ Menu"
                        </button>
                        <Show when=move || nav_open.get()>
                            <div class="admin-scrim" on:click=move |_| nav_open.set(false)></div>
                        </Show>
                        <aside class=move || {
                            if nav_open.get() {
                                "admin-sidebar admin-sidebar--open"
                            } else {
                                "admin-sidebar"
                            }
                        }>
                            <ProfileCard profile=profile />
                            <nav class="admin-nav">
                                <button
                                    class=move || {
                                        if section.get() == HomeSection::Account {
                                            "admin-nav-item is-active"
                                        } else {
                                            "admin-nav-item"
                                        }
                                    }
                                    on:click=move |_| {
                                        section.set(HomeSection::Account);
                                        nav_open.set(false);
                                    }
                                >
                                    "Account"
                                </button>
                                <button
                                    class=move || {
                                        if section.get() == HomeSection::Mfa {
                                            "admin-nav-item is-active"
                                        } else {
                                            "admin-nav-item"
                                        }
                                    }
                                    on:click=move |_| {
                                        section.set(HomeSection::Mfa);
                                        nav_open.set(false);
                                    }
                                >
                                    "Two-factor auth"
                                </button>
                                <button
                                    class=move || {
                                        if section.get() == HomeSection::Tokens {
                                            "admin-nav-item is-active"
                                        } else {
                                            "admin-nav-item"
                                        }
                                    }
                                    on:click=move |_| {
                                        section.set(HomeSection::Tokens);
                                        nav_open.set(false);
                                    }
                                >
                                    "API tokens"
                                </button>
                                // Admin is a separate route, not an in-page section:
                                // this item navigates rather than swapping the pane.
                                <PermissionGate policy=admin_policy()>
                                    <a class="admin-nav-item" href="/admin">"Admin"</a>
                                </PermissionGate>
                            </nav>
                            <div class="app-actions-buttons">
                                <Button variant=ButtonVariant::Outline on_click=sign_out>
                                    "Sign out"
                                </Button>
                            </div>
                        </aside>
                        <main class="admin-content">
                            {move || match section.get() {
                                HomeSection::Account => view! { <AccountSettings /> }.into_any(),
                                HomeSection::Mfa => view! { <MfaSetup embedded=true /> }.into_any(),
                                HomeSection::Tokens => view! { <ApiTokens embedded=true /> }.into_any(),
                            }}
                        </main>
                    </div>
                }
                    .into_any()
            } else if pending_mfa.get() {
                view! {
                    <main class="app-shell">
                        <MfaChallenge
                            on_logged_in=Callback::new(move |_| {
                                pending_mfa.set(false);
                                perms.refresh();
                            })
                            on_cancel=Callback::new(move |_| {
                                pending_mfa.set(false);
                                auth_error.set(String::new());
                                spawn_local(async move {
                                    let _ = arium_leptos::server::cancel_mfa_challenge().await;
                                });
                            })
                        />
                    </main>
                }
                    .into_any()
            } else if let Some(email) = pending_email.get() {
                view! {
                    <main class="app-shell">
                        <VerificationPending
                            email=email
                            on_back=Callback::new(move |_| {
                                pending_email.set(None);
                                auth_error.set(String::new());
                            })
                        />
                    </main>
                }
                    .into_any()
            } else {
                view! {
                    <main class="app-shell">
                        <LoginPanel
                            providers=providers
                            title="Welcome back"
                            description="Sign in to your workspace."
                            forgot_href="/auth/forgot"
                            error=Signal::derive(move || {
                                let e = auth_error.get();
                                if e.is_empty() { None } else { Some(e) }
                            })
                            on_submit=on_login
                        />
                    </main>
                }
                    .into_any()
            }
        }}
    }
}

#[component]
fn ProfileCard(profile: UserProfile) -> impl IntoView {
    // `display()` resolves the chosen display name, falling back to the
    // @username handle — call it instead of poking at the fields directly.
    let display_name = profile.display().to_string();
    let fallback = initials(&display_name);
    let alt = display_name.clone();
    let handle = profile.username.clone();
    let avatar_url = profile.avatar_url.clone();
    let email = profile.email.clone();
    let html_url = profile.html_url.clone();
    view! {
        <div class="profile-card">
            <div class="profile-card-identity">
                <Avatar>
                    {avatar_url.map(|url| view! { <AvatarImage src=url alt=alt /> })}
                    <AvatarFallback>{fallback}</AvatarFallback>
                </Avatar>
                <div class="profile-card-text">
                    <div class="profile-card-name">{display_name}</div>
                    <div class="profile-card-handle">{format!("@{handle}")}</div>
                    {email.map(|addr| view! { <div class="profile-card-email">{addr}</div> })}
                    {html_url
                        .map(|url| {
                            let href = url.clone();
                            view! {
                                <a class="profile-card-link" href=href target="_blank">
                                    {url}
                                </a>
                            }
                        })}
                </div>
            </div>
        </div>
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
fn VerificationPending(email: String, on_back: Callback<()>) -> impl IntoView {
    let resending = RwSignal::new(false);
    let resent = RwSignal::new(false);
    let email_resend = email.clone();
    view! {
        <Card class="login-panel">
            <CardHeader>
                <CardTitle>"Check your inbox"</CardTitle>
                <CardDescription>
                    "We sent a verification link to " <strong>{email}</strong>
                    ". Click it to finish signing in."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div class="auth-form">
                    <Show when=move || resent.get()>
                        <p class="auth-success">"Sent another link."</p>
                    </Show>
                    <Button
                        variant=ButtonVariant::Outline
                        on_click=Callback::new(move |_| {
                            let email = email_resend.clone();
                            resending.set(true);
                            spawn_local(async move {
                                let _ = resend_verification_email(email).await;
                                resending.set(false);
                                resent.set(true);
                            });
                        })
                    >
                        {move || if resending.get() { "Sending…" } else { "Resend verification email" }}
                    </Button>
                    <p class="auth-aux">
                        <a
                            href="#"
                            on:click=move |ev| {
                                ev.prevent_default();
                                on_back.run(());
                            }
                        >
                            "Back to sign in"
                        </a>
                    </p>
                </div>
            </CardContent>
        </Card>
    }
}

#[component]
fn ResetRoute() -> impl IntoView {
    let query = use_query_map();
    let token = query.read_untracked().get("token").unwrap_or_default();
    view! { <ResetPassword token=token /> }
}

#[component]
fn VerifyRoute() -> impl IntoView {
    let query = use_query_map();
    let token = query.read_untracked().get("token").unwrap_or_default();
    view! { <VerifyEmail token=token /> }
}

#[component]
fn AccountPage() -> impl IntoView {
    view! {
        <main class="app-shell">
            <AccountSettings />
            <p class="auth-aux">
                <a href="/">"← Back to home"</a>
            </p>
        </main>
    }
}

/// Which admin surface the sidebar currently has selected. Replaces the former
/// tabset: the page is a single `/admin` route and the active section is in-page
/// signal state rather than a URL.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AdminSection {
    Users,
    Audit,
    Roles,
}

/// Admin console: its own route with a sticky sidebar nav. Gated behind
/// `any_of` so a user with any single admin token can land here; individual
/// sidebar items are pruned to the specific permission each surface needs. On
/// phones the sidebar collapses behind a hamburger toggle and slides in as an
/// overlay drawer.
#[component]
fn AdminPage() -> impl IntoView {
    let perms = use_permissions();
    let selected = RwSignal::new(None::<i64>);
    // Role pane: None = list, Some(None) = new, Some(Some(id)) = edit.
    let role_pane = RwSignal::new(None::<Option<i64>>);

    // Default to the first section the user is actually permitted to see.
    let default_section = if perms.has(TOKEN_ADMIN_USERS) {
        AdminSection::Users
    } else if perms.has(TOKEN_ADMIN_AUDIT) {
        AdminSection::Audit
    } else {
        AdminSection::Roles
    };
    let section = RwSignal::new(default_section);
    let nav_open = RwSignal::new(false);

    view! {
        <RequirePermission policy=admin_policy() redirect_to="/">
            <div class="admin-layout">
                <button
                    class="admin-hamburger"
                    aria-label="Toggle navigation"
                    on:click=move |_| nav_open.update(|o| *o = !*o)
                >
                    "☰ Menu"
                </button>
                <Show when=move || nav_open.get()>
                    <div class="admin-scrim" on:click=move |_| nav_open.set(false)></div>
                </Show>
                <aside class=move || {
                    if nav_open.get() {
                        "admin-sidebar admin-sidebar--open"
                    } else {
                        "admin-sidebar"
                    }
                }>
                    <h2 class="admin-brand">"Admin"</h2>
                    <nav class="admin-nav">
                        <PermissionGate token=TOKEN_ADMIN_USERS.to_string()>
                            <button
                                class=move || {
                                    if section.get() == AdminSection::Users {
                                        "admin-nav-item is-active"
                                    } else {
                                        "admin-nav-item"
                                    }
                                }
                                on:click=move |_| {
                                    section.set(AdminSection::Users);
                                    nav_open.set(false);
                                }
                            >
                                "Users"
                            </button>
                        </PermissionGate>
                        <PermissionGate token=TOKEN_ADMIN_AUDIT.to_string()>
                            <button
                                class=move || {
                                    if section.get() == AdminSection::Audit {
                                        "admin-nav-item is-active"
                                    } else {
                                        "admin-nav-item"
                                    }
                                }
                                on:click=move |_| {
                                    section.set(AdminSection::Audit);
                                    nav_open.set(false);
                                }
                            >
                                "Audit log"
                            </button>
                        </PermissionGate>
                        <PermissionGate token=TOKEN_ADMIN_ROLES.to_string()>
                            <button
                                class=move || {
                                    if section.get() == AdminSection::Roles {
                                        "admin-nav-item is-active"
                                    } else {
                                        "admin-nav-item"
                                    }
                                }
                                on:click=move |_| {
                                    section.set(AdminSection::Roles);
                                    nav_open.set(false);
                                }
                            >
                                "Roles"
                            </button>
                        </PermissionGate>
                    </nav>
                    <p class="auth-aux">
                        <a href="/">"← Back to home"</a>
                    </p>
                </aside>
                <main class="admin-content">
                    {move || match section.get() {
                        AdminSection::Users => {
                            match selected.get() {
                                Some(uid) => {
                                    view! {
                                        <AdminUserDetail
                                            user_id=uid
                                            on_back=Callback::new(move |_| selected.set(None))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <AdminUserList on_select=Callback::new(move |id: i64| {
                                            selected.set(Some(id))
                                        }) />
                                    }
                                        .into_any()
                                }
                            }
                        }
                        AdminSection::Audit => view! { <AuditLog /> }.into_any(),
                        AdminSection::Roles => {
                            match role_pane.get() {
                                Some(rid_opt) => {
                                    view! {
                                        <AdminRoleEditor
                                            role_id=rid_opt
                                            on_back=Callback::new(move |_| role_pane.set(None))
                                        />
                                    }
                                        .into_any()
                                }
                                None => {
                                    view! {
                                        <AdminRoleList
                                            on_select=Callback::new(move |id: i64| {
                                                role_pane.set(Some(Some(id)))
                                            })
                                            on_new=Callback::new(move |_| role_pane.set(Some(None)))
                                        />
                                    }
                                        .into_any()
                                }
                            }
                        }
                    }}
                </main>
            </div>
        </RequirePermission>
    }
}
