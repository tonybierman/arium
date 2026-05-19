use dioxus::prelude::*;

use crate::friendly_server_error;
use crate::server::{
    admin_get_user, admin_list_roles, admin_list_users, admin_set_user_roles,
    admin_soft_delete_user,
};
use crate::ui::components::button::{Button, ButtonVariant};
use crate::ui::components::card::{Card, CardContent, CardDescription, CardHeader, CardTitle};
use crate::wire::AdminUserSummary;

/// Paginated user list. Renders 100 users at a time; clicking a row fires
/// `on_select(user_id)` so the parent can navigate to a detail page.
#[component]
pub fn AdminUserList(on_select: EventHandler<i64>) -> Element {
    let mut page = use_signal(|| 0i64);
    let users = use_resource(use_reactive!(|page| async move {
        admin_list_users(100, page * 100).await
    }));

    let body = match users() {
        None => rsx! { p { "Loading…" } },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: "auth-error", "{msg}" } }
        }
        Some(Ok(list)) => rsx! {
            table { class: "dx-admin-table",
                thead {
                    tr {
                        th { "User" }
                        th { "Email" }
                        th { "Roles" }
                        th { "Status" }
                    }
                }
                tbody {
                    for user in list.iter() {
                        AdminUserRow {
                            key: "{user.id}",
                            user: user.clone(),
                            on_select,
                        }
                    }
                }
            }
            div { class: "dx-admin-pager",
                Button {
                    variant: ButtonVariant::Ghost,
                    onclick: move |_| {
                        if page() > 0 { page.set(page() - 1); }
                    },
                    "← Prev"
                }
                span { " Page {page() + 1} " }
                Button {
                    variant: ButtonVariant::Ghost,
                    onclick: move |_| {
                        if list.len() == 100 { page.set(page() + 1); }
                    },
                    "Next →"
                }
            }
        },
    };

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "Users" }
                CardDescription { "Click a row to view details, change roles, or delete the account." }
            }
            CardContent { {body} }
        }
    }
}

#[component]
fn AdminUserRow(user: AdminUserSummary, on_select: EventHandler<i64>) -> Element {
    let id = user.id;
    let display = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.username.clone());
    let role_names: Vec<&'static str> = user.role_ids.iter().map(|r| role_name(*r)).collect();
    let status = if user.deleted {
        "deleted"
    } else if user.anonymous {
        "anonymous"
    } else if !user.email_verified {
        "unverified"
    } else {
        "active"
    };

    rsx! {
        tr {
            onclick: move |_| on_select.call(id),
            td {
                strong { "{display}" }
                " "
                small { "#{id}" }
            }
            td { "{user.email.clone().unwrap_or_default()}" }
            td {
                for name in role_names.iter() {
                    span { class: "dx-role-badge", "{name}" }
                    " "
                }
            }
            td {
                "{status}"
                if user.mfa_enabled { " · 2FA" }
            }
        }
    }
}

fn role_name(id: i64) -> &'static str {
    match id {
        1 => "admin",
        2 => "member",
        3 => "guest",
        _ => "custom",
    }
}

/// Single-user detail: profile fields + role toggle + soft-delete.
#[component]
pub fn AdminUserDetail(user_id: i64, on_back: EventHandler<()>) -> Element {
    let mut detail = use_resource(use_reactive!(|user_id| async move {
        admin_get_user(user_id).await
    }));
    let roles = use_resource(|| async { admin_list_roles().await });
    let mut error = use_signal(String::new);
    let mut info_msg = use_signal(String::new);
    let mut busy = use_signal(|| false);

    let body = match detail() {
        None => rsx! { p { "Loading…" } },
        Some(Err(e)) => {
            let msg = friendly_server_error(e);
            rsx! { div { class: "auth-error", "{msg}" } }
        }
        Some(Ok(None)) => rsx! { p { "User not found." } },
        Some(Ok(Some(d))) => {
            let display = d
                .summary
                .display_name
                .clone()
                .unwrap_or_else(|| d.summary.username.clone());
            let current_roles = d.summary.role_ids.clone();
            rsx! {
                div {
                    h3 { "{display}" }
                    p {
                        "@{d.summary.username}"
                        if d.summary.deleted { " — deleted" }
                    }
                    if let Some(e) = d.summary.email.as_ref() {
                        p { "Email: {e}" }
                    }

                    h3 { "Roles" }
                    if let Some(Ok(role_list)) = roles().as_ref() {
                        ul { class: "dx-admin-roles",
                            for r in role_list.iter() {
                                {
                                    let r_id = r.id;
                                    let checked = current_roles.contains(&r_id);
                                    let starting = current_roles.clone();
                                    let r_name = r.name.clone();
                                    rsx! {
                                        li { key: "{r_id}",
                                            label {
                                                input {
                                                    r#type: "checkbox",
                                                    checked,
                                                    onchange: move |evt: FormEvent| {
                                                        let mut next = starting.clone();
                                                        let now_on = evt.value() == "true" || evt.value() == "on";
                                                        next.retain(|x| *x != r_id);
                                                        if now_on { next.push(r_id); }
                                                        busy.set(true);
                                                        error.set(String::new());
                                                        info_msg.set(String::new());
                                                        spawn(async move {
                                                            match admin_set_user_roles(user_id, next).await {
                                                                Ok(()) => info_msg.set("Roles updated.".to_string()),
                                                                Err(e) => error.set(friendly_server_error(e)),
                                                            }
                                                            busy.set(false);
                                                            detail.restart();
                                                        });
                                                    },
                                                }
                                                " {r_name}"
                                                if let Some(desc) = r.description.as_ref() {
                                                    span { class: "dx-admin-role-desc", " — {desc}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !info_msg().is_empty() {
                        p { class: "auth-success", "{info_msg}" }
                    }
                    if !error().is_empty() {
                        div { class: "auth-error", "{error}" }
                    }

                    if !d.summary.deleted {
                        h3 { "Danger zone" }
                        Button {
                            variant: ButtonVariant::Destructive,
                            onclick: move |_| {
                                busy.set(true);
                                error.set(String::new());
                                info_msg.set(String::new());
                                spawn(async move {
                                    match admin_soft_delete_user(user_id).await {
                                        Ok(()) => info_msg.set("User soft-deleted.".to_string()),
                                        Err(e) => error.set(friendly_server_error(e)),
                                    }
                                    busy.set(false);
                                    detail.restart();
                                });
                            },
                            if busy() { "Working…" } else { "Soft-delete user" }
                        }
                    }
                }
            }
        }
    };

    rsx! {
        Card { class: "login-panel",
            CardHeader {
                CardTitle { "User detail" }
                CardDescription {
                    a {
                        href: "#",
                        onclick: move |evt| {
                            evt.prevent_default();
                            on_back.call(());
                        },
                        "← Back to user list"
                    }
                }
            }
            CardContent { {body} }
        }
    }
}
