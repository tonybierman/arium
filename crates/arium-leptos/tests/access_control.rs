//! Access-control regression gate — the Rust port of the three-phase shell
//! probe that used to live at `examples/leptos-fullstack-example/access-control-probe.sh`.
//!
//! Boots the real `install`-layered axum router in-process (shared
//! `common::spawn_app`) and asserts the auth gates fire on the *mounted routes*:
//!
//!   Phase 1  every protected / admin endpoint DENIES an anonymous caller.
//!   Phase 2  every admin endpoint REFUSES a logged-in non-admin (vertical
//!            privilege escalation).
//!   Phase 3  user B cannot revoke user A's API token (horizontal IDOR).
//!
//! Leptos server fns are all POST and form-encoded (the `PostUrl` default), so
//! the inventory below uses form fields rather than the Dioxus adapter's JSON.
//! The engine crate already tests the permission *model* (`crates/arium/tests/
//! rbac.rs`) and SQL ownership *scoping* (`crates/arium/tests/api_tokens.rs`);
//! this file adds the missing HTTP-route enforcement coverage.
//!
//! Native-only (see `server_fn_roundtrip.rs` for the rationale).
#![cfg(not(target_arch = "wasm32"))]

mod common;

use arium_leptos::{ApiTokenView, CreateApiTokenResponse, LoginOutcome};
// Link the `#[server]` inventory into this test binary so `handle_server_fns`
// can dispatch to them.
#[allow(unused_imports)]
use arium_leptos::server::*;
use reqwest::StatusCode;

/// One endpoint in the inventory. The endpoint name is relative to `/api/`
/// (the helper prepends it). Form fields are shaped so the request reaches the
/// auth gate instead of dying in arg deserialization.
struct Ep {
    endpoint: &'static str,
    form: &'static [(&'static str, &'static str)],
}

fn ep(endpoint: &'static str, form: &'static [(&'static str, &'static str)]) -> Ep {
    Ep { endpoint, form }
}

/// Endpoints that require a signed-in (non-anonymous) user. Feature-gated
/// entries match the `#[cfg(feature = ...)]` gates on the server fns.
fn protected() -> Vec<Ep> {
    let mut v = vec![
        ep("account", &[]),
        ep("account/display-name", &[("new_name", "probe")]),
        ep(
            "account/password",
            &[("current", "x"), ("new_password", "probeprobe1")],
        ),
        ep("account/delete", &[]),
    ];
    #[cfg(feature = "mfa")]
    v.extend([
        ep("user/mfa/setup", &[]),
        ep("user/mfa/confirm", &[("code", "000000")]),
        ep("user/mfa/disable", &[]),
        ep("user/verify-mfa", &[("code", "000000")]),
    ]);
    #[cfg(feature = "tokens")]
    v.extend([
        ep("user/tokens/new", &[("name", "probe")]),
        ep("user/tokens", &[]),
        ep("user/tokens/revoke", &[("token_id", "1")]),
    ]);
    v
}

/// Endpoints that require an `admin:*` permission (and must also reject anon).
fn admin() -> Vec<Ep> {
    vec![
        ep("admin/users", &[("limit", "10"), ("offset", "0")]),
        ep("admin/users/get", &[("user_id", "1")]),
        ep(
            "admin/users/roles",
            &[("user_id", "1"), ("role_ids[0]", "1")],
        ),
        ep("admin/users/delete", &[("user_id", "1")]),
        ep(
            "admin/audit/query",
            &[
                ("query[event_type]", ""),
                ("query[limit]", "10"),
                ("query[offset]", "0"),
            ],
        ),
        ep("admin/roles", &[]),
        ep(
            "admin/roles/create",
            &[("name", "probe"), ("permissions[0]", "x")],
        ),
        ep(
            "admin/roles/update",
            &[("role_id", "1"), ("name", "probe"), ("permissions[0]", "x")],
        ),
        ep("admin/roles/delete", &[("role_id", "1")]),
    ]
}

async fn call(client: &reqwest::Client, base: &str, e: &Ep) -> (StatusCode, String) {
    let (status, text, _) = common::post_form_raw(client, base, e.endpoint, e.form).await;
    (status, text)
}

/// A denial is: the call did not succeed with a real payload. A rejected
/// server fn comes back non-2xx with the message in the body, so non-success
/// == denied; the marker is a belt-and-suspenders for a 2xx error envelope.
fn check_denied(failures: &mut Vec<String>, e: &Ep, status: StatusCode, body: &str) {
    let denied = !status.is_success() || common::has_deny_marker(body);
    if !denied {
        failures.push(format!(
            "POST {}: caller got {status} with a body — POSSIBLE ACCESS-CONTROL GAP: {}",
            e.endpoint,
            snippet(body),
        ));
    }
}

fn snippet(body: &str) -> String {
    body.replace('\n', " ").chars().take(120).collect()
}

// ============================================================
// Phase 1 — anonymous caller must be denied everywhere
// ============================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase1_anonymous_caller_is_denied_on_every_protected_and_admin_endpoint() {
    let base = common::spawn_app().await;
    let anon = common::client(); // a cookie store, but we never log in

    let mut failures = Vec::new();
    let inventory: Vec<Ep> = protected().into_iter().chain(admin()).collect();
    for e in &inventory {
        let (status, body) = call(&anon, &base, e).await;
        check_denied(&mut failures, e, status, &body);
    }

    assert!(
        failures.is_empty(),
        "anonymous access-control gaps ({} of {}):\n  {}",
        failures.len(),
        inventory.len(),
        failures.join("\n  "),
    );
}

// ============================================================
// Phase 2 — logged-in non-admin must be refused on admin endpoints
// ============================================================
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase2_non_admin_is_refused_on_admin_endpoints() {
    let base = common::spawn_app().await;

    // Claim the first-admin slot so our test user is a genuine non-admin.
    common::claim_first_admin_slot(&base).await;

    let user = common::client();
    let outcome =
        common::register(&user, &base, "nonadmin@example.test", "NonAdmin-Probe-1!").await;
    assert_eq!(
        outcome,
        LoginOutcome::LoggedIn,
        "non-admin should be logged in after register"
    );

    let mut failures = Vec::new();
    let admin = admin();
    for e in &admin {
        let (status, body) = call(&user, &base, e).await;
        check_denied(&mut failures, e, status, &body);
    }

    assert!(
        failures.is_empty(),
        "privilege-escalation gaps — a non-admin reached {} of {} admin endpoints:\n  {}",
        failures.len(),
        admin.len(),
        failures.join("\n  "),
    );
}

// ============================================================
// Phase 3 — horizontal isolation: B must not revoke A's token (IDOR)
// ============================================================
#[cfg(feature = "tokens")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase3_user_cannot_revoke_another_users_token() {
    let base = common::spawn_app().await;

    // User A creates a token.
    let a = common::client();
    common::register(&a, &base, "idor-a@example.test", "Idor-Probe-A1!").await;
    let created: CreateApiTokenResponse =
        common::post_form(&a, &base, "user/tokens/new", &[("name", "victim")]).await;
    let token_id = created.view.id;

    // User B tries to revoke A's token by id.
    let b = common::client();
    common::register(&b, &base, "idor-b@example.test", "Idor-Probe-B1!").await;
    let id_str = token_id.to_string();
    let (b_status, _b_body, _) =
        common::post_form_raw(&b, &base, "user/tokens/revoke", &[("token_id", &id_str)]).await;
    assert!(
        !b_status.is_success(),
        "B's revoke of A's token must be rejected, got {b_status}"
    );

    // The authoritative check: A's token is still there (B's attempt was a no-op).
    let a_tokens: Vec<ApiTokenView> = common::post_form(&a, &base, "user/tokens", &[]).await;
    assert!(
        a_tokens.iter().any(|t| t.id == token_id),
        "A's token (id={token_id}) must survive B's revoke attempt — IDOR if it's gone"
    );

    // Control: A revokes its own token and it disappears — proves the id was
    // real and revoke works, so B's failure above is genuine ownership scoping.
    let (ctrl_status, _, _) =
        common::post_form_raw(&a, &base, "user/tokens/revoke", &[("token_id", &id_str)]).await;
    assert!(
        ctrl_status.is_success(),
        "A should revoke its own token, got {ctrl_status}"
    );
    let a_tokens_after: Vec<ApiTokenView> = common::post_form(&a, &base, "user/tokens", &[]).await;
    assert!(
        !a_tokens_after.iter().any(|t| t.id == token_id),
        "control failed: A's own revoke didn't remove the token — test is inconclusive"
    );
}
