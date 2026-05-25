//! Access-control regression gate — the Rust port of the three-phase shell
//! probe that used to live at `examples/dioxus-fullstack-example/access-control-probe.sh`.
//!
//! Boots the real `install`-layered dioxus server-fn router in-process (shared
//! `common::spawn_app`) and asserts the auth gates fire on the *mounted routes*:
//!
//!   Phase 1  every protected / admin endpoint DENIES an anonymous caller.
//!   Phase 2  every `/api/admin/*` endpoint REFUSES a logged-in non-admin
//!            (vertical privilege escalation).
//!   Phase 3  user B cannot revoke user A's API token (horizontal IDOR).
//!
//! The engine crate already tests the permission *model* (`crates/arium/tests/
//! rbac.rs`) and the SQL ownership *scoping* (`crates/arium/tests/api_tokens.rs`);
//! this file adds the missing coverage that those gates are actually wired onto
//! the HTTP server fns. A refactor that silently un-gates an endpoint turns it red.
//!
//! Native-only (see `server_fn_roundtrip.rs` for the rationale).
#![cfg(not(target_arch = "wasm32"))]

mod common;

use arium_dioxus::{ApiTokenView, CreateApiTokenResponse, LoginOutcome};
// Link the server-fn inventory into this test binary so `spawn_app`'s
// `register_server_functions` can collect them.
#[allow(unused_imports)]
use arium_dioxus::server::*;
use reqwest::StatusCode;
use serde_json::json;

/// One endpoint in the inventory. Bodies are arg-shaped JSON (the Dioxus JSON
/// codec keys args by name) so the request reaches the auth gate instead of
/// dying in arg deserialization.
struct Ep {
    method: &'static str,
    path: &'static str,
    body: serde_json::Value,
}

fn ep(method: &'static str, path: &'static str, body: serde_json::Value) -> Ep {
    Ep { method, path, body }
}

/// Endpoints that require a signed-in (non-anonymous) user. Feature-gated
/// entries match the `#[cfg(feature = ...)]` gates on the server fns, so the
/// inventory stays accurate under reduced feature sets.
fn protected() -> Vec<Ep> {
    let mut v = vec![
        ep("GET", "/api/account", json!({})),
        ep(
            "POST",
            "/api/account/display-name",
            json!({ "new_name": "probe" }),
        ),
        ep(
            "POST",
            "/api/account/password",
            json!({ "current": "x", "new_password": "probeprobe1" }),
        ),
        ep("POST", "/api/account/delete", json!({})),
    ];
    #[cfg(feature = "mfa")]
    v.extend([
        ep("POST", "/api/user/mfa/setup", json!({})),
        ep("POST", "/api/user/mfa/confirm", json!({ "code": "000000" })),
        ep("POST", "/api/user/mfa/disable", json!({})),
        ep("POST", "/api/user/verify-mfa", json!({ "code": "000000" })),
    ]);
    #[cfg(feature = "tokens")]
    v.extend([
        ep("POST", "/api/user/tokens/new", json!({ "name": "probe" })),
        ep("GET", "/api/user/tokens", json!({})),
        ep("POST", "/api/user/tokens/revoke", json!({ "token_id": 1 })),
    ]);
    v
}

/// Endpoints that require an `admin:*` permission (and must also reject anon).
fn admin() -> Vec<Ep> {
    vec![
        ep("GET", "/api/admin/users?limit=10&offset=0", json!({})),
        ep("GET", "/api/admin/users/get?user_id=1", json!({})),
        ep(
            "POST",
            "/api/admin/users/roles",
            json!({ "user_id": 1, "role_ids": [] }),
        ),
        ep("POST", "/api/admin/users/delete", json!({ "user_id": 1 })),
        ep(
            "POST",
            "/api/admin/audit/query",
            json!({ "query": { "event_type": "", "limit": 10, "offset": 0 } }),
        ),
        ep("GET", "/api/admin/roles", json!({})),
        ep(
            "POST",
            "/api/admin/roles/create",
            json!({ "name": "probe", "description": null, "permissions": [] }),
        ),
        ep(
            "POST",
            "/api/admin/roles/update",
            json!({ "role_id": 1, "name": "probe", "description": null, "permissions": [] }),
        ),
        ep("POST", "/api/admin/roles/delete", json!({ "role_id": 1 })),
    ]
}

async fn call(client: &reqwest::Client, base: &str, e: &Ep) -> (StatusCode, String) {
    match e.method {
        "GET" => common::get_raw(client, base, e.path).await,
        "POST" => {
            let (status, text, _) =
                common::post_json_raw(client, base, e.path, e.body.clone()).await;
            (status, text)
        }
        m => panic!("unsupported method in inventory: {m}"),
    }
}

/// A denial is: the route exists (not 404) and the call did not succeed with a
/// real payload. Dioxus surfaces a rejected `ServerFnError` as a non-2xx with
/// the message in the body, so non-success == denied; the marker is a
/// belt-and-suspenders for any 2xx error envelope. Pushes a description onto
/// `failures` if the gate let the caller through.
fn check_denied(failures: &mut Vec<String>, e: &Ep, status: StatusCode, body: &str) {
    if status == StatusCode::NOT_FOUND {
        failures.push(format!(
            "{} {}: 404 — route missing / inventory drift",
            e.method, e.path
        ));
        return;
    }
    let denied = !status.is_success() || common::has_deny_marker(body);
    if !denied {
        failures.push(format!(
            "{} {}: caller got {status} with a body — POSSIBLE ACCESS-CONTROL GAP: {}",
            e.method,
            e.path,
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
// Phase 2 — logged-in non-admin must be refused on /api/admin/*
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
    let (status, text, _) = common::post_json_raw(
        &a,
        &base,
        "/api/user/tokens/new",
        json!({ "name": "victim" }),
    )
    .await;
    assert!(
        status.is_success(),
        "A should create a token: {status} {text}"
    );
    let created: CreateApiTokenResponse = common::deserialize(&text, "/api/user/tokens/new");
    let token_id = created.view.id;

    // User B tries to revoke A's token by id.
    let b = common::client();
    common::register(&b, &base, "idor-b@example.test", "Idor-Probe-B1!").await;
    let (b_status, _b_body, _) = common::post_json_raw(
        &b,
        &base,
        "/api/user/tokens/revoke",
        json!({ "token_id": token_id }),
    )
    .await;
    assert!(
        !b_status.is_success(),
        "B's revoke of A's token must be rejected, got {b_status}"
    );

    // The authoritative check: A's token is still there (B's attempt was a no-op).
    let a_tokens: Vec<ApiTokenView> = common::get_json(&a, &base, "/api/user/tokens").await;
    assert!(
        a_tokens.iter().any(|t| t.id == token_id),
        "A's token (id={token_id}) must survive B's revoke attempt — IDOR if it's gone"
    );

    // Control: A revokes its own token and it disappears — proves the id was
    // real and revoke works, so B's failure above is genuine ownership scoping.
    let (ctrl_status, _, _) = common::post_json_raw(
        &a,
        &base,
        "/api/user/tokens/revoke",
        json!({ "token_id": token_id }),
    )
    .await;
    assert!(
        ctrl_status.is_success(),
        "A should revoke its own token, got {ctrl_status}"
    );
    let a_tokens_after: Vec<ApiTokenView> = common::get_json(&a, &base, "/api/user/tokens").await;
    assert!(
        !a_tokens_after.iter().any(|t| t.id == token_id),
        "control failed: A's own revoke didn't remove the token — test is inconclusive"
    );
}
