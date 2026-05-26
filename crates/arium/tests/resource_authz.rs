//! Per-resource authorization: the `require_resource` enforcement boundary,
//! the role lattice, default-deny, lookup-error propagation, and freshness
//! (no caching, no dependence on the session's flat permission set).

mod common;

use arium::authz::{ResourceAuthzError, ResourceRef, require_resource};
// The global↔resource bridge lives at the arium crate root (it reads the auth
// engine's permission set), not under `arium::authz`.
use arium::{
    AuditCtx, ResourceGrant, ResourceRole, require_resource_audited, require_resource_or_permission,
};
use common::test_authority::{FailingAuthority, TableAuthority};

const BOARD: &str = "board";

/// Grant a global permission token directly (the global RBAC axis).
async fn grant_permission(pool: &sqlx::SqlitePool, user_id: i64, token: &str) {
    sqlx::query("INSERT INTO user_permissions (user_id, token) VALUES ($1, $2)")
        .bind(user_id)
        .bind(token)
        .execute(pool)
        .await
        .expect("grant permission token");
}

/// The resource axis authorizes on its own — no global token needed, and the
/// return value names the resource path.
#[tokio::test]
async fn resource_role_authorizes_without_a_token() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    TableAuthority::grant(&pool, uid, BOARD, 1, "editor").await;

    let grant = require_resource_or_permission(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Editor,
        "boards:superadmin",
    )
    .await
    .expect("a sufficient resource role authorizes");
    assert_eq!(grant, ResourceGrant::Resource);
}

/// With no (or insufficient) resource role, the global permission token is the
/// escape hatch — and the grant is reported as the global path.
#[tokio::test]
async fn global_permission_is_the_escape_hatch() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    // No membership row on board 1; instead, an app-wide capability.
    grant_permission(&pool, uid, "boards:superadmin").await;

    let grant = require_resource_or_permission(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Manager,
        "boards:superadmin",
    )
    .await
    .expect("the global token authorizes when the resource role is absent");
    assert_eq!(grant, ResourceGrant::GlobalPermission);
}

/// Neither a sufficient role nor the token → default-deny, exactly as the
/// single-axis [`require_resource`] would.
#[tokio::test]
async fn neither_axis_is_forbidden() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await; // below Manager
    grant_permission(&pool, uid, "some:other:token").await; // not the one required

    let res = require_resource_or_permission(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Manager,
        "boards:superadmin",
    )
    .await;
    assert!(matches!(res, Err(ResourceAuthzError::Forbidden)));
}

/// A storage failure on the resource lookup is a `Lookup` error — the global
/// fallback must not mask an infrastructure failure as a deny.
#[tokio::test]
async fn resource_lookup_failure_does_not_fall_through() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    grant_permission(&pool, uid, "boards:superadmin").await; // would pass if reached

    let res = require_resource_or_permission(
        &FailingAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Manager,
        "boards:superadmin",
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Lookup(_))),
        "a role_on failure must surface as Lookup, never fall through to the token check",
    );
}

#[tokio::test]
async fn no_relationship_is_forbidden() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    let res = require_resource(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Viewer,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Forbidden)),
        "a user with no membership row must be denied even the lowest role",
    );
}

#[tokio::test]
async fn role_meets_or_exceeds_minimum_is_allowed() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    // Viewer satisfies a Viewer requirement (equality).
    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await;
    assert_eq!(
        require_resource(
            &TableAuthority,
            &pool,
            uid,
            ResourceRef::new(BOARD, 1),
            ResourceRole::Viewer
        )
        .await
        .ok(),
        Some(uid),
        "require_resource returns the user id on success",
    );

    // Owner satisfies an Editor requirement (lattice above).
    TableAuthority::grant(&pool, uid, BOARD, 2, "owner").await;
    assert!(
        require_resource(
            &TableAuthority,
            &pool,
            uid,
            ResourceRef::new(BOARD, 2),
            ResourceRole::Editor
        )
        .await
        .is_ok(),
    );

    // Editor satisfies an Editor requirement (equality).
    TableAuthority::grant(&pool, uid, BOARD, 3, "editor").await;
    assert!(
        require_resource(
            &TableAuthority,
            &pool,
            uid,
            ResourceRef::new(BOARD, 3),
            ResourceRole::Editor
        )
        .await
        .is_ok(),
    );
}

#[tokio::test]
async fn role_below_minimum_is_forbidden() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await;
    let res = require_resource(
        &TableAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Editor,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Forbidden)),
        "a Viewer must not satisfy an Editor requirement",
    );
}

#[tokio::test]
async fn lookup_error_propagates_distinct_from_deny() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    let res = require_resource(
        &FailingAuthority,
        &pool,
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Viewer,
    )
    .await;
    assert!(
        matches!(res, Err(ResourceAuthzError::Lookup(_))),
        "an errored role_on must surface as Lookup, never a silent Forbidden",
    );
}

#[tokio::test]
async fn check_is_fresh_no_caching() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    let r = ResourceRef::new(BOARD, 1);

    TableAuthority::grant(&pool, uid, BOARD, 1, "editor").await;
    assert!(
        require_resource(&TableAuthority, &pool, uid, r, ResourceRole::Editor)
            .await
            .is_ok(),
        "granted Editor should pass",
    );

    // Revoke and re-check: the very next call must reflect the new state,
    // proving the check hits storage every time rather than caching a snapshot.
    TableAuthority::revoke(&pool, uid, BOARD, 1).await;
    assert!(
        matches!(
            require_resource(&TableAuthority, &pool, uid, r, ResourceRole::Editor).await,
            Err(ResourceAuthzError::Forbidden)
        ),
        "revocation must take effect on the next request",
    );
}

// --- require_resource_audited: the reusable audit-on-denial kernel ----------

/// Count `resource.access.denied` rows attributed to `actor`, and return the
/// most recent one's `details` blob for shape assertions.
async fn denied_rows(pool: &sqlx::SqlitePool, actor: i64) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(details, '') FROM audit_events \
         WHERE event_type = 'resource.access.denied' AND actor_id = $1 \
         ORDER BY id",
    )
    .bind(actor)
    .fetch_all(pool)
    .await
    .expect("read audit rows")
}

/// A denial writes exactly one `resource.access.denied` row, attributed to the
/// caller, whose details carry the resource and the *lowercase* required role.
#[tokio::test]
async fn audited_denial_writes_one_row() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    TableAuthority::grant(&pool, uid, BOARD, 1, "viewer").await; // below Manager

    let res = require_resource_audited(
        &TableAuthority,
        &pool,
        &AuditCtx::default(),
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Manager,
    )
    .await;
    assert!(matches!(res, Err(ResourceAuthzError::Forbidden)));

    let rows = denied_rows(&pool, uid).await;
    assert_eq!(rows.len(), 1, "a denial must leave exactly one audit row");
    assert!(
        rows[0].contains("\"min_role\":\"manager\""),
        "details must record the canonical lowercase role, got: {}",
        rows[0],
    );
    assert!(rows[0].contains("\"kind\":\"board\"") && rows[0].contains("\"id\":1"));
}

/// A successful check returns the user id and writes no audit row.
#[tokio::test]
async fn audited_success_is_silent() {
    let pool = common::pool().await;
    TableAuthority::create_table(&pool).await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;
    TableAuthority::grant(&pool, uid, BOARD, 1, "editor").await;

    let ok = require_resource_audited(
        &TableAuthority,
        &pool,
        &AuditCtx::default(),
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Editor,
    )
    .await
    .expect("a sufficient role authorizes");
    assert_eq!(ok, uid, "returns the acting user id on success");
    assert!(
        denied_rows(&pool, uid).await.is_empty(),
        "an allowed access must not write a denial row",
    );
}

/// A storage failure surfaces as `Lookup` and is **not** audited as a denial —
/// an infrastructure error is never recast as (or logged as) a deliberate deny.
#[tokio::test]
async fn audited_lookup_failure_is_not_a_denial() {
    let pool = common::pool().await;
    let uid = common::make_user(&pool, "a@example.invalid", "password123").await;

    let res = require_resource_audited(
        &FailingAuthority,
        &pool,
        &AuditCtx::default(),
        uid,
        ResourceRef::new(BOARD, 1),
        ResourceRole::Viewer,
    )
    .await;
    assert!(matches!(res, Err(ResourceAuthzError::Lookup(_))));
    assert!(
        denied_rows(&pool, uid).await.is_empty(),
        "a lookup failure must not be audited as an access denial",
    );
}
