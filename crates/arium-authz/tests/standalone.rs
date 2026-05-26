//! Proof that `arium-authz` stands alone: enforcement + the full lifecycle,
//! driven against a self-owned table with **no** arium auth schema (no `users`
//! table, no FK, no `create_password_user`). This is the coverage the
//! extraction earns — the crate is usable with any authn stack, or none.

use arium_authz::authz::{ResourceAuthority, ResourceRef};
use arium_authz::membership::{
    Membership, MembershipError, MembershipStore, TxExec, grant_membership, revoke_membership,
    transfer_ownership,
};
use arium_authz::pool::Pool;
use arium_authz::{ResourceRole, require_resource};
use async_trait::async_trait;

const KIND: &str = "doc";

/// A membership store over a plain `members` table — no dependency on arium's
/// users/roles schema.
struct Store;

async fn pool() -> Pool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    sqlx::query(
        "CREATE TABLE members (
            kind        TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            user_id     INTEGER NOT NULL,
            role        TEXT NOT NULL,
            PRIMARY KEY (kind, resource_id, user_id)
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool
}

async fn seed(pool: &Pool, id: i64, user: i64, role: &str) {
    sqlx::query("INSERT INTO members (kind, resource_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(KIND)
        .bind(id)
        .bind(user)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
}

#[async_trait]
impl ResourceAuthority for Store {
    async fn role_on(
        &self,
        db: &Pool,
        user_id: i64,
        r: ResourceRef<'_>,
    ) -> anyhow::Result<Option<ResourceRole>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM members WHERE kind = $1 AND resource_id = $2 AND user_id = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
        Ok(role.map(|s| ResourceRole::from_str_lossy(&s)))
    }
}

#[async_trait]
impl MembershipStore for Store {
    async fn list_members(&self, db: &Pool, r: ResourceRef<'_>) -> anyhow::Result<Vec<Membership>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT user_id, role FROM members WHERE kind = $1 AND resource_id = $2 ORDER BY user_id",
        )
        .bind(r.kind)
        .bind(r.id)
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(user_id, role)| Membership {
                user_id,
                role: ResourceRole::from_str_lossy(&role),
            })
            .collect())
    }

    async fn list_resources_for_user(
        &self,
        db: &Pool,
        user_id: i64,
        kind: &str,
        min_role: ResourceRole,
    ) -> anyhow::Result<Vec<i64>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT resource_id, role FROM members WHERE user_id = $1 AND kind = $2 ORDER BY resource_id",
        )
        .bind(user_id)
        .bind(kind)
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(_, role)| ResourceRole::from_str_lossy(role).at_least(min_role))
            .map(|(id, _)| id)
            .collect())
    }

    async fn role_on_tx(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<Option<ResourceRole>> {
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM members WHERE kind = $1 AND resource_id = $2 AND user_id = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(role.map(|s| ResourceRole::from_str_lossy(&s)))
    }

    async fn count_holders_of_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        role: ResourceRole,
    ) -> anyhow::Result<u64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE kind = $1 AND resource_id = $2 AND role = $3",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(role.as_str())
        .fetch_one(&mut **tx)
        .await?;
        Ok(n as u64)
    }

    async fn upsert_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
        role: ResourceRole,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO members (kind, resource_id, user_id, role) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (kind, resource_id, user_id) DO UPDATE SET role = excluded.role",
        )
        .bind(r.kind)
        .bind(r.id)
        .bind(user_id)
        .bind(role.as_str())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn remove_role(
        &self,
        tx: &mut TxExec<'_>,
        r: ResourceRef<'_>,
        user_id: i64,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM members WHERE kind = $1 AND resource_id = $2 AND user_id = $3")
            .bind(r.kind)
            .bind(r.id)
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn enforcement_and_lifecycle_without_an_auth_schema() {
    let pool = pool().await;
    let r = ResourceRef::new(KIND, 1);
    seed(&pool, 1, 100, "owner").await;

    // Enforcement: the owner clears the Manager bar; a stranger is denied even
    // Viewer (default-deny).
    assert!(
        require_resource(&Store, &pool, 100, r, ResourceRole::Manager)
            .await
            .is_ok()
    );
    assert!(
        require_resource(&Store, &pool, 999, r, ResourceRole::Viewer)
            .await
            .is_err()
    );

    // Lifecycle: owner grants an editor.
    grant_membership(&Store, &pool, 100, r, 200, ResourceRole::Editor)
        .await
        .expect("owner can grant editor");

    // The orphan guard holds with no users table in sight.
    assert!(matches!(
        revoke_membership(&Store, &pool, r, 100).await,
        Err(MembershipError::LastOwner),
    ));

    // Transfer flips owner ↔ manager atomically.
    transfer_ownership(&Store, &pool, r, 100, 200)
        .await
        .expect("owner transfers");
    assert_eq!(
        Store.role_on(&pool, 200, r).await.unwrap(),
        Some(ResourceRole::Owner),
    );
    assert_eq!(
        Store.role_on(&pool, 100, r).await.unwrap(),
        Some(ResourceRole::Manager),
    );
}
