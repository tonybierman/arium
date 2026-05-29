//! `act-db roles` — list / create / delete roles, inspect their
//! permissions, and grant / revoke them on users.
//!
//! Grant and revoke accept either a numeric role id or a role name;
//! name resolution goes through `arium::auth::list_roles` so we don't
//! carry a second source of truth.

use anyhow::Context;
use arium::auth;
use arium::auth::audit as ariumaudit;
use arium::pool::Pool;

use crate::RolesOp;
use crate::audit;
use crate::output::{Format, print_json};

pub async fn run(pool: &Pool, actor_id: i64, op: RolesOp, fmt: Format) -> anyhow::Result<()> {
    match op {
        RolesOp::List => list(pool, fmt).await,
        RolesOp::Create {
            name,
            description,
            permissions,
        } => create(pool, actor_id, name, description, permissions, fmt).await,
        RolesOp::Delete { role_id } => delete(pool, actor_id, role_id).await,
        RolesOp::Permissions { role_id } => permissions(pool, role_id, fmt).await,
        RolesOp::Grant { user_id, role } => grant(pool, actor_id, user_id, role).await,
        RolesOp::Revoke { user_id, role } => revoke(pool, actor_id, user_id, role).await,
    }
}

async fn list(pool: &Pool, fmt: Format) -> anyhow::Result<()> {
    let rows = auth::list_roles(pool).await?;
    match fmt {
        Format::Json => {
            let views: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "description": r.description,
                    })
                })
                .collect();
            print_json(&views)?;
        }
        Format::Human => {
            println!("{:>4}  {:<24}  description", "id", "name");
            for r in &rows {
                println!(
                    "{:>4}  {:<24}  {}",
                    r.id,
                    r.name,
                    r.description.as_deref().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

async fn create(
    pool: &Pool,
    actor_id: i64,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    fmt: Format,
) -> anyhow::Result<()> {
    let new_id = auth::create_role(pool, &name, description.as_deref(), &permissions).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::ADMIN_ROLE_CREATED,
        None,
        serde_json::json!({
            "verb": "roles.create",
            "role_id": new_id,
            "name": name,
            "permissions": permissions,
        }),
    )
    .await;
    match fmt {
        Format::Json => print_json(&serde_json::json!({ "id": new_id, "name": name }))?,
        Format::Human => println!("created role {new_id} ({name})"),
    }
    Ok(())
}

async fn delete(pool: &Pool, actor_id: i64, role_id: i64) -> anyhow::Result<()> {
    auth::delete_role(pool, role_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::ADMIN_ROLE_DELETED,
        None,
        serde_json::json!({ "verb": "roles.delete", "role_id": role_id }),
    )
    .await;
    println!("deleted role {role_id}");
    Ok(())
}

async fn permissions(pool: &Pool, role_id: i64, fmt: Format) -> anyhow::Result<()> {
    let perms = auth::list_permissions_for_role(pool, role_id).await?;
    match fmt {
        Format::Json => print_json(&perms)?,
        Format::Human => {
            if perms.is_empty() {
                println!("(no permissions)");
            } else {
                for p in &perms {
                    println!("{p}");
                }
            }
        }
    }
    Ok(())
}

async fn grant(pool: &Pool, actor_id: i64, user_id: i64, role: String) -> anyhow::Result<()> {
    let role_id = resolve_role(pool, &role).await?;
    auth::grant_role(pool, user_id, role_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::ADMIN_ROLES_CHANGED,
        Some(user_id),
        serde_json::json!({
            "verb": "roles.grant",
            "user_id": user_id,
            "role_id": role_id,
            "role": role,
        }),
    )
    .await;
    println!("granted role {role_id} to user {user_id}");
    Ok(())
}

async fn revoke(pool: &Pool, actor_id: i64, user_id: i64, role: String) -> anyhow::Result<()> {
    let role_id = resolve_role(pool, &role).await?;
    auth::revoke_role(pool, user_id, role_id).await?;
    audit::record(
        pool,
        actor_id,
        ariumaudit::ADMIN_ROLES_CHANGED,
        Some(user_id),
        serde_json::json!({
            "verb": "roles.revoke",
            "user_id": user_id,
            "role_id": role_id,
            "role": role,
        }),
    )
    .await;
    println!("revoked role {role_id} from user {user_id}");
    Ok(())
}

/// Resolve `role` (numeric id, or unique name) to a role id via the existing
/// `list_roles` API. Keeps the no-second-source-of-truth rule intact.
async fn resolve_role(pool: &Pool, role: &str) -> anyhow::Result<i64> {
    if let Ok(id) = role.parse::<i64>() {
        return Ok(id);
    }
    let all = auth::list_roles(pool).await?;
    let hit = all
        .into_iter()
        .find(|r| r.name.eq_ignore_ascii_case(role))
        .with_context(|| format!("no role named '{role}'"))?;
    Ok(hit.id)
}
