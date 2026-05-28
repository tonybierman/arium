use arium::auth::audit as ariumaudit;
use arium::pool::Pool;
use arium::wire::AuditQuery;

use crate::AuditOp;
use crate::audit;
use crate::output::{Format, print_json};

pub async fn run(pool: &Pool, actor_id: i64, op: AuditOp, fmt: Format) -> anyhow::Result<()> {
    match op {
        AuditOp::Query {
            event_type,
            actor_id: actor_filter,
            target_id,
            limit,
            offset,
        } => {
            query(
                pool,
                event_type,
                actor_filter,
                target_id,
                limit,
                offset,
                fmt,
            )
            .await
        }
        AuditOp::Prune { retention_days } => prune(pool, actor_id, retention_days).await,
    }
}

async fn query(
    pool: &Pool,
    event_type: Option<String>,
    actor_id: Option<i64>,
    target_id: Option<i64>,
    limit: i64,
    offset: i64,
    fmt: Format,
) -> anyhow::Result<()> {
    let q = AuditQuery {
        event_type: event_type.unwrap_or_default(),
        actor_id,
        target_id,
        since: None,
        until: None,
        limit,
        offset,
    };
    let rows = ariumaudit::query(pool, &q).await?;
    match fmt {
        Format::Json => print_json(&rows)?,
        Format::Human => {
            for e in &rows {
                let actor = e
                    .actor_id
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let target = e
                    .target_id
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{}\t{}\tactor={}\ttarget={}",
                    e.occurred_at_iso, e.event_type, actor, target
                );
            }
        }
    }
    Ok(())
}

async fn prune(pool: &Pool, actor_id: i64, retention_days: u64) -> anyhow::Result<()> {
    let removed = ariumaudit::prune(pool, retention_days).await?;
    audit::record(
        pool,
        actor_id,
        audit::ACT_AUDIT_PRUNED,
        None,
        serde_json::json!({
            "verb": "audit.prune",
            "retention_days": retention_days,
            "removed": removed,
        }),
    )
    .await;
    println!("pruned {removed} audit rows older than {retention_days} days");
    Ok(())
}
