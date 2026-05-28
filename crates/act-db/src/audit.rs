//! Extension-side audit emission for `act-db`.
//!
//! Wraps `arium::auth::audit::record_or_log` so the call site stays a
//! one-liner. Policy: every mutating verb emits one event after the
//! underlying arium call returns `Ok`. Reads never audit.

use arium::auth::audit::{RecordInput, record_or_log};
use arium::pool::Pool;

// Custom event types for verbs that don't have a canonical
// `arium::auth::audit::*` constant.
pub const ACT_USER_CREATED: &str = "act.user.created";
pub const ACT_DB_MIGRATED: &str = "act.db.migrated";
pub const ACT_AUDIT_PRUNED: &str = "act.audit.pruned";

fn user_agent() -> String {
    format!("act-db/{}", env!("CARGO_PKG_VERSION"))
}

pub async fn record(
    db: &Pool,
    actor_id: i64,
    event_type: &str,
    target_id: Option<i64>,
    details: serde_json::Value,
) {
    let details_str = details.to_string();
    let ua = user_agent();
    // actor_id 0 is the bootstrap sentinel from `act --bootstrap`. There's no
    // user row to satisfy the FK, so flatten to None and rely on the
    // `details` payload to mark the action as bootstrap-flavored.
    let actor = if actor_id == 0 { None } else { Some(actor_id) };
    record_or_log(
        db,
        RecordInput {
            event_type,
            actor_id: actor,
            target_id,
            ip: None,
            user_agent: Some(&ua),
            details: Some(&details_str),
        },
    )
    .await;
}
