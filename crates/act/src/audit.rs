//! Parent-side audit emission for the `act` host.
//!
//! Every gate decision flows through here so the arium `audit_events` table
//! has a complete operator trail of CLI sessions — both denials (always
//! recorded) and successful admin entries (recorded so downstream consumers
//! can correlate later mutating actions with a session).
//!
//! Custom event types live alongside the canonical `arium::auth::audit::*`
//! constants:
//!
//! - `act.cli.gate_denied`     — auth OK but missing `admin` permission
//! - `act.cli.session_started` — admin verified, about to dispatch
//!
//! Authentication failures reuse the canonical
//! `arium::auth::audit::USER_LOGIN_FAILED` so they're indistinguishable in
//! the log from a web-form failure (same user with the same wrong password
//! gets one event type regardless of entry point).

use arium::auth::audit::{RecordInput, USER_LOGIN_FAILED, record_or_log};
use arium::pool::Pool;

pub const ACT_GATE_DENIED: &str = "act.cli.gate_denied";
pub const ACT_SESSION_STARTED: &str = "act.cli.session_started";

fn user_agent() -> String {
    format!("act/{}", env!("CARGO_PKG_VERSION"))
}

/// Record a failed login attempt from the `act` parent. `actor_id` is
/// always `None` because the failure happens before we can trust the
/// identifier.
pub async fn login_failed(db: &Pool, identifier: &str, sub: &str) {
    let details = serde_json::json!({
        "via": "act",
        "identifier": identifier,
        "subcommand": sub,
    })
    .to_string();
    let ua = user_agent();
    record_or_log(
        db,
        RecordInput {
            event_type: USER_LOGIN_FAILED,
            actor_id: None,
            target_id: None,
            ip: None,
            user_agent: Some(&ua),
            details: Some(&details),
        },
    )
    .await;
}

/// Record an auth-OK but admin-role-missing denial.
pub async fn gate_denied(db: &Pool, user_id: i64, sub: &str) {
    let details = serde_json::json!({
        "via": "act",
        "reason": "admin role required",
        "subcommand": sub,
    })
    .to_string();
    let ua = user_agent();
    record_or_log(
        db,
        RecordInput {
            event_type: ACT_GATE_DENIED,
            actor_id: Some(user_id),
            target_id: Some(user_id),
            ip: None,
            user_agent: Some(&ua),
            details: Some(&details),
        },
    )
    .await;
}

/// Record a successful admin entry, just before dispatching to the extension.
pub async fn session_started(db: &Pool, user_id: i64, sub: &str) {
    let details = serde_json::json!({
        "via": "act",
        "subcommand": sub,
    })
    .to_string();
    let ua = user_agent();
    record_or_log(
        db,
        RecordInput {
            event_type: ACT_SESSION_STARTED,
            actor_id: Some(user_id),
            target_id: None,
            ip: None,
            user_agent: Some(&ua),
            details: Some(&details),
        },
    )
    .await;
}
