//! Subcommand dispatch. One module per top-level verb group; each
//! exposes a single `run(pool, actor_id, op, fmt)` async fn that
//! `main::run` calls after the gate hands back the authenticated
//! actor.

pub mod audit;
pub mod migrate;
pub mod roles;
pub mod tokens;
pub mod users;
