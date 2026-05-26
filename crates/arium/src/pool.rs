//! Compile-time-selected sqlx pool aliases.
//!
//! Enable exactly one of the `sqlite` or `postgres` features. Library code
//! consistently uses [`Pool`] / [`SessionPool`] rather than naming the
//! concrete sqlx pool type so the same query strings work across backends.
//!
//! The backend selection itself (and its single "exactly one backend" guard)
//! lives in the shared [`arium_pool`] crate, so the auth engine and
//! `arium-authz` agree on one `Pool` type; this module re-exports those aliases
//! and adds [`SessionPool`] (the `axum_session` adapter, used only by auth).

/// The sqlx connection pool, the backing [`Database`](sqlx::Database), and its
/// connection type — re-exported from [`arium_pool`].
pub use arium_pool::{DbBackend, DbConnection, Pool};

/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "sqlite")]
pub type SessionPool = axum_session_sqlx::SessionSqlitePool;
/// The session-store pool adapter consumed by `axum_session`. Wraps the
/// matching backend variant of [`Pool`].
#[cfg(feature = "postgres")]
pub type SessionPool = axum_session_sqlx::SessionPgPool;
