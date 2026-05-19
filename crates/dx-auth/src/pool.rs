//! Compile-time-selected sqlx pool aliases.
//!
//! Enable exactly one of the `sqlite` or `postgres` features. Library code
//! consistently uses [`Pool`] / [`SessionPool`] rather than naming the
//! concrete sqlx pool type so the same query strings work across backends.

#![cfg(feature = "server")]

#[cfg(all(feature = "sqlite", feature = "postgres"))]
compile_error!(
    "dx-auth: enable exactly one of the `sqlite` or `postgres` features, not both."
);

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!(
    "dx-auth: enable one of the `sqlite` or `postgres` features."
);

#[cfg(feature = "sqlite")]
pub type Pool = sqlx::SqlitePool;
#[cfg(feature = "postgres")]
pub type Pool = sqlx::PgPool;

#[cfg(feature = "sqlite")]
pub type SessionPool = axum_session_sqlx::SessionSqlitePool;
#[cfg(feature = "postgres")]
pub type SessionPool = axum_session_sqlx::SessionPgPool;
