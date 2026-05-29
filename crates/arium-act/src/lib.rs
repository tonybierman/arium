//! `arium-act` ships two things from one crate:
//!
//! - The `act` binary (`src/main.rs`) — a generic, `dotnet`-style host
//!   that discovers `act-<sub>` executables on PATH (and next to itself)
//!   and execs into them. The binary has no opinion about auth.
//!
//! - This library (`use arium_act::gate;`) — the **gate SDK** that
//!   extensions use to plug into a uniform `-u`/`-p`/admin-role flow.
//!   Available only when one of the `gate-sqlite` or `gate-postgres`
//!   features is enabled; with neither feature on, the library has no
//!   surface and pulls in no transitive deps. See the `gate` module for
//!   the contract every extension uses.
//!
//! The split keeps the host binary free of arium/tokio/sqlx noise while
//! letting every extension share one audited gate implementation. Today
//! the only consumer is `arium-act-db`.

#[cfg(any(feature = "gate-sqlite", feature = "gate-postgres"))]
pub mod audit;
#[cfg(any(feature = "gate-sqlite", feature = "gate-postgres"))]
pub mod gate;
