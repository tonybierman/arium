[![Crates.io](https://img.shields.io/crates/v/arium-act.svg)](https://crates.io/crates/arium-act)
[![Docs.rs](https://docs.rs/arium-act/badge.svg)](https://docs.rs/arium-act)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-act.svg)](#license)

# arium-act

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

`arium-act` ships two things from one crate:

- The `act` binary (`src/main.rs`) — a generic, `dotnet`-style host
  that discovers `act-<sub>` executables on PATH (and next to itself)
  and execs into them. The binary has no opinion about auth.

- This library (`use arium_act::gate;`) — the **gate SDK** that
  extensions use to plug into a uniform `-u`/`-p`/admin-role flow.
  Available only when one of the `gate-sqlite` or `gate-postgres`
  features is enabled; with neither feature on, the library has no
  surface and pulls in no transitive deps. See the `gate` module for
  the contract every extension uses.

The split keeps the host binary free of arium/tokio/sqlx noise while
letting every extension share one audited gate implementation. Today
the only consumer is `arium-act-db`.

<!-- cargo-rdme end -->

## Installation

The `act` host binary:

```sh
cargo install arium-act
```

The gate SDK, for authoring an `act-<sub>` extension:

```toml
[dependencies]
arium-act = { version = "0.1", features = ["gate-sqlite"] }   # or "gate-postgres"
```

Full API reference on [docs.rs](https://docs.rs/arium-act). Key items: `gate::AuthArgs`, `gate::run`, `gate::build_pool`, `audit::record_or_log`.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
