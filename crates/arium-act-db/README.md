[![Crates.io](https://img.shields.io/crates/v/arium-act-db.svg)](https://crates.io/crates/arium-act-db)
[![Docs.rs](https://docs.rs/arium-act-db/badge.svg)](https://docs.rs/arium-act-db)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-act-db.svg)](#license)

# arium-act-db

<!-- The section below is generated from src/main.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

`act-db` — operator-grade DB administration for arium.

Plugs into the `act` host via the `arium-act` gate SDK: every verb
authenticates with `-u`/`-p` against the same arium database it
mutates, requires the canonical `admin` role, and writes one
`audit_events` row per successful action. Reads never audit;
denials are always recorded (by the gate itself).

```text
act-db migrate
act-db users create alice@example.com --new-password ... --verified
act-db users reset-password 42 --new-password ...
act-db roles grant 42 admin
act-db tokens create 42 "ci-deploy"        # cleartext printed once
act-db audit query --event-type user.login.failed --limit 200
act-db audit prune 90
```

Database selection follows arium's normal precedence:
`--database-url` > `DATABASE_URL` > `--db <PATH>` (the SQLite
shorthand that expands to `sqlite://<PATH>?mode=rwc`). Pass
`--bootstrap` to skip the admin check — accepted only by `migrate`
and `users create`, the verbs that have to run before there can be
an admin to authenticate against.

Every operation routes through arium's existing public APIs
(`arium::auth::*`, `arium::auth::tokens::*`, `arium::auth::audit::*`).
`act-db` itself contains no second source of truth about the schema —
if a behavior changes in arium, `act-db` inherits it.

<!-- cargo-rdme end -->

## Installation

```sh
cargo install arium-act        # the host
cargo install arium-act-db     # this extension
```

Then:

```sh
act extensions        # confirms act-db is discoverable
act db --help
```

Backends: `--features sqlite` (default) or `--features postgres`. Add `--features membership` to also run arium's membership migrator on `act-db migrate`.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
