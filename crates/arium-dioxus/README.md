[![Crates.io](https://img.shields.io/crates/v/arium-dioxus.svg)](https://crates.io/crates/arium-dioxus)
[![Docs.rs](https://docs.rs/arium-dioxus/badge.svg)](https://docs.rs/arium-dioxus)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-dioxus.svg)](#license)

# arium-dioxus

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Dioxus 0.7 adapter for the [`arium`](https://github.com/tonybierman/arium) auth engine.

This crate exposes arium's authentication as Dioxus fullstack server
functions (`server`) plus ready-made UI components (`ui`). The
framework-agnostic engine lives in the `arium` crate; this adapter wires it
to Dioxus and, under the `server` feature, re-exports the engine's
server-side API (`AuthConfig`, `install`, `migrator`, `Mailer`, the OAuth
registry, the request extractors) so a fullstack app can reach everything
through this one crate.

```rust
use arium_dioxus::{
    AuthConfig, Mailer, install, migrator,
    oauth::{github::GithubProvider, OAuthRegistry},
    server::*,
    ui::LoginPanel,
};
```

<!-- cargo-rdme end -->

## Installation

```toml
[dependencies]
arium-dioxus = "0.1"
```

Like any Dioxus fullstack app, the crate is compiled for two targets: the wasm client and the native server. The capability flags (`ui`, `oauth-github`, `mfa`, `mail`, `ratelimit`, `tokens`) must be present on **both** builds so the dioxus macro sees the gated server-fn declarations; the server-only crates they pull in are already target-gated to non-wasm. The backend (`sqlite` / `postgres`) is server-only — keep it gated behind your own `server` feature, not in the default feature list. See [`examples/dioxus-fullstack-example`](https://github.com/tonybierman/arium/tree/main/examples/dioxus-fullstack-example) for a complete `Cargo.toml` and an end-to-end app. Full API reference on [docs.rs](https://docs.rs/arium-dioxus).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
