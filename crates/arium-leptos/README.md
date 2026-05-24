[![Crates.io](https://img.shields.io/crates/v/arium-leptos.svg)](https://crates.io/crates/arium-leptos)
[![Docs.rs](https://docs.rs/arium-leptos/badge.svg)](https://docs.rs/arium-leptos)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-leptos.svg)](#license)

# arium-leptos

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Leptos 0.8 adapter for the [`arium`](https://github.com/tonybierman/arium) auth engine.

This crate exposes arium's authentication as Leptos fullstack server
functions (`server`) plus ready-made UI components (`ui`). The
framework-agnostic engine lives in the `arium` crate; this adapter wires it
to Leptos and, under the `ssr` feature, re-exports the engine's server-side
API (`AuthConfig`, `install`, `migrator`, `Mailer`, the OAuth registry, the
request extractors) so a fullstack app can reach everything through this one
crate.

Unlike the Dioxus adapter, the server/client split is driven by the `ssr` /
`hydrate` cargo features (`#[cfg(feature = "ssr")]`), not by
`cfg(target_arch = "wasm32")` — Leptos compiles the crate once per side.

```rust
// Server (`ssr` feature): layer the engine onto your Leptos axum router.
use arium_leptos::{AuthConfig, Mailer, install, migrator};

migrator().run(&pool).await?;
let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?).build()?;
let app = install(app, cfg).await?; // sessions, OAuth routes, audit, rate limiting

// Client + server: wrap the router and drop in components.
use arium_leptos::ui::{LoginPanel, OAuthProvidersProvider, PermissionsProvider};
// <PermissionsProvider><OAuthProvidersProvider> <Router/> … <LoginPanel/> … </…></…>
```

<!-- cargo-rdme end -->

## Installation

```toml
[dependencies]
arium-leptos = "0.1"
```

Like any Leptos fullstack app, the crate is compiled twice: `ssr` for the server binary, `hydrate` for the wasm client. The capability flags (`oauth-github`, `oauth-oidc`, `oauth-google`, `oauth-microsoft`, `mfa`, `mail`, `ratelimit`, `tokens`) and the backend (`sqlite` / `postgres`) must be present on **both** builds; they only pull in engine code on the `ssr` build. See [`examples/leptos-fullstack-example`](https://github.com/tonybierman/arium/tree/main/examples/leptos-fullstack-example) for a complete `Cargo.toml` and an end-to-end app. Full API reference on [docs.rs](https://docs.rs/arium-leptos).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
