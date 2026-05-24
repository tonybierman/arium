[![Crates.io](https://img.shields.io/crates/v/arium-wire.svg)](https://crates.io/crates/arium-wire)
[![Docs.rs](https://docs.rs/arium-wire/badge.svg)](https://docs.rs/arium-wire)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium-wire.svg)](#license)

# arium-wire

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Types that cross the client/server boundary. Kept feature-flag-free so
they compile on both targets without bringing in any server-only deps.

Most apps don't depend on this crate directly — they get these types
transitively through `arium`, `arium-leptos`, or `arium-dioxus`, which
re-export them (e.g. `arium_leptos::wire`). Depend on it directly only when
sharing the types with a separate client crate.

```rust
use arium_wire::{LoginOutcome, UserProfile};

let profile = UserProfile {
    is_authenticated: true,
    username: "ada".to_string(),
    ..Default::default()
};
println!("Signed in as {}", profile.display());

let next = match LoginOutcome::MfaRequired {
    LoginOutcome::LoggedIn => "dashboard",
    LoginOutcome::EmailUnverified => "verify email",
    LoginOutcome::MfaRequired => "enter a TOTP code",
};
assert_eq!(next, "enter a TOTP code");
```

<!-- cargo-rdme end -->

## Installation

```toml
[dependencies]
arium-wire = "0.1"
```

Full API reference on [docs.rs](https://docs.rs/arium-wire). Key types: `UserProfile`, `LoginOutcome`, `ProviderInfo`, `MfaSetupView`, `MfaStatusView`, `ApiTokenView`, `CreateApiTokenResponse`, `AccountView`, and the admin/audit views.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
