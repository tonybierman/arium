[![Crates.io](https://img.shields.io/crates/v/arium.svg)](https://crates.io/crates/arium)
[![Docs.rs](https://docs.rs/arium/badge.svg)](https://docs.rs/arium)
[![CI](https://github.com/tonybierman/arium/actions/workflows/ci.yml/badge.svg)](https://github.com/tonybierman/arium/actions)
[![License](https://img.shields.io/crates/l/arium.svg)](#license)

# arium

<!-- The section below is generated from src/lib.rs by cargo-rdme. Edit the `//!` doc comment, then run `cargo rdme`. -->
<!-- cargo-rdme start -->

Framework-agnostic authentication engine for axum + sqlx fullstack apps.

`arium` owns the auth domain — password hashing, sessions, OAuth, MFA/TOTP,
email verification + password reset, RBAC, API tokens, and an audit log —
plus the `install` helper that bolts the whole thing onto an
`axum::Router`. It has no UI-framework dependency; framework adapters such
as `arium-dioxus` wrap these primitives in their own server fns + UI.

Typical server-side usage:

```rust
use arium::{
    AuthConfig, Mailer, install, migrator,
    oauth::{github::GithubProvider, OAuthRegistry},
};

let pool = sqlx::sqlite::SqlitePoolOptions::new()
    .connect_with("sqlite://./app.db?mode=rwc".parse()?)
    .await?;
migrator().run(&pool).await?;

let mut oauth = OAuthRegistry::new(pool.clone())?;
if let Some(gh) = GithubProvider::from_env()? {
    oauth = oauth.with_provider(gh);
}

let cfg = AuthConfig::builder(pool.clone(), Mailer::from_env()?)
    .oauth(oauth)
    .build()?;

// `router` is any `axum::Router` (e.g. your framework's server router).
let router = install(router, cfg).await?;
```

<!-- cargo-rdme end -->

## Installation

```toml
[dependencies]
arium = "0.1"
```

`arium` requires exactly one database backend. `sqlite` is on by default; for PostgreSQL, disable defaults and select `postgres`:

```toml
[dependencies]
arium = { version = "0.1", default-features = false, features = ["postgres", "oauth-github", "mfa", "mail", "ratelimit", "tokens"] }
```

| Feature        | Default | Enables                                        |
| -------------- | ------- | ---------------------------------------------- |
| `sqlite`       | yes     | SQLite backend (pick exactly one backend)      |
| `postgres`     | no      | PostgreSQL backend (pick exactly one backend)  |
| `oauth-github` | yes     | GitHub OAuth provider + routes                 |
| `mfa`          | yes     | TOTP MFA setup and challenge                   |
| `mail`         | yes     | Email verification & password reset (`Mailer`) |
| `ratelimit`    | yes     | Per-IP rate limiting on auth routes            |
| `tokens`       | yes     | API token issuance and validation             |

Without `mail`, `AuthConfig::builder` takes the pool alone. Full API reference on [docs.rs](https://docs.rs/arium).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
