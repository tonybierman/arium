# Configuring arium-dioxus

Two kinds of configuration: **Cargo features** (compiled in at build time) and
**environment variables** (read at runtime). Every feature degrades gracefully
when its config is absent — the GitHub button hides itself when OAuth isn't
configured, the mailer falls back to writing `.eml` files, and so on.

See also [INSTALL_DIOXUS.md](INSTALL_DIOXUS.md) and [USAGE_DIOXUS.md](USAGE_DIOXUS.md).

## Cargo features

Defaults give you "everything on, SQLite backend, UI included":

```toml
default = ["server", "ui", "sqlite", "oauth-github", "mfa", "mail", "ratelimit", "tokens"]
```

| Feature | Default | Gates |
| --- | --- | --- |
| `server` | yes | Core server runtime (sqlx, axum, axum_session, argon2). Required for any backend functionality. |
| `ui` | yes | Catalog widgets + drop-in screens (`LoginPanel`, `MfaSetup`, …). |
| `sqlite` | yes | `sqlx::SqlitePool` backend. **Mutually exclusive with `postgres`.** |
| `postgres` | no | `sqlx::PgPool` backend. **Mutually exclusive with `sqlite`.** |
| `oauth-github` | yes | GitHub provider + the generic OAuth routes. |
| `mfa` | yes | TOTP enrollment + verification, recovery codes, MFA challenge step (+ `MfaChallenge` / `MfaSetup` UI). |
| `mail` | yes | `Mailer` (SMTP + dev `.eml` fallback) and the email-verification / password-reset endpoints + UI. Without `mail`, signup auto-marks accounts verified. |
| `ratelimit` | yes | Per-IP rate limiting via `tower_governor`. |
| `tokens` | yes | Personal API tokens (`ApiTokens` UI + `create/list/revoke` server fns + `hash_api_token`). |

> **Pick exactly one backend.** And keep `sqlite` / `postgres` gated behind your
> own `server` feature, never in the default feature list — see
> [INSTALL_DIOXUS.md](INSTALL_DIOXUS.md#common-pitfalls).

Examples:

```toml
# Postgres + everything
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "ui", "postgres", "oauth-github", "mfa", "mail", "ratelimit", "tokens"] }

# OAuth-only (no password / email flows), SQLite
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "ui", "sqlite", "oauth-github", "ratelimit"] }

# Headless (bring your own component library)
arium-dioxus = { version = "0.1", default-features = false, features = ["server", "sqlite", "oauth-github", "mfa", "mail", "ratelimit"] }
```

## Environment variables

All are optional. Defaults below are what the engine uses when the variable is
unset.

### GitHub OAuth (`oauth-github`)

`GithubProvider::from_env()` returns `Ok(None)` when the client ID or secret is
unset — the routes aren't registered and the "Continue with GitHub" button
hides itself.

| Var | Default | Notes |
| --- | --- | --- |
| `GITHUB_CLIENT_ID` | _(unset)_ | OAuth App Client ID from <https://github.com/settings/developers>. |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | OAuth App Client Secret. |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/github/callback` | Must exactly match the GitHub OAuth App's "Authorization callback URL". |

### Email (`mail`)

When `SMTP_HOST` is set, [lettre](https://github.com/lettre/lettre) opens a
STARTTLS submission connection. When unset, the dev fallback writes RFC-822
`.eml` files into `./emails/<timestamp>.eml`.

| Var | Default | Notes |
| --- | --- | --- |
| `SMTP_HOST` | _(unset → file backend)_ | e.g. `smtp.sendgrid.net`, or `localhost` against [Mailpit](https://mailpit.axllent.org/). |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | _(unset → no auth)_ | |
| `SMTP_PASSWORD` | _(unset)_ | |
| `FROM_EMAIL` | `noreply@localhost` | `From:` header. |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | Builds the absolute links in email bodies. |

### Bootstrap / dev

| Var | Default | Notes |
| --- | --- | --- |
| `DX_AUTH_BOOTSTRAP_ADMIN_EMAIL` | _(unset)_ | If set, the matching signup is auto-granted the `admin` role (re-granted on every startup if the row exists). `BOOTSTRAP_ADMIN_EMAIL` is accepted as an alias. Independently, if no admin exists when a new user signs up, that signup is promoted — so a fresh install always has one admin. |
| `DX_AUTH_SKIP_EMAIL_VERIFICATION` | _(unset)_ | Accepts `1` / `true` / `yes` / `on`. When truthy, `register_with_password` marks accounts verified immediately and returns `LoginOutcome::LoggedIn`. |

### Dev server

| Var | Default | Notes |
| --- | --- | --- |
| `IP` | `127.0.0.1` | Wired by `dx serve`. |
| `PORT` | `8080` | Wired by `dx serve`. |

## Audit log

Sign-ins, sign-outs, admin actions, and account self-service writes all land in
the `audit_events` table. Tune capture and retention on the builder:

```rust
use arium_dioxus::{AuditConfig, AuthConfig};

let cfg = AuthConfig::builder(pool.clone(), mailer)
    .audit(AuditConfig {
        capture_ip: true,
        capture_user_agent: true,
        retention_days: 90,   // a background task prunes older rows; 0 disables pruning
    })
    .build()?;
```

Defaults: IP + user-agent captured, 90-day retention. Drop
`arium_dioxus::ui::admin::AuditLog` onto an `/admin/audit` route for the viewer.
