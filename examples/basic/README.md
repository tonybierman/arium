# examples/basic

End-to-end demo of [`dx-auth`](../../). All auth primitives — password,
GitHub OAuth, email verification, password reset, TOTP MFA, rate
limiting, sessions — come from the library; this binary owns the
Home page, ProfileCard, MFA setup UI, and a small `get_permissions`
server fn that uses an app-specific permission token.

## Run

```bash
cd examples/basic
dx serve
```

Then open `http://localhost:8080`. A `auth.db` SQLite file is created on
first run alongside the binary; `rm auth.db` to start fresh (you'll lose
all accounts).

## Optional env vars

See [the workspace README](../../README.md#environment-variables) for
the full table. The most useful ones for kicking the tires locally:

```bash
# Enable the "Continue with GitHub" button. Without these the panel
# renders email/password only.
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...

# With no SMTP_HOST set, verification + password-reset emails get
# written to ./emails/<timestamp>.eml — open them in any email client
# (or `cat`) to grab the link.

dx serve
```

## What's in the example

- `src/main.rs` — `Home`, `ProfileCard`, `VerificationPending`,
  `MfaChallengeView`, `MfaSetup`, `MfaSetupArtifacts`, `MfaConfirmForm`,
  `VerifyEmail`, `ForgotPassword`, `ResetPassword`, plus a
  `get_permissions` server fn demoing the `axum_session_auth` rights
  check against the library's `User`.
- `assets/dx-components-theme.css` — the catalog's theme (dark
  variables; the example forces dark via `app.css`).
- `assets/app.css` — page layout + dark-theme override + dx-auth panel
  visuals.
- `migrations/0001_init.sql` … `0004_mfa.sql` — copied from
  `crates/dx-auth/migrations/sqlite/` and applied via `sqlx::migrate!()`
  at startup.
