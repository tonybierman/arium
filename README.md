# Arium - For Authentication & Authorization

Reusable authentication **and** authorization library — sign-in flows,
session management, MFA, OAuth, and a full RBAC surface (roles,
permission tokens, route guards, audit log) all in one crate.
Provides:

- Email + password sign-in / sign-up with Argon2id hashing.
- "Continue with GitHub" OAuth (env-driven; the button hides itself when
  unconfigured).
- Account linking — signing in with GitHub when an email-matched local
  account already exists attaches the OAuth identity to it.
- Forgot-password reset and email-verification flows with a pluggable
  email backend (SMTP via lettre, or a dev fallback that writes `.eml`
  files locally).
- TOTP two-factor authentication with single-use recovery codes.
- Per-IP rate limiting on the entire router.
- "Remember me" long-lived sessions.
- A drop-in `LoginPanel` UI component built on the Dioxus components
  catalog.
- Role-based access control — system `ADMIN` / `USER` roles plus
  user-defined roles, scoped permission tokens, and a
  `BOOTSTRAP_ADMIN_EMAIL` env var that auto-promotes the first matching
  signup.
- Append-only audit log of authentication and admin events
  (`audit_events` table) with a built-in viewer screen.
- Admin UI screens for managing users, roles, and permission
  assignments.
- Account self-service screens (display name, password change, delete
  account) plus a standalone email-verification screen.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
