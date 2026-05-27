# dioxus-rbac-example

The smallest faithful demo of arium's **global RBAC** authorization in
[`arium-dioxus`](../../crates/arium-dioxus) — the first authorization axis
("what is this user across the whole app?"), kept apart from everything else so
the RBAC story stands alone.

Its sibling, [dioxus-authz-example](../dioxus-authz-example), shows the *second*
axis: a user's role on *one* resource. For the everything-on tour (OAuth, MFA,
mail, API tokens, admin console) see
[dioxus-fullstack-example](../dioxus-fullstack-example).

## Run

```bash
cd examples/dioxus-rbac-example
dx serve
```

Open <http://localhost:8080> and register any account — signup logs you straight
in (no email round-trip; this example builds the adapter without `mail`). The
dev SQLite DB is `target/rbac.db` (`rm` it to start fresh). Needs the
[Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started/) (`dx`).

## What it shows

A single capability — publishing the newsletter — gated on one permission
token, `newsletter:publish`. Use the toggle to grant/revoke yourself the demo
`editor` role and watch both paths:

| Your roles            | Holds `newsletter:publish`? | Publish button? | Server fn (`require token`) |
|-----------------------|-----------------------------|-----------------|-----------------------------|
| `member` (default)    | no                          | hidden          | **rejected**                |
| `member` + `editor`   | yes                         | shown           | accepted                    |

Three pieces, and only these three:

1. **A demo role** — `editor` — seeded at startup carrying the
   `newsletter:publish` token. Roles are how RBAC grants tokens: hold the role,
   hold its tokens. The "Grant me the editor role" toggle calls `grant_role` /
   `revoke_role` on your own account and stands in for an admin assigning the
   role (a real app gates that behind `admin:roles:write`).

2. **`PermissionGate`** is a *cosmetic* UI gate — it only decides whether the
   publish button is shown, by checking the client's cached token snapshot.
   Hiding a control is not a security boundary.

3. **`publish_newsletter`** is the gated server fn. It re-checks the token
   *first*, per request, against the user's **live** permission set
   (`list_permissions_for_user`) — and that is the *real* boundary. The "Attempt
   publish anyway" button proves the point: the request reaches the server and
   is rejected there, gate or no gate.

> The very first account on a fresh DB is auto-promoted to `admin` (an arium
> convention so every install has one admin). It will show the `admin:*` tokens
> — but still lacks `newsletter:publish` until you grant the `editor` role, so
> the demo behaves the same.

The two axes map to the engine's `arium::authz` module — see its docs for the
global-RBAC vs. per-resource distinction.
