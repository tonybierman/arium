# dioxus-fullstack-example

End-to-end demo of [`arium-dioxus`](../../crates/arium-dioxus).

## Run

```bash
cd examples/dioxus-fullstack-example
DX_AUTH_SKIP_EMAIL_VERIFICATION=1 dx serve
```

Open <http://localhost:8080>. Register an account — the **first** user
becomes admin. The dev SQLite DB is `target/auth.db` (`rm` it to start
fresh).

- `DX_AUTH_SKIP_EMAIL_VERIFICATION=1` skips the email round-trip. Without
  it, verification/reset emails are written to `./emails/*.eml`.
- Set `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` to enable the GitHub
  button; set `SMTP_HOST` (+ creds) for real email. See
  [CONFIG_DIOXUS.md](../../CONFIG_DIOXUS.md#environment-variables) for the full list.
- For Google sign-in (OIDC), run `dx serve --features oauth-google` and set
  `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`.

Needs the [Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started/)
(`dx`).

## Run with Docker

A **runtime-only** image — no Rust/wasm toolchain inside. You build the bundle
on the host, and a slim Debian image just runs the resulting `server` +
`public/`. SQLite keeps it single-container: no database service to manage.

```bash
cd examples/dioxus-fullstack-example
cp .env.example .env            # optional — edit port / OAuth / SMTP
mkdir -p data                   # so it's owned by you, not root (see below)
dx bundle --release --platform web --package dioxus-fullstack-example
docker compose up -d --build
```

Open <http://localhost:8080>. The SQLite DB and the `.eml` mailer output land
in `./data/` (host-owned, gitignored) — `rm -rf data` to start fresh.

- Create `data/` yourself first: the container runs as `user:
  ${UID:-1000}:${GID:-1000}` so the DB/emails land host-owned, but if Docker
  has to create the bind-mount dir it makes it `root`-owned and the container
  can't write. On a default `1000:1000` login, `mkdir -p data` is all you
  need; on a different uid/gid, set `UID=` / `GID=` in `.env` (bash keeps
  `UID` readonly, so `export UID` won't work — `.env` is the clean path).
- Build context is the workspace root (the bundle lives in the shared
  `target/`); compose sets `context: ../..` for you.
- Override the published port, `PUBLIC_BASE_URL`, SMTP creds, GitHub OAuth,
  etc. via `.env` (see `.env.example`). For the full arium config surface —
  Microsoft, generic OIDC, rate limiting, … — see
  [CONFIG_DIOXUS.md](../../CONFIG_DIOXUS.md#environment-variables).
- After a code change, re-bundle and rebuild:
  `dx bundle --release --platform web --package dioxus-fullstack-example && docker compose up -d --build`.

## Run against Postgres

The backend (SQLite vs Postgres) is a **compile-time** choice — arium selects it
via a cargo feature, so you bundle with `--features postgres` and run a second
compose file that adds a `db` service. SQLite stays the default; this is purely
opt-in.

```bash
cd examples/dioxus-fullstack-example
dx bundle --release --platform web --package dioxus-fullstack-example \
    --no-default-features --features web,server,postgres
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

`docker-compose.postgres.yml` layers on top of the base file: it adds a
`postgres:16-alpine` service (data in the `pgdata` named volume) and repoints
the app's `DATABASE_URL` at it, with `depends_on: condition: service_healthy`
so the first migration doesn't race the database. Override the DB credentials
with `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` in `.env` (defaults:
`arium`/`arium`). The same arium migrations run, just against the Postgres
dialect. Tear down with `docker compose -f docker-compose.yml -f docker-compose.postgres.yml down -v`
(`-v` also drops the `pgdata` volume).
