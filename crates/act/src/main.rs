mod audit;
mod extensions;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Arg, ArgAction, Command};

use arium::auth::VerifyOutcome;
use arium::auth::role::ADMIN as ADMIN_ROLE_ID;
use arium::pool::Pool;

const TOOL_NAME: &str = "act";

// Env vars handed off to dispatched extensions. Extensions trust these.
const ENV_USER_ID: &str = "ACT_USER_ID";
const ENV_DATABASE_URL: &str = "ACT_DATABASE_URL";

fn cli() -> Command {
    Command::new(TOOL_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authenticated, RBAC-gated CLI host for arium.")
        .long_about(
            "Built-in subcommands are dispatched directly. Any unrecognized \
             subcommand is forwarded to an executable named `act-<sub>` on \
             PATH — but only after `-u` / `-p` authenticate against the \
             arium DB and the user proves the `admin` role.",
        )
        .subcommand_required(false)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .value_name("USERNAME_OR_EMAIL")
                .help("Identifier for the operator (also reads ACT_USER env)."),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help(
                    "Password (also reads ACT_PASSWORD env). \
                     Prompted interactively if absent on a TTY.",
                ),
        )
        .arg(
            Arg::new("database-url")
                .long("database-url")
                .value_name("URL")
                .help("Overrides the DATABASE_URL env var."),
        )
        .arg(
            Arg::new("bootstrap")
                .long("bootstrap")
                .help(
                    "Skip the auth gate for a freshly initialized DB. \
                     Intended for `act db migrate` against an empty store \
                     where no admin exists yet. Refuses to run once any \
                     user with the `admin` permission exists.",
                )
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("extensions")
                .about("List `act-*` extensions discovered on PATH.")
                .arg(
                    Arg::new("paths")
                        .long("paths")
                        .help("Print the full path of each extension binary.")
                        .action(ArgAction::SetTrue),
                ),
        )
}

fn main() -> ExitCode {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("extensions", sub)) => {
            // Built-in: read-only PATH inspection, no auth required.
            let show_paths = sub.get_flag("paths");
            let found = extensions::discover(TOOL_NAME);
            if found.is_empty() {
                eprintln!("No `{TOOL_NAME}-*` extensions found on PATH.");
                return ExitCode::from(0);
            }
            for ext in found {
                if show_paths {
                    println!("{TOOL_NAME}-{}\t{}", ext.name, ext.path.display());
                } else {
                    println!("{TOOL_NAME}-{}", ext.name);
                }
            }
            ExitCode::from(0)
        }
        Some((external, sub)) => {
            // External subcommand — auth + admin-gate, then dispatch.
            let extra: Vec<OsString> = sub
                .get_many::<OsString>("")
                .map(|v| v.cloned().collect())
                .unwrap_or_default();
            let database_url = match resolve_database_url(&matches) {
                Ok(url) => url,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let bootstrap = matches.get_flag("bootstrap");

            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: tokio runtime: {e}");
                    return ExitCode::from(1);
                }
            };

            let gate_result = rt.block_on(run_gate(&matches, &database_url, external, bootstrap));
            // Drop the runtime so we go back to a single thread before
            // exec'ing — keeps the process state predictable.
            drop(rt);

            let user_id = match gate_result {
                Ok(id) => id,
                Err(code) => return code,
            };

            let env_overrides = vec![
                (ENV_USER_ID.to_string(), user_id.to_string()),
                (ENV_DATABASE_URL.to_string(), database_url),
            ];
            extensions::dispatch(TOOL_NAME, external, &extra, &env_overrides)
        }
        None => {
            let _ = cli().print_help();
            println!();
            ExitCode::from(2)
        }
    }
}

/// Returns the authenticated admin user id, or an ExitCode to bubble up.
async fn run_gate(
    matches: &clap::ArgMatches,
    database_url: &str,
    subcommand: &str,
    bootstrap: bool,
) -> Result<i64, ExitCode> {
    let pool = match build_pool(database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: connect to {database_url}: {e}");
            return Err(ExitCode::from(1));
        }
    };

    if bootstrap {
        // The bootstrap escape hatch is only honored against an empty store.
        // Once any user holds the `admin` permission, refuse so this can't
        // become a backdoor on a real deployment.
        if has_any_admin(&pool).await.unwrap_or(false) {
            eprintln!(
                "error: --bootstrap refused; an admin already exists. \
                 Authenticate with -u/-p instead."
            );
            return Err(ExitCode::from(1));
        }
        // user_id = 0 is reserved/sentinel — extensions that audit will use
        // this as actor_id, distinguishable from real users (which start at 1).
        return Ok(0);
    }

    let identifier = match resolve_identifier(matches) {
        Some(id) => id,
        None => {
            eprintln!(
                "error: -u/--user is required (or set ACT_USER) when \
                 dispatching to an extension. \
                 Run `act extensions` to list installed commands without auth."
            );
            return Err(ExitCode::from(2));
        }
    };

    let password = match resolve_password(matches) {
        Ok(pw) => pw,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::from(2));
        }
    };

    match arium::auth::verify_password_by_identifier(&pool, &identifier, &password).await {
        Ok(VerifyOutcome::Verified(uid)) => {
            // Verified user — now check that they hold the `admin` role.
            let role_ids = match arium::auth::get_user_role_ids(&pool, uid).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: load roles: {e}");
                    return Err(ExitCode::from(1));
                }
            };
            if !role_ids.contains(&ADMIN_ROLE_ID) {
                audit::gate_denied(&pool, uid, subcommand).await;
                eprintln!("error: admin role required");
                return Err(ExitCode::from(1));
            }
            audit::session_started(&pool, uid, subcommand).await;
            Ok(uid)
        }
        Ok(VerifyOutcome::Unverified) => {
            audit::login_failed(&pool, &identifier, subcommand).await;
            eprintln!("error: account email not verified");
            Err(ExitCode::from(1))
        }
        Ok(VerifyOutcome::Invalid) => {
            audit::login_failed(&pool, &identifier, subcommand).await;
            eprintln!("error: authentication failed");
            Err(ExitCode::from(1))
        }
        Err(e) => {
            eprintln!("error: verify: {e}");
            Err(ExitCode::from(1))
        }
    }
}

fn resolve_identifier(matches: &clap::ArgMatches) -> Option<String> {
    if let Some(u) = matches.get_one::<String>("user") {
        return Some(u.clone());
    }
    std::env::var("ACT_USER").ok().filter(|s| !s.is_empty())
}

fn resolve_password(matches: &clap::ArgMatches) -> anyhow::Result<String> {
    if let Some(p) = matches.get_one::<String>("password") {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("ACT_PASSWORD")
        && !p.is_empty()
    {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no password supplied — pass -p/--password, set ACT_PASSWORD, \
             or run on a TTY for an interactive prompt"
        );
    }
    Ok(rpassword::prompt_password("Password: ")?)
}

fn resolve_database_url(matches: &clap::ArgMatches) -> anyhow::Result<String> {
    if let Some(u) = matches.get_one::<String>("database-url") {
        return Ok(u.clone());
    }
    if let Ok(u) = std::env::var("DATABASE_URL")
        && !u.is_empty()
    {
        return Ok(u);
    }
    #[cfg(feature = "sqlite")]
    {
        Ok("sqlite://./auth.db?mode=rwc".to_string())
    }
    #[cfg(not(feature = "sqlite"))]
    {
        anyhow::bail!("no database URL (use --database-url or DATABASE_URL)")
    }
}

#[cfg(feature = "sqlite")]
async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;

    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

#[cfg(feature = "postgres")]
async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;

    let opts = sqlx::postgres::PgConnectOptions::from_str(url)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

/// Returns true if any user holds the canonical `admin` role
/// (`arium::auth::role::ADMIN`). Used to refuse `--bootstrap` once the
/// install is past initial setup.
///
/// Uses only public arium APIs (no SQL): pages `list_users_for_admin`
/// in 200-row chunks and probes each user's role list. For a brand-new
/// install this stops at the first user; for an established install with
/// at least one admin it stops at the first admin. The worst case (a
/// large install with NO admins at all) iterates everyone — but in that
/// case `--bootstrap` would have legitimately succeeded anyway.
async fn has_any_admin(pool: &Pool) -> anyhow::Result<bool> {
    let chunk: i64 = 200;
    let mut offset: i64 = 0;
    loop {
        let users = arium::auth::list_users_for_admin(pool, chunk, offset).await?;
        if users.is_empty() {
            return Ok(false);
        }
        for u in &users {
            let roles = arium::auth::get_user_role_ids(pool, u.id).await?;
            if roles.contains(&ADMIN_ROLE_ID) {
                return Ok(true);
            }
        }
        if (users.len() as i64) < chunk {
            return Ok(false);
        }
        offset += chunk;
    }
}
