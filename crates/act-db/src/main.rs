mod audit;
mod cmd;
mod config;
mod output;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use output::Format;

#[derive(Parser)]
#[command(name = "act-db", version, about = "DB operations for arium.")]
struct Cli {
    /// Render list/show output as JSON instead of human-readable.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run arium's core migrations (and the membership migrator if
    /// `--features membership` was enabled at build time).
    Migrate,

    /// Manage users.
    Users {
        #[command(subcommand)]
        op: UsersOp,
    },

    /// Manage roles.
    Roles {
        #[command(subcommand)]
        op: RolesOp,
    },

    /// Manage API tokens.
    Tokens {
        #[command(subcommand)]
        op: TokensOp,
    },

    /// Query / prune the audit log.
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
}

#[derive(Subcommand)]
pub enum UsersOp {
    /// List users (paginated).
    List {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Show one user by id.
    Show { user_id: i64 },
    /// Create a new password user. Prompts for password if --password is omitted.
    Create {
        email: String,
        #[arg(long)]
        password: Option<String>,
        /// Mark the new user's email as verified immediately.
        #[arg(long)]
        verified: bool,
    },
    /// Soft-delete a user.
    Delete { user_id: i64 },
    /// Mark a user's email as verified.
    Verify { user_id: i64 },
    /// Reset a user's password (chains request_password_reset + consume_password_reset).
    ResetPassword {
        user_id: i64,
        #[arg(long)]
        password: Option<String>,
    },
    /// List a user's role ids and names.
    Roles { user_id: i64 },
    /// Turn MFA off for a user (recovery).
    DisableMfa { user_id: i64 },
}

#[derive(Subcommand)]
pub enum RolesOp {
    /// List all roles.
    List,
    /// Create a role.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "permission", value_name = "PERM")]
        permissions: Vec<String>,
    },
    /// Delete a role.
    Delete { role_id: i64 },
    /// List a role's permissions.
    Permissions { role_id: i64 },
    /// Grant a role to a user (role can be id or name).
    Grant { user_id: i64, role: String },
    /// Revoke a role from a user (role can be id or name).
    Revoke { user_id: i64, role: String },
}

#[derive(Subcommand)]
pub enum TokensOp {
    /// List a user's active tokens.
    List { user_id: i64 },
    /// Mint a new API token for a user. The cleartext is printed once.
    Create { user_id: i64, name: String },
    /// Revoke a token by its id.
    Revoke { user_id: i64, token_id: i64 },
}

#[derive(Subcommand)]
pub enum AuditOp {
    /// Query the audit log.
    Query {
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long)]
        actor_id: Option<i64>,
        #[arg(long)]
        target_id: Option<i64>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Prune events older than the given retention window.
    Prune { retention_days: u64 },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let fmt = if cli.json { Format::Json } else { Format::Human };

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

    let result = rt.block_on(run(cli.cmd, fmt));
    match result {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run(cmd: Cmd, fmt: Format) -> anyhow::Result<()> {
    let url = config::resolve_database_url()?;
    let pool = config::build_pool(&url).await?;

    match cmd {
        Cmd::Migrate => {
            let actor_id = config::parse_actor_id()?;
            cmd::migrate::run(&pool, actor_id).await
        }
        Cmd::Users { op } => {
            let actor_id = config::parse_actor_id()?;
            cmd::users::run(&pool, actor_id, op, fmt).await
        }
        Cmd::Roles { op } => {
            let actor_id = config::parse_actor_id()?;
            cmd::roles::run(&pool, actor_id, op, fmt).await
        }
        Cmd::Tokens { op } => {
            let actor_id = config::parse_actor_id()?;
            cmd::tokens::run(&pool, actor_id, op, fmt).await
        }
        Cmd::Audit { op } => {
            let actor_id = config::parse_actor_id()?;
            cmd::audit::run(&pool, actor_id, op, fmt).await
        }
    }
}

