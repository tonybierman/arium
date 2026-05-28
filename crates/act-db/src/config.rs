use anyhow::Context;
use arium::pool::Pool;

pub fn parse_actor_id() -> anyhow::Result<i64> {
    let raw = std::env::var("ACT_USER_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .context("missing ACT_USER_ID; act-db must be invoked via `act`")?;
    raw.parse::<i64>().context("ACT_USER_ID is not a number")
}

pub fn resolve_database_url() -> anyhow::Result<String> {
    if let Ok(u) = std::env::var("ACT_DATABASE_URL")
        && !u.is_empty()
    {
        return Ok(u);
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
        anyhow::bail!("no database URL (set ACT_DATABASE_URL or DATABASE_URL)")
    }
}

#[cfg(feature = "sqlite")]
pub async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;
    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url)?;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}

#[cfg(feature = "postgres")]
pub async fn build_pool(url: &str) -> anyhow::Result<Pool> {
    use std::str::FromStr;
    let opts = sqlx::postgres::PgConnectOptions::from_str(url)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;
    Ok(pool)
}
