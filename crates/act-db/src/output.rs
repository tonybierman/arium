use anyhow::Context;
use arium::auth::AdminUserRow;
use serde::Serialize;
use std::io::Write;

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Human,
    Json,
}

/// Serde-friendly view of `AdminUserRow`, which is `FromRow`-derived but
/// doesn't carry a `Serialize` impl. Local to act-db so arium's public
/// surface doesn't grow a derive for our convenience.
#[derive(Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub email_verified_at: Option<i64>,
    pub mfa_enabled_at: Option<i64>,
    pub anonymous: bool,
}

impl From<&AdminUserRow> for UserView {
    fn from(u: &AdminUserRow) -> Self {
        UserView {
            id: u.id,
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            email: u.email.clone(),
            email_verified_at: u.email_verified_at,
            mfa_enabled_at: u.mfa_enabled_at,
            anonymous: u.anonymous,
        }
    }
}

pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value).context("json render")?;
    out.write_all(b"\n")?;
    Ok(())
}
