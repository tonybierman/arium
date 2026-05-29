//! `act-db migrate` — run arium's core migrator (and the membership
//! migrator when the `membership` feature is on). Allowed under
//! `--bootstrap` because by definition there is no schema yet to host
//! an admin row.

use arium::pool::Pool;

use crate::audit;

pub async fn run(pool: &Pool, actor_id: i64) -> anyhow::Result<()> {
    arium::migrator().run(pool).await?;

    #[cfg(feature = "membership")]
    {
        arium::membership_migrator().run(pool).await?;
    }

    audit::record(
        pool,
        actor_id,
        audit::ACT_DB_MIGRATED,
        None,
        serde_json::json!({ "verb": "migrate" }),
    )
    .await;

    println!("migrations applied");
    Ok(())
}
