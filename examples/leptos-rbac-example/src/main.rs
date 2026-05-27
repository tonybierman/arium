//! SSR server for the Leptos global-RBAC demo. Wires the arium engine
//! (`arium_leptos::install`) onto the axum router that serves the Leptos app +
//! server-fn endpoints, and seeds the demo `editor` role the toggle grants.
//!
//! Unlike the membership demo there is no `ResourceAuthority` to register —
//! global RBAC reads the session's own permission set, not any app-supplied
//! per-resource lookup.

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use axum::Router;
    use axum::routing::post;
    use leptos::config::get_configuration;
    use leptos::prelude::*;
    use leptos_axum::{
        LeptosRoutes, file_and_error_handler, generate_route_list, handle_server_fns,
    };
    use leptos_rbac_example::app::App;
    use leptos_rbac_example::app::{CAP_PUBLISH, DEMO_ROLE};
    use leptos_rbac_example::shell;

    // Dev SQLite DB under the workspace `target/` dir (gitignored), unless
    // DATABASE_URL is set. arium owns this schema; the migrator creates it.
    let pool = {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr;

        let connect_opts = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => SqliteConnectOptions::from_str(&url)?,
            _ => SqliteConnectOptions::new()
                .filename(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../target/rbac-leptos.db"
                ))
                .create_if_missing(true),
        };
        SqlitePoolOptions::new()
            .max_connections(20)
            .connect_with(connect_opts)
            .await?
    };
    arium_leptos::migrator().run(&pool).await?;

    // Seed the demo role (idempotent across restarts). This is the only
    // RBAC-specific setup: a role that carries the capability token. arium
    // already seeds `admin` / `member` / `guest`; every new account gets
    // `member`, which carries no tokens — so a fresh user starts with the gate
    // closed until they grant themselves `editor` via the toggle.
    let roles = arium_leptos::auth::list_roles(&pool).await?;
    if !roles.iter().any(|r| r.name == DEMO_ROLE) {
        arium_leptos::auth::create_role(
            &pool,
            DEMO_ROLE,
            Some("Demo role: may publish the newsletter"),
            &[CAP_PUBLISH.to_string()],
        )
        .await?;
    }

    let cfg = arium_leptos::AuthConfig::builder(pool).build()?;

    let conf = get_configuration(None)?;
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let app = Router::new()
        .route("/api/{*fn_name}", post(handle_server_fns))
        .leptos_routes(&leptos_options, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(file_and_error_handler::<LeptosOptions, _>(shell))
        .with_state(leptos_options.clone());

    // `install` layers AuthSessionLayer + SessionLayer (+ the Pool / Providers
    // extensions) over the whole router.
    let app = arium_leptos::install(app, cfg).await?;

    let addr = leptos_options.site_addr;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[startup] listening on http://{addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
fn main() {}
