//! REST and WebSocket API server for client connections.
//!
//! Composes all routes into a single Axum application with:
//! - Public endpoints (no auth)
//! - Authenticated endpoints (Klever wallet signature)
//! - WebSocket endpoints (auth + public read-only)
//! - Admin endpoints (localhost-only)

pub mod admin;
pub mod auth;
pub mod dashboard;
pub mod routes;
pub mod state;
pub mod websocket;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::Config;

use self::state::AppState;

/// Build and start the API server.
pub async fn start_api_server(
    config: &Config,
    app_state: Arc<AppState>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let app = build_router(config, app_state);

    let addr: SocketAddr = format!(
        "{}:{}",
        config.api.listen_addr, config.api.listen_port
    )
    .parse()
    .context("parsing API listen address")?;

    info!(addr = %addr, "API server starting");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("binding API listener")?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.recv().await;
        info!("API server shutting down");
    })
    .await
    .context("running API server")?;

    Ok(())
}

/// Build the full Axum router with all route groups.
fn build_router(config: &Config, app_state: Arc<AppState>) -> Router {
    // CORS configuration
    let cors = build_cors(&config.api.cors_origins);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/v1/health", get(routes::health))
        .route("/api/v1/network/stats", get(routes::network_stats))
        .route("/api/v1/network/nodes", get(routes::network_nodes))
        .route("/api/v1/channels", get(routes::list_channels))
        .route("/api/v1/channels/{channel_id}", get(routes::get_channel))
        .route(
            "/api/v1/channels/{channel_id}/messages",
            get(routes::get_channel_messages),
        )
        .route("/api/v1/users/{address}", get(routes::get_user))
        .route("/api/v1/users/{address}/followers", get(routes::get_followers))
        .route("/api/v1/users/{address}/following", get(routes::get_following))
        .route("/api/v1/news", get(routes::list_news))
        .route(
            "/api/v1/news/{msg_id}/reactions",
            get(routes::get_news_reactions),
        )
        .route(
            "/api/v1/news/{msg_id}/reposts",
            get(routes::get_news_reposts),
        )
        .route(
            "/api/v1/channels/{channel_id}/members",
            get(routes::get_channel_members),
        )
        .route(
            "/api/v1/channels/{channel_id}/pins",
            get(routes::get_channel_pins),
        )
    // Authenticated routes (Klever wallet signature required)
    let auth_routes = Router::new()
        .route("/api/v1/messages", post(routes::post_message))
        .route("/api/v1/profile", put(routes::update_profile))
        .route("/api/v1/dm/{address}", post(routes::send_dm))
        .route("/api/v1/users/{address}/follow", post(routes::follow_user).delete(routes::unfollow_user))
        .route("/api/v1/feed", get(routes::personal_feed))
        // News engagement
        .route(
            "/api/v1/news/{msg_id}/react",
            post(routes::react_to_news),
        )
        .route(
            "/api/v1/news/{msg_id}/repost",
            post(routes::repost_news),
        )
        // Bookmarks
        .route("/api/v1/bookmarks", get(routes::list_bookmarks))
        .route(
            "/api/v1/bookmarks/{msg_id}",
            post(routes::save_bookmark).delete(routes::remove_bookmark),
        )
        // Channel bans (auth-gated — moderator/creator only, per spec)
        .route(
            "/api/v1/channels/{channel_id}/bans",
            get(routes::get_channel_bans),
        )
        // Channel administration
        .route(
            "/api/v1/channels/{channel_id}/moderators",
            post(routes::add_moderator),
        )
        .route(
            "/api/v1/channels/{channel_id}/moderators/{address}",
            delete(routes::remove_moderator),
        )
        .route(
            "/api/v1/channels/{channel_id}/kick/{address}",
            post(routes::kick_user),
        )
        .route(
            "/api/v1/channels/{channel_id}/ban/{address}",
            post(routes::ban_user).delete(routes::unban_user),
        )
        .route(
            "/api/v1/channels/{channel_id}/pin/{msg_id}",
            post(routes::pin_message).delete(routes::unpin_message),
        )
        .route(
            "/api/v1/channels/{channel_id}/invite/{address}",
            post(routes::invite_user),
        )
        .layer(middleware::from_fn(auth::auth_middleware));

    // WebSocket routes
    let ws_routes = Router::new()
        .route("/api/v1/ws", get(websocket::ws_authenticated))
        .route("/api/v1/ws/public", get(websocket::ws_public));

    // Admin routes (localhost-only via middleware)
    let admin_routes = if config.api.admin.enabled {
        let mut routes = Router::new()
            .route("/admin/peers", get(admin::list_peers))
            .route("/admin/storage/stats", get(admin::storage_stats))
            .route("/admin/peers/ban", post(admin::ban_peer))
            .route("/admin/channels/pin", post(admin::pin_channel))
            .route("/admin/state/latest", get(admin::state_latest))
            .route("/admin/state/anchor", post(admin::trigger_anchor));

        // Dashboard (if enabled in config)
        if config.api.admin.dashboard {
            routes = routes
                .route("/admin/dashboard", get(dashboard::dashboard_page))
                .route("/admin/dashboard/ws", get(dashboard::dashboard_ws));
        }

        routes.layer(middleware::from_fn(admin::localhost_only))
    } else {
        Router::new()
    };

    // Compose all routes with body size limit (1 MB)
    Router::new()
        .merge(public_routes)
        .merge(auth_routes)
        .merge(ws_routes)
        .merge(admin_routes)
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(axum::Extension(app_state))
}

/// Build CORS layer from configured origins.
fn build_cors(origins: &[String]) -> CorsLayer {
    use tower_http::cors::AllowOrigin;

    if origins.is_empty() || origins.iter().any(|o| o == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let parsed: Vec<axum::http::HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods(Any)
            .allow_headers(Any)
    }
}
