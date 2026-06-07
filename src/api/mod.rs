//! REST and WebSocket API server for client connections.
//!
//! Composes all routes into a single Axum application with:
//! - Public endpoints (no auth)
//! - Authenticated endpoints (Klever wallet signature)
//! - WebSocket endpoints (auth + public read-only)
//! - Admin endpoints (localhost-only)

pub mod admin;
pub mod admin_auth;
pub mod auth;
pub mod dashboard;
pub mod media_fallback;
pub mod media_limiter;
pub mod rate_limit_key;
pub mod routes;
pub mod state;
pub mod websocket;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
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
        // v0.45.0 — spec 13 §4.5: SC-derived bootstrap discovery for
        // SDK clients and new nodes. Public, 5-min cache.
        .route(
            "/api/v1/network/discovery/bootstrap-candidates",
            get(routes::network_bootstrap_candidates),
        )
        // v0.48.0 — spec 13 §10.6 / spec 03 §4.1: presence-gossip
        // surface (off-chain service-provider discovery). All three
        // endpoints are public; the cache is in-memory only.
        .route("/api/v1/network/identity", get(routes::network_identity))
        .route("/api/v1/network/presence", get(routes::network_presence))
        .route(
            "/api/v1/network/presence/{peer_id}",
            get(routes::network_presence_by_peer),
        )
        // /users/search must be registered BEFORE /users/{address} so axum
        // matches the literal segment first instead of treating "search"
        // as an address parameter.
        .route("/api/v1/users/search", get(routes::search_users))
        .route("/api/v1/users/{address}", get(routes::get_user))
        .route("/api/v1/users/{address}/followers", get(routes::get_followers))
        .route("/api/v1/users/{address}/following", get(routes::get_following))
        .route("/api/v1/news", get(routes::list_news))
        .route("/api/v1/news/{msg_id}", get(routes::get_news_post))
        .route(
            "/api/v1/news/{msg_id}/reposts",
            get(routes::get_news_reposts),
        )
        // GET and HEAD share the same handler; the handler inspects the
        // method extractor and elides the body for HEAD. RFC 9110 §9.3.2:
        // HEAD must produce the same headers as GET, no body.
        .route(
            "/api/v1/media/{cid}",
            get(routes::get_media).head(routes::get_media),
        )
        .route(
            "/api/v1/users/{address}/posts",
            get(routes::get_user_posts),
        )
        .route(
            "/api/v1/moderation/reports",
            get(routes::get_moderation_reports),
        )
        .route(
            "/api/v1/moderation/user/{address}",
            get(routes::get_user_moderation),
        );

    // Routes that optionally benefit from auth (e.g. filtering private channels)
    let optional_auth_routes = Router::new()
        .route("/api/v1/channels", get(routes::list_channels))
        .route("/api/v1/channels/by-slug/{slug}", get(routes::channel_by_slug))
        .route("/api/v1/channels/{channel_id}", get(routes::get_channel))
        .route(
            "/api/v1/channels/{channel_id}/messages",
            get(routes::get_channel_messages),
        )
        .route(
            "/api/v1/channels/{channel_id}/members",
            get(routes::get_channel_members),
        )
        .route(
            "/api/v1/channels/{channel_id}/pins",
            get(routes::get_channel_pins),
        )
        .route(
            "/api/v1/news/{msg_id}/reactions",
            get(routes::get_news_reactions),
        )
        .layer(middleware::from_fn(auth::optional_auth_middleware));

    // Authenticated routes (Klever wallet signature required)
    let auth_routes = Router::new()
        .route("/api/v1/notifications", get(routes::get_notifications))
        .route("/api/v1/messages", post(routes::post_message))
        .route("/api/v1/profile", put(routes::update_profile))
        .route("/api/v1/channels", post(routes::create_channel))
        .route("/api/v1/channels/{channel_id}", delete(routes::delete_channel))
        .route("/api/v1/dm/conversations", get(routes::get_dm_conversations))
        .route("/api/v1/dm/unread", get(routes::get_dm_unread_counts))
        .route("/api/v1/dm/{address}", post(routes::send_dm))
        .route("/api/v1/dm/{address}/messages", get(routes::get_dm_messages))
        .route("/api/v1/dm/{address}/read", post(routes::mark_dm_read))
        .route("/api/v1/users/{address}/follow", post(routes::follow_user).delete(routes::unfollow_user))
        // Device encryption-key directory (protocol §2.4). GET = fetch a wallet's
        // active enc keys; POST = submit a signed DeviceEncBinding/Revoke envelope
        // (routed through the standard message pipeline so it gossips + indexes).
        .route(
            "/api/v1/users/{address}/enc-keys",
            get(routes::get_enc_keys).post(routes::post_message),
        )
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
        // Channel read state
        .route(
            "/api/v1/channels/{channel_id}/read",
            post(routes::mark_channel_read),
        )
        .route("/api/v1/channels/unread", get(routes::get_unread_counts))
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
        // Private channel key distribution
        .route(
            "/api/v1/channels/{channel_id}/keys",
            get(routes::get_channel_keys).post(routes::distribute_channel_keys),
        )
        .route("/api/v1/media/upload", post(routes::upload_media))
        // Device identity management
        .route("/api/v1/devices/register", post(routes::register_device))
        .route(
            "/api/v1/devices/{device_address}",
            delete(routes::revoke_device),
        )
        .route("/api/v1/devices", get(routes::list_devices))
        // Settings sync
        .route("/api/v1/settings", get(routes::get_settings))
        // Account data export
        .route("/api/v1/account/export", get(routes::export_account))
        .layer(middleware::from_fn(auth::auth_middleware));

    // PoW anti-spam endpoints (public — unauthenticated)
    let pow_routes = Router::new()
        .route("/api/v1/pow/challenge", post(routes::pow_challenge))
        .route("/api/v1/pow/verify", post(routes::pow_verify));

    // WebSocket routes
    let ws_routes = Router::new()
        .route("/api/v1/ws", get(websocket::ws_authenticated))
        .route("/api/v1/ws/public", get(websocket::ws_public));

    // Admin auth state (shared between middleware and auth endpoints).
    // Passes app_state.trusted_proxies so the localhost-bypass works when
    // operators reverse-proxy through Docker (peer IP = bridge gateway,
    // not loopback). See admin_auth_middleware doc.
    let admin_auth_state = std::sync::Arc::new(admin_auth::AdminAuthState::new(
        config.api.admin.admin_wallets.clone(),
        config.api.admin.session_ttl_hours,
        app_state.node_id.clone(),
        app_state.trusted_proxies.clone(),
    ));

    // Admin routes (localhost + wallet auth via middleware)
    let admin_routes = if config.api.admin.enabled {
        // Public admin routes — no auth required (login page + auth endpoints).
        // The dashboard HTML must load without auth so it can show the login screen.
        let mut public_admin = Router::new()
            .route("/admin/auth/challenge", get(admin_auth::auth_challenge))
            .route("/admin/auth/login", post(admin_auth::auth_login))
            .route("/admin/auth/logout", post(admin_auth::auth_logout));

        if config.api.admin.dashboard {
            public_admin = public_admin
                .route("/admin/dashboard", get(dashboard::dashboard_page));
        }

        let public_admin = public_admin
            .layer(axum::Extension(admin_auth_state.clone()));

        // Protected admin routes — require localhost or valid session token.
        let mut protected = Router::new()
            .route("/admin/peers", get(admin::list_peers))
            .route("/admin/storage/stats", get(admin::storage_stats))
            .route("/admin/peers/ban", post(admin::ban_peer))
            .route("/admin/channels/pin", post(admin::pin_channel))
            .route("/admin/state/latest", get(admin::state_latest))
            .route("/admin/state/anchor", post(admin::trigger_anchor))
            .route("/admin/node/registration", get(admin::node_registration))
            // v0.45.0 — spec 12 §2.10 + §2.11 operator surface.
            // All four return Klever-extension calldata; no node-side
            // SC signing happens here. See admin::node_metadata doc.
            .route("/admin/node/metadata", get(admin::node_metadata))
            .route("/admin/node/pause-status", get(admin::node_pause_status))
            .route("/admin/node/pause", post(admin::node_pause))
            .route("/admin/node/resume", post(admin::node_resume))
            // v0.46.6 — spec 10 §9.2 B4 instrumentation. Per-topic
            // mesh size + subscriber count + cumulative publish-
            // failure counters partitioned by PublishError variant.
            .route("/admin/network/mesh-stats", get(admin::mesh_stats))
            // B4 peer-telemetry (0.48.4): per-peer inbound/outbound
            // connection balance + mesh participation. Diagnoses the
            // asymmetric-mesh case the `mesh_outbound_min = 0` fix
            // tolerates.
            .route("/admin/network/peer-telemetry", get(admin::peer_telemetry));

        if config.api.admin.dashboard {
            protected = protected
                .route("/admin/dashboard/ws", get(dashboard::dashboard_ws))
                .route("/admin/metrics/snapshot", get(dashboard::metrics_snapshot))
                .route("/admin/metrics/history", get(dashboard::metrics_history))
                .route("/admin/metrics/peers", get(dashboard::metrics_peers))
                .route("/admin/metrics/storage", get(dashboard::metrics_storage))
                .route("/admin/metrics/rejections", get(dashboard::metrics_rejections))
                .route("/admin/alerts/history", get(dashboard::alerts_history))
                .route("/admin/snapshot/status", get(dashboard::snapshot_status));
        }

        let protected = protected
            .layer(middleware::from_fn(admin_auth::admin_auth_middleware))
            .layer(axum::Extension(admin_auth_state));

        // Merge public + protected admin routes
        public_admin.merge(protected)
    } else {
        Router::new()
    };

    // IP-based rate limiting: limit total HTTP requests per IP per minute.
    // Uses the `governor` crate via `tower_governor` middleware.
    // v0.48.6: key on the REAL client IP (resolved via trusted_proxies +
    // X-Forwarded-For/Forwarded), not the raw peer IP. Behind a reverse
    // proxy the peer is always the proxy, so the default PeerIpKeyExtractor
    // funnels every client into one shared bucket — on the Apache-fronted
    // production node that saturated the 100/min bucket and 429'd every
    // request (including login). Reuses the same resolution as admin_auth
    // so an untrusted direct client still can't spoof its key.
    let rate_limit_per_ip = config.api.rate_limit_per_ip;
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(60_000 / rate_limit_per_ip.max(1) as u64)
            .burst_size(rate_limit_per_ip.max(1))
            .key_extractor(rate_limit_key::TrustedProxyIpKeyExtractor::new(
                app_state.trusted_proxies.clone(),
            ))
            .finish()
            .expect("valid governor config"),
    );

    // Compose all routes with body size limit (10 MB for media uploads)
    Router::new()
        .merge(public_routes)
        .merge(optional_auth_routes)
        .merge(auth_routes)
        .merge(pow_routes)
        .merge(ws_routes)
        .merge(admin_routes)
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(GovernorLayer::new(governor_conf))
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
