use axum::{
    middleware,
    Router,
    routing::{get, post, put},
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

use crate::application::services::AuthService;
use crate::api::middleware::auth_middleware;
use super::{
    register_handler, login_handler, google_auth_handler, google_callback_handler,
    connect_wallet_handler, nonce_handler, profile_handler, update_profile_handler,
    // Contract endpoints
    mint_nft, initiate_social_media_nft_mint, mint_social_media_nft,
    get_network_info, check_connection,
};

async fn health_check() -> &'static str {
    "OK"
}

pub fn create_v1_router(auth_service: AuthService) -> Router {
    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/google-auth", get(google_auth_handler))
        .route("/google-callback", get(google_callback_handler))
        .route("/nonce", post(nonce_handler))
        .route("/health", get(health_check))
        // Contract utility endpoints (public)
        .route("/contracts/network-info", get(get_network_info))
        .route("/contracts/check-connection", get(check_connection))
        // NFT endpoints (public - wallet-based authentication)
        .route("/contracts/mint-nft", post(mint_nft))
        .route("/contracts/initiate-social-media-nft-mint", post(initiate_social_media_nft_mint))
        .route("/contracts/mint-social-media-nft", post(mint_social_media_nft));

    // Protected routes (authentication required)
    let protected_routes = Router::new()
        .route("/profile", get(profile_handler))
        .route("/update-profile", put(update_profile_handler))
        .route("/connect-wallet", post(connect_wallet_handler))
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth_middleware,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(auth_service)
}