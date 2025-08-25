use axum::{
    middleware,
    Router,
    routing::{get, post, put, delete},
    http::HeaderValue,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::handlers::AppState;
use crate::api::middleware::auth_middleware;
use super::{
    register_handler, login_handler, google_auth_handler, google_callback_handler,
    connect_wallet_handler, get_nonce_handler, profile_handler, update_profile_handler,
    refresh_token_handler, revoke_token_handler, revoke_all_tokens_handler,
    // Contract endpoints
    mint_nft, initiate_social_media_nft_mint, mint_social_media_nft,
    get_network_info, get_supported_chains, check_connection, get_all_collections,
    list_nft, list_non_nft_asset, list_social_media_nft, list_nft_for_auction,
    buy_nft, buy_non_nft_asset, cancel_nft_listing, cancel_non_nft_listing,
    confirm_transfer, raise_dispute, refund,
};

async fn health_check() -> &'static str {
    "OK"
}

pub fn create_v1_router(app_state: AppState) -> Router {
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://0.0.0.0:3000".to_string())
        .split(',')
        .map(|origin| origin.trim().parse::<HeaderValue>().unwrap())
        .collect::<Vec<_>>();

    let cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_origin(allowed_origins)
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(true);


    // Auth routes
    let auth_routes = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/revoke", post(revoke_token_handler))
        .route("/google-auth", get(google_auth_handler))
        .route("/google-callback", get(google_callback_handler))
        .route("/nonce", post(get_nonce_handler));

    // User routes
    let user_routes = Router::new()
        .route("/profile", get(profile_handler))
        .route("/update-profile", put(update_profile_handler))
        .route("/connect-wallet", post(connect_wallet_handler))
        .route("/revoke-all", delete(revoke_all_tokens_handler))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    // Contract routes
    let contract_routes = Router::new()
        // Public contract endpoints
        .route("/network-info", get(get_network_info))
        .route("/supported-chains", get(get_supported_chains))
        .route("/check-connection", get(check_connection))
        .route("/collections", get(get_all_collections))
        // NFT endpoints (public - wallet-based authentication)
        .route("/mint-nft", post(mint_nft))
        .route("/initiate-social-media-nft-mint", post(initiate_social_media_nft_mint))
        .route("/mint-social-media-nft", post(mint_social_media_nft))
        .route("/list-nft", post(list_nft))
        .route("/list-social-media-nft", post(list_social_media_nft))
        .route("/list-nft-for-auction", post(list_nft_for_auction))
        .route("/buy-nft", post(buy_nft))
        .route("/buy-non-nft-asset", post(buy_non_nft_asset))
        .route("/cancel-nft-listing", post(cancel_nft_listing))
        // Protected contract endpoints
        .route("/list-non-nft-asset", post(list_non_nft_asset))
        .route("/cancel-non-nft-listing", post(cancel_non_nft_listing))
        .route("/confirm-transfer", post(confirm_transfer))
        .route("/raise-dispute", post(raise_dispute))
        .route("/refund", post(refund));

    // Health check route
    let health_route = Router::new()
        .route("/health", get(health_check));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/users", user_routes)
        .nest("/contracts", contract_routes)
        .merge(health_route)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}