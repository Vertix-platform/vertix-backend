use axum::{
    middleware,
    Router,
    routing::{get, post, put},
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

use crate::handlers::AppState;
use crate::api::middleware::auth_middleware;
use super::{
    register_handler, login_handler, google_auth_handler, google_callback_handler,
    connect_wallet_handler, nonce_handler, profile_handler, update_profile_handler,
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
    // Public routes
    let public_routes = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/google-auth", get(google_auth_handler))
        .route("/google-callback", get(google_callback_handler))
        .route("/nonce", post(nonce_handler))
        .route("/health", get(health_check))
        // Contract utility endpoints (public)
        .route("/contracts/network-info", get(get_network_info))
        .route("/contracts/supported-chains", get(get_supported_chains))
        .route("/contracts/check-connection", get(check_connection))
        .route("/contracts/collections", get(get_all_collections))
        // NFT endpoints (public - wallet-based authentication)
        .route("/contracts/mint-nft", post(mint_nft))
        .route("/contracts/initiate-social-media-nft-mint", post(initiate_social_media_nft_mint))
        .route("/contracts/mint-social-media-nft", post(mint_social_media_nft))
        .route("/contracts/list-nft", post(list_nft))
        .route("/contracts/list-social-media-nft", post(list_social_media_nft))
        .route("/contracts/list-nft-for-auction", post(list_nft_for_auction))
        .route("/contracts/buy-nft", post(buy_nft))
        .route("/contracts/buy-non-nft-asset", post(buy_non_nft_asset))
        .route("/contracts/cancel-nft-listing", post(cancel_nft_listing));

    // Protected routes
    let protected_routes = Router::new()
        .route("/profile", get(profile_handler))
        .route("/update-profile", put(update_profile_handler))
        .route("/connect-wallet", post(connect_wallet_handler))
        // Non-NFT listing (requires user authentication + wallet connection)
        .route("/contracts/list-non-nft-asset", post(list_non_nft_asset))
        .route("/contracts/cancel-non-nft-listing", post(cancel_non_nft_listing))
        .route("/contracts/confirm-transfer", post(confirm_transfer))
        .route("/contracts/raise-dispute", post(raise_dispute))
        .route("/contracts/refund", post(refund))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}