use axum::{
    extract::{Query, State},
    Json,
};
use tracing::info;

use crate::api::dto::{
    RegisterRequest, LoginRequest, LoginResponse, GoogleCallbackQuery, 
    GoogleAuthResponse, ConnectWalletRequest, NonceRequest, NonceResponse, UserResponse,
    RefreshTokenRequest, RefreshTokenResponse, RevokeTokenRequest, RevokeTokenResponse
};
use crate::api::middleware::AuthenticatedUser;
use crate::handlers::AppState;

pub async fn register_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, String> {
    // Input validation
    if request.email.is_empty() || request.password.is_empty() ||
       request.first_name.is_empty() || request.last_name.is_empty() {
        return Err("All fields are required".to_string());
    }

    // Delegate to application service
    let response = app_state.auth_service.register(
        &request.email,
        &request.password,
        &request.first_name,
        &request.last_name,
    )
    .await
    .map_err(|e| format!("Registration failed: {:?}", e))?;

    info!("User registered: {}", request.email);
    Ok(Json(response))
}

pub async fn login_handler(
    State(app_state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, String> {
    let response = app_state.auth_service.login(&request.email, &request.password)
        .await
        .map_err(|e| format!("Login failed: {:?}", e))?;

    info!("User logged in: {}", request.email);
    Ok(Json(response))
}

pub async fn refresh_token_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, String> {
    let response = app_state.auth_service.refresh_token(&request.refresh_token)
        .await
        .map_err(|e| format!("Token refresh failed: {:?}", e))?;

    info!("Token refreshed successfully");
    Ok(Json(response))
}

pub async fn revoke_token_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<Json<RevokeTokenResponse>, String> {
    app_state.auth_service.revoke_token(&request.refresh_token)
        .await
        .map_err(|e| format!("Token revocation failed: {:?}", e))?;

    info!("Token revoked successfully");
    Ok(Json(RevokeTokenResponse {
        message: "Token revoked successfully".to_string(),
    }))
}

pub async fn revoke_all_tokens_handler(
    State(app_state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<RevokeTokenResponse>, String> {
    app_state.auth_service.revoke_all_user_tokens(&user.user_id.to_string())
        .await
        .map_err(|e| format!("Token revocation failed: {:?}", e))?;

    info!("All tokens revoked for user: {}", user.user_id);
    Ok(Json(RevokeTokenResponse {
        message: "All tokens revoked successfully".to_string(),
    }))
}

pub async fn google_auth_handler() -> Json<GoogleAuthResponse> {
    let (auth_url, _csrf_token) = crate::application::services::AuthService::google_auth_url();
    Json(GoogleAuthResponse { auth_url })
}

pub async fn google_callback_handler(
    State(app_state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Json<LoginResponse>, String> {
    let response = app_state.auth_service.google_callback(&query.code, &query.state)
        .await
        .map_err(|e| format!("Google callback failed: {:?}", e))?;

    info!("Google OAuth callback successful");
    Ok(Json(response))
}

pub async fn connect_wallet_handler(
    State(app_state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(request): Json<ConnectWalletRequest>,
) -> Result<Json<UserResponse>, String> {
    let user = app_state.auth_service.connect_wallet(Some(authenticated_user.user_id), request)
        .await
        .map_err(|e| format!("Wallet connection failed: {:?}", e))?;

    info!("Wallet connected: {}", user.wallet_address.as_ref().unwrap_or(&"unknown".to_string()));
    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        username: user.username,
        wallet_address: user.wallet_address,
        is_verified: user.is_verified,
        created_at: user.created_at,
    }))
}

pub async fn get_nonce_handler(
    State(app_state): State<AppState>,
    Json(request): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, String> {
    let nonce = app_state.auth_service.create_nonce(&request.wallet_address)
        .await
        .map_err(|e| format!("Nonce creation failed: {:?}", e))?;

    info!("Nonce created for wallet: {}", request.wallet_address);
    Ok(Json(NonceResponse { nonce }))
}