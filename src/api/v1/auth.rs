use axum::{
    extract::{Query, State},
    Json,
};
use tracing::info;

use crate::api::dto::{
    RegisterRequest, LoginRequest, LoginResponse, GoogleCallbackQuery, 
    GoogleAuthResponse, ConnectWalletRequest, NonceRequest, NonceResponse, UserResponse
};
use crate::api::middleware::AuthenticatedUser;
use crate::application::services::AuthService;

pub async fn register_handler(
    State(auth_service): State<AuthService>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, String> {
    // Input validation
    if request.email.is_empty() || request.password.is_empty() ||
       request.first_name.is_empty() || request.last_name.is_empty() {
        return Err("All fields are required".to_string());
    }

    // Delegate to application service
    let response = auth_service.register(
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
    State(auth_service): State<AuthService>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, String> {
    let response = auth_service.login(&request.email, &request.password)
        .await
        .map_err(|e| format!("Login failed: {:?}", e))?;

    info!("User logged in: {}", request.email);
    Ok(Json(response))
}

pub async fn google_auth_handler() -> Json<GoogleAuthResponse> {
    let (auth_url, _csrf_token) = AuthService::google_auth_url();
    Json(GoogleAuthResponse { auth_url })
}

pub async fn google_callback_handler(
    State(auth_service): State<AuthService>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Json<LoginResponse>, String> {
    let response = auth_service.google_callback(&query.code, &query.state)
        .await
        .map_err(|e| format!("Google OAuth failed: {:?}", e))?;

    info!("User authenticated via Google");
    Ok(Json(response))
}

pub async fn connect_wallet_handler(
    State(auth_service): State<AuthService>,
    authenticated_user: AuthenticatedUser,
    Json(request): Json<ConnectWalletRequest>,
) -> Result<Json<UserResponse>, String> {
    let user = auth_service.connect_wallet(Some(authenticated_user.user_id), request)
        .await
        .map_err(|e| format!("Wallet connection failed: {:?}", e))?;

    info!("Wallet connected: {}", user.wallet_address.as_deref().unwrap_or(""));

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

pub async fn nonce_handler(
    State(auth_service): State<AuthService>,
    Json(request): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, String> {
    let nonce = auth_service.create_nonce(&request.wallet_address)
        .await
        .map_err(|e| format!("Nonce creation failed: {:?}", e))?;

    info!("Nonce created for wallet: {}", request.wallet_address);
    Ok(Json(NonceResponse { nonce }))
}