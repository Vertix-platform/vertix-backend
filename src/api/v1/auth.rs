use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use tracing::info;

use crate::api::dto::{
    RegisterRequest, LoginRequest, GoogleCallbackQuery, 
    ConnectWalletRequest, NonceRequest, NonceResponse, UserResponse,
    RefreshTokenRequest, RevokeTokenRequest, RevokeTokenResponse
};
use crate::api::middleware::AuthenticatedUser;
use crate::api::errors::{ApiResult, ApiError};
use crate::domain::ServiceError;
use crate::handlers::AppState;

pub async fn register_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<impl IntoResponse> {
    // Input validation
    if request.email.is_empty() || request.password.is_empty() ||
       request.first_name.is_empty() || request.last_name.is_empty() {
        return Err(ApiError::BadRequest("All fields are required".to_string()));
    }

    // Delegate to application service
    let response = app_state.auth_service.register(
        &request.email,
        &request.password,
        &request.first_name,
        &request.last_name,
    )
    .await
            .map_err(|e| {
            match e {
                ServiceError::UserAlreadyExists => {
                    ApiError::Conflict("An account with this email already exists.".to_string())
                }
                _ => ApiError::InternalServerError(format!("Registration failed: {}", e))
            }
        })?;

    info!("User registered: {}", request.email);
    Ok(Json(serde_json::json!({
        "success": true,
        "data": response,
        "message": "User registered successfully"
    })))
}

pub async fn login_handler(
    State(app_state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let response = app_state.auth_service.login(&request.email, &request.password)
        .await
        .map_err(|e| {
            match e {
                ServiceError::InvalidCredentials => {
                    ApiError::Unauthorized("Invalid email or password. Please check your credentials and try again.".to_string())
                }
                ServiceError::UserNotFound => {
                    ApiError::NotFound("No account found with this email address. Please create an account first.".to_string())
                }
                _ => ApiError::InternalServerError(format!("Login failed: {}", e))
            }
        })?;

    info!("User logged in: {}", request.email);
    Ok(Json(serde_json::json!({
        "success": true,
        "data": response,
        "message": "Login successful"
    })))
}

pub async fn refresh_token_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> ApiResult<impl IntoResponse> {
    let response = app_state.auth_service.refresh_token(&request.refresh_token)
        .await
        .map_err(|e| {
            match e {
                ServiceError::InvalidRefreshToken => {
                    ApiError::Unauthorized("Invalid refresh token".to_string())
                }
                ServiceError::RefreshTokenExpired => {
                    ApiError::Unauthorized("Refresh token has expired".to_string())
                }
                ServiceError::RefreshTokenRevoked => {
                    ApiError::Unauthorized("Refresh token has been revoked".to_string())
                }
                _ => ApiError::InternalServerError(format!("Token refresh failed: {}", e))
            }
        })?;

    info!("Token refreshed successfully");
    Ok(Json(serde_json::json!({
        "success": true,
        "data": response,
        "message": "Token refreshed successfully"
    })))
}

pub async fn revoke_token_handler(
    State(app_state): State<AppState>,
    Json(request): Json<RevokeTokenRequest>,
) -> ApiResult<Json<RevokeTokenResponse>> {
    app_state.auth_service.revoke_token(&request.refresh_token)
        .await
        .map_err(|e| {
            match e {
                ServiceError::InvalidRefreshToken => {
                    ApiError::Unauthorized("Invalid refresh token".to_string())
                }
                _ => ApiError::InternalServerError(format!("Token revocation failed: {}", e))
            }
        })?;

    info!("Token revoked successfully");
    Ok(Json(RevokeTokenResponse { message: "Token revoked successfully".to_string() }))
}

pub async fn logout_all_sessions_handler(
    State(app_state): State<AppState>,
    AuthenticatedUser { user_id, .. }: AuthenticatedUser,
) -> ApiResult<Json<RevokeTokenResponse>> {
    app_state.auth_service.revoke_all_user_tokens(&user_id.to_string())
        .await
        .map_err(|e| {
            ApiError::InternalServerError(format!("Failed to logout all sessions: {}", e))
        })?;

    info!("All sessions logged out for user: {}", user_id);
    Ok(Json(RevokeTokenResponse { message: "All sessions logged out successfully".to_string() }))
}

pub async fn revoke_all_tokens_handler(
    State(app_state): State<AppState>,
    user: AuthenticatedUser,
) -> ApiResult<Json<RevokeTokenResponse>> {
    app_state.auth_service.revoke_all_user_tokens(&user.user_id.to_string())
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Token revocation failed: {}", e)))?;

    info!("All tokens revoked for user: {}", user.user_id);
    Ok(Json(RevokeTokenResponse {
        message: "All tokens revoked successfully".to_string(),
    }))
}

pub async fn google_auth_handler() -> ApiResult<impl IntoResponse> {
    let (auth_url, _csrf_token) = crate::application::services::AuthService::google_auth_url();
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "auth_url": auth_url
        },
        "message": "Google auth URL generated successfully"
    })))
}

pub async fn google_callback_handler(
    State(app_state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> ApiResult<impl IntoResponse> {
    let response = app_state.auth_service.google_callback(&query.code, &query.state)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Google callback failed: {}", e)))?;

    info!("Google OAuth callback successful");
    Ok(Json(serde_json::json!({
        "success": true,
        "data": response,
        "message": "Google OAuth callback successful"
    })))
}

pub async fn connect_wallet_handler(
    State(app_state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(request): Json<ConnectWalletRequest>,
) -> ApiResult<Json<UserResponse>> {
    let user = app_state.auth_service.connect_wallet(Some(authenticated_user.user_id), request)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Wallet connection failed: {}", e)))?;

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
) -> ApiResult<Json<NonceResponse>> {
    let nonce = app_state.auth_service.create_nonce(&request.wallet_address)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Nonce creation failed: {}", e)))?;

    info!("Nonce created for wallet: {}", request.wallet_address);
    Ok(Json(NonceResponse { nonce }))
}