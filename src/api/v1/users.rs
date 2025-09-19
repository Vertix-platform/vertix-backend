use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use tracing::info;

use crate::api::dto::{UpdateProfileRequest, UserResponse};
use crate::api::middleware::AuthenticatedUser;
use crate::api::errors::{ApiResult, ApiError};
use crate::handlers::AppState;

pub async fn profile_handler(
    State(app_state): State<AppState>,
    authenticated_user: AuthenticatedUser,
) -> ApiResult<impl IntoResponse> {
    let user = app_state.auth_service.get_user_profile(authenticated_user.user_id)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Failed to get profile: {:?}", e)))?;

    info!("Profile accessed for user: {}", user.email);
    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        username: user.username,
        wallet_address: user.wallet_address,
        is_verified: user.is_verified,
        created_at: user.created_at,
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "data": user_response,
        "message": "Profile retrieved successfully"
    })))
}

pub async fn update_profile_handler(
    State(app_state): State<AppState>,
    authenticated_user: AuthenticatedUser,
    Json(request): Json<UpdateProfileRequest>,
) -> ApiResult<impl IntoResponse> {
    // Input validation
    if let Some(username) = &request.username {
        if username.is_empty() {
            return Err(ApiError::BadRequest("Username cannot be empty".to_string()));
        }
        if username.len() > 255 {
            return Err(ApiError::BadRequest("Username too long".to_string()));
        }
    }

    let user = app_state.auth_service.update_user_profile(authenticated_user.user_id, request)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Profile update failed: {:?}", e)))?;

    info!("Profile updated for user: {}", user.email);
    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        username: user.username,
        wallet_address: user.wallet_address,
        is_verified: user.is_verified,
        created_at: user.created_at,
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "data": user_response,
        "message": "Profile updated successfully"
    })))
}