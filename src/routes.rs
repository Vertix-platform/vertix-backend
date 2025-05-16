use axum::{
    extract::{Query, State}, middleware, routing::{get, post, put}, Json, Router
};
use axum::http::{header, HeaderMap};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::{info};
use uuid::Uuid;
use crate::{
    auth::{connect_wallet, google_auth_url, google_callback, login, register, update_profile, verify_jwt},
    middleware::auth_middleware,
    models::{ConnectWalletRequest, LoginResponse, LoginUser, NonceResponse, RegisterUser, UpdateProfileRequest, User, UserResponse}
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

pub fn app_router(pool: PgPool) -> Router {
    let state = AppState { pool };
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/google-auth", get(google_auth_handler))
        .route("/google-callback", get(google_callback_handler))
        .route("/connect-wallet", post(connect_wallet_handler))
        .route("/nonce", post(nonce_handler))
        .route("/profile", get(profile_handler))
        .route_layer(middleware::from_fn(auth_middleware))
        .route("/update-profile", put(update_profile_handler))
        // .route("/kyc", post(kyc_handler))
        // .route("/kyc/callback", post(kyc_callback_handler))
        .with_state(state)
}

async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUser>,
) -> Result<Json<LoginResponse>, String> {
    if payload.email.is_empty() || payload.password.is_empty() || payload.first_name.is_empty() || payload.last_name.is_empty() {
        return Err("All fields are required".to_string());
    }

    let user = register(&state.pool, &payload.email, &payload.password, &payload.first_name, &payload.last_name)
        .await
        .map_err(|e| format!("Registration failed: {:?}", e))?;

    let token = crate::auth::generate_jwt(&user.id.to_string())
        .map_err(|e| format!("JWT generation failed: {:?}", e))?;

    info!("User registered: {}", user.email);
    Ok(Json(LoginResponse { token }))
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginUser>,
) -> Result<Json<LoginResponse>, String> {
    let response = login(&state.pool, &payload.email, &payload.password)
        .await
        .map_err(|e| format!("Login failed: {:?}", e))?;

    info!("User logged in: {}", payload.email);
    Ok(Json(response))
}

async fn google_auth_handler() -> Json<serde_json::Value> {
    let (auth_url, _csrf_token) = google_auth_url();
    Json(serde_json::json!({ "auth_url": auth_url }))
}

#[derive(Deserialize)]
struct GoogleCallbackQuery {
    code: String,
    state: String,
}

async fn google_callback_handler(
    State(state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Json<LoginResponse>, String> {
    let response = google_callback(&state.pool, &query.code, &query.state)
        .await
        .map_err(|e| format!("Google OAuth failed: {:?}", e))?;

    info!("User authenticated via Google");
    Ok(Json(response))
}

async fn connect_wallet_handler(
    State(state): State<AppState>,
    Json(payload): Json<ConnectWalletRequest>,
) -> Result<Json<UserResponse>, String> {
    // For buyers, user_id is None; for sellers, it should come from JWT (to be added in middleware)
    let user = connect_wallet(&state.pool, None, payload)
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

#[derive(Deserialize)]
struct NonceRequest {
    wallet_address: String,
}

async fn nonce_handler(
    State(state): State<AppState>,
    Json(payload): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, String> {
    let nonce = crate::db::create_nonce(&state.pool, &payload.wallet_address)
        .await
        .map_err(|e| format!("Nonce creation failed: {:?}", e))?;

    info!("Nonce created for wallet: {}", payload.wallet_address);
    Ok(Json(NonceResponse { nonce }))
}

async fn profile_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserResponse>, String> {
    let auth_header = headers.get(header::AUTHORIZATION)
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    let token = auth_header.strip_prefix("Bearer ")
        .ok_or("Invalid Bearer token")?;

    let user_id = verify_jwt(token)
        .map_err(|e| format!("JWT verification failed: {:?}", e))?;

    let user_id = Uuid::parse_str(&user_id)
        .map_err(|_| "Invalid user ID")?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| format!("Database error: {:?}", e))?
    .ok_or("User not found")?;

    info!("Profile accessed for user: {}", user.email);
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

async fn update_profile_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserResponse>, String> {
    tracing::debug!("Received payload: {:?}", payload);
    if let Some(username) = &payload.username {
        if username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }
        if username.len() > 255 {
            return Err("Username too long".to_string());
        }
    }
    let auth_header = headers.get(header::AUTHORIZATION)
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    let token = auth_header.strip_prefix("Bearer ")
        .ok_or("Invalid Bearer token")?;

    let user_id = verify_jwt(token)
        .map_err(|e| format!("JWT verification failed: {:?}", e))?;

    let user_id = Uuid::parse_str(&user_id)
        .map_err(|_| "Invalid user ID")?;

    let user = update_profile(&state.pool, user_id, payload)
        .await
        .map_err(|e| format!("Profile update failed: {:?}", e))?;

    info!("Profile updated for user: {}", user.email);
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

// async fn kyc_handler(
//     State(state): State<AppState>,
//     Extension(user_id): Extension<Uuid>,
//     Json(payload): Json<KycRequest>,
// ) -> Result<Json<serde_json::Value>, String> {
//     if payload.user_id != user_id {
//         return Err("Unauthorized: user_id mismatch".to_string());
//     }

//     let kyc_url = initiate_kyc(&state.pool, payload)
//         .await
//         .map_err(|e| format!("KYC initiation failed: {:?}", e))?;

//     info!("KYC initiated for user: {}", user_id);
//     Ok(Json(serde_json::json!({ "kyc_url": kyc_url })))
// }

// async fn kyc_callback_handler(
//     State(state): State<AppState>,
//     Json(payload): Json<KycCallback>,
// ) -> Result<Json<UserResponse>, String> {
//     let user = complete_kyc(&state.pool, payload)
//         .await
//         .map_err(|e| format!("KYC callback failed: {:?}", e))?;

//     info!("KYC completed for user: {}", user.email);
//     Ok(Json(UserResponse {
//         id: user.id,
//         email: user.email,
//         first_name: user.first_name,
//         last_name: user.last_name,
//         username: user.username,
//         wallet_address: user.wallet_address,
//         is_verified: user.is_verified,
//         created_at: user.created_at,
//     }))
// }