use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub google_id: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub username: Option<String>,
    pub wallet_address: Option<String>,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub username: Option<String>,
    pub wallet_address: Option<String>,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConnectWalletRequest {
    pub wallet_address: String,
    pub signature: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct NonceResponse {
    pub nonce: String,
}

// #[derive(Debug, Deserialize)]
// pub struct KycRequest {
//     pub user_id: Uuid,
// }

// #[derive(Debug, Deserialize)]
// pub struct KycCallback {
//     pub user_id: Uuid,
//     pub status: String, // "verified" or "rejected"
// }