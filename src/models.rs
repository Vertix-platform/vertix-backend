use serde::{Deserialize, Serialize};

// Input for /verify
#[derive(Deserialize)]
pub struct VerifyRequest {
    pub asset_type: String, // e.g., "social_media", "domain"
    pub asset_id: String,   // e.g., "123" (X user ID), "example.com"
    pub proof: String,      // Proof of ownership (e.g., token)
}

// Output for /verify
#[derive(Serialize)]
pub struct VerifyResponse {
    pub is_verified: bool,  // true if ownership is valid
}

// Input for /value
#[derive(Deserialize)]
pub struct ValueRequest {
    pub asset_type: String,
    pub asset_id: String,
}

// Output for /value
#[derive(Serialize)]
pub struct ValueResponse {
    pub value: u64,        // Value in USD * 1,000,000
}

// Error message format
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}