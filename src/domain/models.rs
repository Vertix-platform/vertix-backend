use std::sync::Arc;

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
    pub google_id: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub username: Option<String>,
    pub wallet_address: Option<String>,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
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

// ============ CONTRACT-RELATED MODELS ============

#[derive(Debug, Deserialize)]
pub struct CreateCollectionRequest {
    pub name: Arc<str>,
    pub symbol: Arc<str>,
    pub image: Arc<str>,
    pub max_supply: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCollectionResponse {
    pub collection_id: u64,
    pub creator: String,
    pub name: String,
    pub symbol: String,
    pub image: String,
    pub max_supply: u64,
    pub current_supply: u64,
    pub token_ids: Vec<u64>,
    pub transaction_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct MintNftRequest {
    pub to: Arc<str>,
    pub token_uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub collection_id: Option<u64>,
    pub royalty_bps: Option<u64>, // Basis points (e.g., 500 = 5%)
}

#[derive(Debug, Serialize)]
pub struct MintNftResponse {
    pub to: Arc<str>,
    pub token_id: u64,
    pub collection_id: Option<u64>,
    pub uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub royalty_recipient: Arc<str>,
    pub royalty_bps: u64,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct MintNftToCollectionRequest {
    pub to: Arc<str>,
    pub collection_id: u64,
    pub token_uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub royalty_bps: Option<u64>, // Basis points (e.g., 500 = 5%)
}

#[derive(Debug, Serialize)]
pub struct MintNftToCollectionResponse {
    pub to: Arc<str>,
    pub collection_id: u64,
    pub token_id: u64,
    pub uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub royalty_recipient: Arc<str>,
    pub royalty_bps: u64,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

// ============ NON-NFT ASSET MODELS ============

#[derive(Debug, Deserialize)]
pub struct CreateEscrowRequest {
    pub asset_type: String, // "social_media", "website", "domain", etc.
    pub asset_id: String,   // Platform-specific ID or URL
    pub price: String,      // Price in ETH/wei
    pub description: String,
    pub verification_data: serde_json::Value, // Platform-specific verification data
}

#[derive(Debug, Serialize)]
pub struct CreateEscrowResponse {
    pub escrow_id: String,
    pub transaction_hash: String,
    pub block_number: u64,
    pub escrow_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ListAssetRequest {
    pub asset_type: String, // "social_media", "website", "domain", etc.
    pub asset_id: String,   // Platform-specific ID or URL
    pub price: String,      // Price in ETH/wei
    pub description: String,
    pub verification_data: serde_json::Value, // Platform-specific verification data
}

#[derive(Debug, Serialize)]
pub struct ListAssetResponse {
    pub listing_id: String,
    pub transaction_hash: String,
    pub block_number: u64,
}

// Domain error and response models can stay or be moved to api layer as needed