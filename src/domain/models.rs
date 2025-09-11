use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::domain::SocialMediaPlatform;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub collection_id: u64,
    pub chain_id: u64,
    pub name: Arc<str>,
    pub symbol: Arc<str>,
    pub image: Arc<str>,
    pub max_supply: u16,
    pub creator: Arc<str>,
    pub current_supply: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escrow {
    pub listing_id: u64,
    pub seller: Arc<str>,
    pub buyer: Arc<str>,
    pub amount: u64,
    pub deadline: u64,
    pub completed: bool,
    pub disputed: bool,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmTransferRequest {
    pub listing_id: u64,
}

#[derive(Debug, Serialize)]
pub struct ConfirmTransferResponse {
    pub listing_id: u64,
    pub transaction_hash: Arc<str>,
    pub seller: Arc<str>,
    pub amount: u64,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct RaiseDisputeRequest {
    pub listing_id: u64,
}

#[derive(Debug, Serialize)]
pub struct RaiseDisputeResponse {
    pub listing_id: u64,
    pub transaction_hash: Arc<str>,
    pub raiser: Arc<str>, // Address of who raised the dispute
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct RefundRequest {
    pub listing_id: u64,
}

#[derive(Debug, Serialize)]
pub struct RefundResponse {
    pub listing_id: u64,
    pub transaction_hash: Arc<str>,
    pub buyer: Arc<str>,
    pub amount: u64,
    pub block_number: u64,
}

// ============ ADMIN MODELS ============

#[derive(Debug, Deserialize)]
pub struct AddSupportedNftContractRequest {
    pub nft_contract: Arc<str>,
}

#[derive(Debug, Serialize)]
pub struct AddSupportedNftContractResponse {
    pub nft_contract: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct RemoveSupportedNftContractRequest {
    pub nft_contract: Arc<str>,
}

#[derive(Debug, Serialize)]
pub struct RemoveSupportedNftContractResponse {
    pub nft_contract: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct SetPlatformFeeRequest {
    pub new_fee: u16, // Basis points (e.g., 100 = 1%)
}

#[derive(Debug, Serialize)]
pub struct SetPlatformFeeResponse {
    pub new_fee: u16,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct SetFeeRecipientRequest {
    pub new_recipient: Arc<str>,
}

#[derive(Debug, Serialize)]
pub struct SetFeeRecipientResponse {
    pub new_recipient: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResolveDisputeRequest {
    pub listing_id: u64,
    pub winner: Arc<str>, // Address of the winner (seller or buyer)
}

#[derive(Debug, Serialize)]
pub struct ResolveDisputeResponse {
    pub listing_id: u64,
    pub winner: Arc<str>,
    pub amount: u64,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct SetEscrowDurationRequest {
    pub new_duration: u32, // Duration in seconds
}

#[derive(Debug, Serialize)]
pub struct SetEscrowDurationResponse {
    pub new_duration: u32,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct PauseContractRequest {
    pub contract_type: Arc<str>, // "escrow", "marketplace", etc.
}

#[derive(Debug, Serialize)]
pub struct PauseContractResponse {
    pub contract_type: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

#[derive(Debug, Deserialize)]
pub struct UnpauseContractRequest {
    pub contract_type: Arc<str>, // "escrow", "marketplace", etc.
}

#[derive(Debug, Serialize)]
pub struct UnpauseContractResponse {
    pub contract_type: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

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
    pub creator: Arc<str>,
    pub name: Arc<str>,
    pub symbol: Arc<str>,
    pub image: Arc<str>,
    pub max_supply: u64,
    pub current_supply: u64,
    pub token_ids: Vec<u64>,
    pub transaction_hash: Arc<str>,
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

#[derive(Debug, Clone)]
pub struct MintSocialMediaNftRequest {
    pub to: Arc<str>,
    pub social_media_id: Arc<str>,
    pub token_uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub royalty_bps: Option<u16>,
    pub signature: Arc<str>, // Backend-generated signature for verification
    // pub custom_image_url: Option<Arc<str>>, // Optional custom image URL
}

#[derive(Debug, Clone)]
pub struct MintSocialMediaNftResponse {
    pub to: Arc<str>,
    pub token_id: u64,
    pub social_media_id: Arc<str>,
    pub uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub signature: Arc<str>,
    pub royalty_recipient: Arc<str>,
    pub royalty_bps: u16,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

// New request for initiating social media NFT minting
#[derive(Debug, Clone)]
pub struct InitiateSocialMediaNftMintRequest {
    pub platform: SocialMediaPlatform,
    pub user_id: Arc<str>,
    pub username: Arc<str>,
    pub display_name: Arc<str>,
    pub profile_image_url: Option<Arc<str>>,
    pub follower_count: Option<u64>,
    pub verified: bool,
    pub access_token: Arc<str>,
    pub custom_image_url: Option<Arc<str>>, // Optional custom image URL
    pub royalty_bps: Option<u16>, // Default 5% if not provided
}

#[derive(Debug, Clone)]
pub struct InitiateSocialMediaNftMintResponse {
    pub social_media_id: Arc<str>,
    pub token_uri: Arc<str>,
    pub metadata_hash: Arc<str>,
    pub signature: Arc<str>,
    pub royalty_bps: u16,
    pub metadata: Arc<str>, // Full metadata JSON
}

/// Request to list an NFT for sale
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListNftRequest {
    pub nft_contract: Arc<str>,
    pub token_id: u64,
    pub price: u64, // Price in wei as string
    pub description: Arc<str>, // User-provided description for the listing
}

/// Response for listing creation
#[derive(Debug, Serialize, Deserialize)]
pub struct ListNftResponse {
    pub listing_id: u64,
    pub creator: Arc<str>,
    pub nft_contract: Arc<str>,
    pub token_id: u64,
    pub price: u64,
    pub description: Arc<str>, // User-provided description
    pub active: bool,
    pub is_auction: bool,
    pub created_at: u64,
    pub transaction_hash: String,
    pub block_number: u64, // Added missing field
    pub chain_id: u64, // Chain where the NFT was listed
}

#[derive(Debug, Clone)]
pub struct ListSocialMediaNftRequest {
    pub token_id: u64,
    pub price: u64,
    pub social_media_id: Arc<str>,
    pub signature: Arc<str>,
    pub description: Arc<str>, // User-provided description
}

// ============ NON-NFT ASSET MODELS ============

#[derive(Debug, Deserialize, Clone)]
pub struct ListNonNftAssetRequest {
    pub asset_type: u8, // 1 = SocialMedia, 2 = Website, 3 = Domain, etc.
    pub asset_id: Arc<str>,   // Platform-specific ID or URL
    pub price: u64,      // Price in ETH/wei
    pub description: Arc<str>, // User-provided description for the listing
    pub metadata: Arc<str>,
    pub verification_proof: Arc<str>, // Platform-specific verification data
}

#[derive(Debug, Serialize)]
pub struct ListNonNftAssetResponse {
    pub listing_id: u64,
    pub creator: Arc<str>,
    pub asset_type: u8,
    pub asset_id: Arc<str>,
    pub price: u64,
    pub description: Arc<str>, // User-provided description
    pub metadata: Arc<str>,
    pub verification_proof: Arc<str>,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
    pub chain_id: u64, // Chain where the asset was listed
}

/// Request to place a bid
#[derive(Debug, Serialize, Deserialize)]
pub struct PlaceBidRequest {
    pub listing_id: u64,
}

/// Response for NFT purchase
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNftResponse {
    pub transaction_hash: String,
    pub new_owner: String,
    pub price: u64,
    pub royalty_amount: u64,
    pub royalty_recipient: String,
    pub platform_fee: u64,
    pub platform_recipient: String,
}

/// Response for auction creation
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAuctionResponse {
    pub auction_id: u64,
    pub transaction_hash: String,
    pub end_time: u64,
}

/// Response for bid placement
#[derive(Debug, Serialize, Deserialize)]
pub struct PlaceBidResponse {
    pub transaction_hash: String,
    pub bid_amount: String,
}

/// Request to buy a non-NFT asset
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNonNftAssetRequest {
    pub listing_id: u64,
}

/// Response for non-NFT asset purchase
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNonNftAssetResponse {
    pub listing_id: u64,
    pub transaction_hash: String,
    pub buyer: String,
    pub price: u64,
    pub seller_amount: u64,
    pub platform_fee: u64,
    pub platform_recipient: String,
}

/// Request to cancel an NFT listing
#[derive(Debug, Serialize, Deserialize)]
pub struct CancelNftListingRequest {
    pub listing_id: u64,
}

/// Response for NFT listing cancellation
#[derive(Debug, Serialize, Deserialize)]
pub struct CancelNftListingResponse {
    pub listing_id: u64,
    pub transaction_hash: String,
    pub seller: String,
    pub is_nft: bool,
}

/// Request to cancel a non-NFT listing
#[derive(Debug, Serialize, Deserialize)]
pub struct CancelNonNftListingRequest {
    pub listing_id: u64,
}

/// Response for non-NFT listing cancellation
#[derive(Debug, Serialize, Deserialize)]
pub struct CancelNonNftListingResponse {
    pub listing_id: u64,
    pub transaction_hash: String,
    pub seller: String,
    pub is_nft: bool,
}

/// Request to bridge an asset to another chain
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeAssetRequest {
    pub contract_addr: String,
    pub target_contract: String,
    pub token_id: u64,
    pub target_chain_type: u8,
    pub asset_type: u8,
    pub is_nft: bool,
    pub asset_id: String,
}
/// Response for asset bridging
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeAssetResponse {
    pub request_id: String,
    pub transaction_hash: String,
    pub bridge_fee: String,
}

/// Request to buy an NFT
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNftRequest {
    pub listing_id: u64,
}

/// Request to create an auction
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAuctionRequest {
    pub listing_id: u64,
    pub duration: u64, // Duration in seconds
    pub reserve_price: String, // Reserve price in wei as string
}

/// Request to list an NFT for auction
#[derive(Debug, Serialize, Deserialize)]
pub struct ListNftForAuctionRequest {
    pub listing_id: u64,
    pub is_nft: bool, // true for NFT, false for non-NFT
}

/// Response for listing an NFT for auction
#[derive(Debug, Serialize)]
pub struct ListNftForAuctionResponse {
    pub listing_id: u64,
    pub is_nft: bool,
    pub transaction_hash: Arc<str>,
    pub block_number: u64,
}

// ============ LISTING MODELS ============

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct NftListing {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub nft_contract: String,
    pub token_id: i64,
    pub price: i64,
    pub description: String,
    pub active: bool,
    pub is_auction: bool,
    pub metadata_uri: Option<String>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct NonNftListing {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub asset_type: i16,
    pub asset_id: String,
    pub price: i64,
    pub description: String,
    pub platform: Option<String>,
    pub identifier: Option<String>,
    pub metadata_uri: Option<String>,
    pub verification_proof: Option<String>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SocialMediaNftListing {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub token_id: i64,
    pub price: i64,
    pub description: String,
    pub social_media_id: String,
    pub signature: String,
    pub active: bool,
    pub is_auction: bool,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub family_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// ============ NFT MODELS ============