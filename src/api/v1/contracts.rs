use axum::{
    extract::{State},
    Json,
    response::IntoResponse,
};

use serde::{Deserialize, Serialize};
use crate::{
    application::services::AuthService,
    domain::models::{
        MintNftRequest,
        InitiateSocialMediaNftMintRequest, 
        MintSocialMediaNftRequest,
    },
    domain::SocialMediaPlatform,
    application::services::contract_service::ContractService,
    api::validation::{Validator, Validate, ValidationResult},
    api::errors::{ApiError, ApiResult},
};
use std::sync::Arc;

// ============ REQUEST/RESPONSE TYPES ============

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MintNftApiRequest {
    pub wallet_address: String,
    pub token_uri: String,
    pub metadata_hash: String,
    pub collection_id: Option<u64>,
    pub royalty_bps: Option<u64>,
}

impl Validate for MintNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let mut results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_ipfs_uri(&self.token_uri, "token_uri"),
            Validator::validate_hex_string(&self.metadata_hash, "metadata_hash", Some(64)), // 32 bytes = 64 hex chars
        ];

        // Validate royalty_bps if provided
        if let Some(royalty_bps) = self.royalty_bps {
            if royalty_bps > 10000 {
                results.push(Err(crate::api::validation::ValidationError {
                    field: "royalty_bps".to_string(),
                    message: "Royalty basis points cannot exceed 10000 (100%)".to_string(),
                }));
            }
        }

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct ListNftApiRequest {
    pub wallet_address: String,
    pub nft_contract: String,
    pub token_id: u64,
    pub price: String,
}

#[derive(Debug, Deserialize)]
pub struct BuyNftApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateAuctionApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
    pub duration: u64,
    pub reserve_price: String,
}

#[derive(Debug, Deserialize)]
pub struct PlaceBidApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct ListNonNftAssetApiRequest {
    pub wallet_address: String,
    pub asset_type: u8,
    pub asset_id: String,
    pub price: String,
    pub description: String,
    pub verification_proof: String,
}

#[derive(Debug, Deserialize)]
pub struct BuyNonNftAssetApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct BridgeAssetApiRequest {
    pub wallet_address: String,
    pub contract_addr: String,
    pub target_contract: String,
    pub token_id: u64,
    pub target_chain_type: u8,
    pub asset_type: u8,
    pub is_nft: bool,
    pub asset_id: String,
}

// Social Media NFT Minting
#[derive(Debug, Deserialize)]
pub struct InitiateSocialMediaNftMintApiRequest {
    pub wallet_address: String,
    pub platform: String, // "twitter", "instagram", "facebook"
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub profile_image_url: Option<String>,
    pub follower_count: Option<u64>,
    pub verified: bool,
    pub access_token: String,
    pub custom_image_url: Option<String>,
    pub royalty_bps: Option<u16>,
}

impl Validate for InitiateSocialMediaNftMintApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let mut results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_social_media_platform(&self.platform, "platform"),
            Validator::validate_string(&self.user_id, "user_id", 1, 100),
            Validator::validate_string(&self.username, "username", 1, 50),
            Validator::validate_string(&self.display_name, "display_name", 1, 100),
            Validator::validate_string(&self.access_token, "access_token", 10, 1000),
        ];

        // Validate optional profile image URL
        if let Some(ref url) = self.profile_image_url {
            if !url.is_empty() {
                results.push(Validator::validate_url(url, "profile_image_url"));
            }
        }

        // Validate optional custom image URL
        if let Some(ref url) = self.custom_image_url {
            if !url.is_empty() {
                results.push(Validator::validate_url(url, "custom_image_url"));
            }
        }

        // Validate royalty_bps if provided
        if let Some(royalty_bps) = self.royalty_bps {
            results.push(Validator::validate_basis_points(royalty_bps, "royalty_bps"));
        }

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct MintSocialMediaNftApiRequest {
    pub wallet_address: String,
    pub social_media_id: String,
    pub token_uri: String,
    pub metadata_hash: String,
    pub royalty_bps: Option<u16>,
    pub signature: String,
    // pub custom_image_url: Option<String>,
}

impl Validate for MintSocialMediaNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let mut results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_string(&self.social_media_id, "social_media_id", 1, 200),
            Validator::validate_ipfs_uri(&self.token_uri, "token_uri"),
            Validator::validate_hex_string(&self.metadata_hash, "metadata_hash", Some(64)), // 32 bytes = 64 hex chars
            Validator::validate_hex_string(&self.signature, "signature", Some(130)), // 65 bytes = 130 hex chars
        ];

        // Validate royalty_bps if provided
        if let Some(royalty_bps) = self.royalty_bps {
            results.push(Validator::validate_basis_points(royalty_bps, "royalty_bps"));
        }

        Validator::combine_results(results)
    }
}

// ============ NFT OPERATIONS ============

/// Mint a new NFT
pub async fn mint_nft(
    State(_state): State<AuthService>,
    Json(request): Json<MintNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate the request
    request.validate().map_err(ApiError::from_validation_errors)?;
    let contract_request = MintNftRequest {
        to: Arc::from(request.wallet_address.clone()),
        token_uri: Arc::from(request.token_uri),
        metadata_hash: Arc::from(request.metadata_hash),
        collection_id: request.collection_id,
        royalty_bps: request.royalty_bps,
    };

    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let response = contract_service.mint_nft(request.wallet_address.to_string(), contract_request).await
        .map_err(|e| ApiError::bad_request(format!("Failed to mint NFT: {}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "token_id": response.token_id,
            "transaction_hash": response.transaction_hash.to_string(),
            "block_number": response.block_number
        },
        "error": null
    })))
}


// ============ UTILITY OPERATIONS ============

/// Get network information
pub async fn get_network_info(
    State(_state): State<AuthService>,
) -> ApiResult<impl IntoResponse> {
    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let network_config = contract_service.get_network_config().clone();
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "chain_id": network_config.chain_id,
            "rpc_url": network_config.rpc_url,
            "name": "Anvil Local"
        },
        "error": null
    })))
}

/// Check contract service connection
pub async fn check_connection(
    State(_state): State<AuthService>,
) -> ApiResult<impl IntoResponse> {
    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let is_connected = contract_service.is_connected().await;
    Ok(Json(serde_json::json!({
        "success": true,
        "data": is_connected,
        "error": null
    })))
}

/// Initiate social media NFT minting process
/// This endpoint generates all necessary data including signature for the minting process
pub async fn initiate_social_media_nft_mint(
    State(_state): State<AuthService>,
    Json(request): Json<InitiateSocialMediaNftMintApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate the request
    request.validate().map_err(ApiError::from_validation_errors)?;

    // Parse platform (validation already ensures it's valid)
    let platform = match request.platform.as_str() {
        "twitter" => SocialMediaPlatform::Twitter,
        "instagram" => SocialMediaPlatform::Instagram,
        "facebook" => SocialMediaPlatform::Facebook,
        _ => return Err(ApiError::bad_request("Invalid platform. Must be 'twitter', 'instagram', or 'facebook'")),
    };

    let contract_request = InitiateSocialMediaNftMintRequest {
        platform,
        user_id: Arc::from(request.user_id),
        username: Arc::from(request.username),
        display_name: Arc::from(request.display_name),
        profile_image_url: request.profile_image_url.map(Arc::from),
        follower_count: request.follower_count,
        verified: request.verified,
        access_token: Arc::from(request.access_token),
        custom_image_url: request.custom_image_url.map(Arc::from),
        royalty_bps: request.royalty_bps,
    };

    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let response = contract_service.initiate_social_media_nft_mint(request.wallet_address, contract_request).await
        .map_err(|e| ApiError::bad_request(format!("Failed to initiate social media NFT mint: {}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "social_media_id": response.social_media_id.to_string(),
            "token_uri": response.token_uri.to_string(),
            "metadata_hash": response.metadata_hash.to_string(),
            "royalty_bps": response.royalty_bps,
            "signature": response.signature.to_string()
        },
        "error": null
    })))
}

/// Mint social media NFT with signature verification
pub async fn mint_social_media_nft(
    State(_state): State<AuthService>,
    Json(request): Json<MintSocialMediaNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate the request
    request.validate().map_err(ApiError::from_validation_errors)?;

    // Clone wallet_address before using it to avoid move issues
    let wallet_address = request.wallet_address.clone();
    let social_media_id = request.social_media_id.clone();

    let contract_request = MintSocialMediaNftRequest {
        to: Arc::from(request.wallet_address),
        social_media_id: Arc::from(request.social_media_id),
        token_uri: Arc::from(request.token_uri),
        metadata_hash: Arc::from(request.metadata_hash),
        royalty_bps: request.royalty_bps,
        signature: Arc::from(request.signature),
    };

    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let response = contract_service.mint_social_media_nft(wallet_address, contract_request).await
        .map_err(|e| {
            let error_msg = e.to_string();
            if error_msg.contains("Social media NFT minting transaction reverted") {
                ApiError::conflict(format!("Social media profile '{}' has already been minted as an NFT", social_media_id))
            } else {
                ApiError::bad_request(format!("Failed to mint social media NFT: {}", e))
            }
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "to": response.to.to_string(),
            "token_id": response.token_id,
            "social_media_id": response.social_media_id.to_string(),
            "uri": response.uri.to_string(),
            "metadata_hash": response.metadata_hash.to_string(),
            "royalty_recipient": response.royalty_recipient.to_string(),
            "royalty_bps": response.royalty_bps,
            "transaction_hash": response.transaction_hash.to_string(),
            "block_number": response.block_number
        },
        "error": null
    })))
}