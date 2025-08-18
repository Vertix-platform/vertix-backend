use axum::{
    extract::{State},
    Json,
    response::IntoResponse,
};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::{
    domain::models::{
        MintNftRequest,
        InitiateSocialMediaNftMintRequest,
        MintSocialMediaNftRequest,
        ListNftRequest,
        ListNonNftAssetRequest,
        ListNftForAuctionRequest,
        BuyNftRequest, BuyNonNftAssetRequest,
        CancelNftListingRequest, CancelNonNftListingRequest,
        ConfirmTransferRequest, RaiseDisputeRequest, RefundRequest,
    },
    domain::SocialMediaPlatform,
    application::services::{ContractService, ReadOnlyContractService},
    // application::services::contract_service::ContractService,
    api::validation::{Validator, Validate, ValidationResult, ValidationError},
    api::errors::{ApiError, ApiResult},
    handlers::AppState,
    api::middleware::auth::AuthenticatedUser,
};
use std::sync::Arc;

// Helper function to create contract service with current chain configuration
async fn create_contract_service(db_pool: PgPool) -> Result<ContractService, ApiError> {
    let chain_config = crate::infrastructure::contracts::config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    ContractService::new_with_auto_private_key(
        chain_config.rpc_url.clone(),
        chain_config.chain_id,
        db_pool,
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))
}

// Helper function to create read-only contract service with current chain configuration
async fn create_read_only_contract_service(db_pool: PgPool) -> Result<ReadOnlyContractService, ApiError> {
    let chain_config = crate::infrastructure::contracts::config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    ContractService::new_read_only(
        chain_config.rpc_url.clone(),
        chain_config.chain_id,
        db_pool,
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create read-only contract service: {}", e)))
}

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
    pub description: String,
}

impl Validate for ListNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_ethereum_address(&self.nft_contract, "nft_contract"),
            Validator::validate_numeric_string(&self.price, "price"),
            Validator::validate_string(&self.description, "description", 1, 1000),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct BuyNftApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

impl Validate for BuyNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct BuyNonNftAssetApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
    pub price: String, // Price in wei as string
}

impl Validate for BuyNonNftAssetApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_numeric_string(&self.price, "price"),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct CancelNftListingApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

impl Validate for CancelNftListingApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct CancelNonNftListingApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
}

impl Validate for CancelNonNftListingApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateAuctionApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
    pub duration: u64,
    pub reserve_price: String,
}

#[derive(Debug, Deserialize)]
pub struct ListNftForAuctionApiRequest {
    pub wallet_address: String,
    pub listing_id: u64,
    pub is_nft: bool, // true for NFT, false for non-NFT
}

impl Validate for ListNftForAuctionApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct ListSocialMediaNftApiRequest {
    pub wallet_address: String,
    pub token_id: u64,
    pub price: String,
    pub social_media_id: String,
    pub description: String,
}

impl Validate for ListSocialMediaNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_numeric_string(&self.price, "price"),
            Validator::validate_string(&self.social_media_id, "social_media_id", 1, 100),
            Validator::validate_string(&self.description, "description", 1, 1000),
        ];

        Validator::combine_results(results)
    }
}

#[derive(Debug, Deserialize)]
pub struct ConfirmTransferApiRequest {
    pub listing_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct RaiseDisputeApiRequest {
    pub listing_id: u64,
}



#[derive(Debug, Deserialize)]
pub struct RefundApiRequest {
    pub listing_id: u64,
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

impl Validate for ListNonNftAssetApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let mut results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_string(&self.asset_id, "asset_id", 1, 100),
            Validator::validate_numeric_string(&self.price, "price"),
            Validator::validate_string(&self.description, "description", 1, 1000),
            Validator::validate_string(&self.verification_proof, "verification_proof", 1, 10000),
        ];

        // Validate asset_type is within valid range
        if self.asset_type > 5 {
            results.push(Err(ValidationError {
                field: "asset_type".to_string(),
                message: "Asset type must be between 1 and 5".to_string(),
            }));
        }

        Validator::combine_results(results)
    }
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
    State(state): State<AppState>,
    Json(request): Json<MintNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_request = MintNftRequest {
        to: Arc::from(request.wallet_address.clone()),
        token_uri: Arc::from(request.token_uri),
        metadata_hash: Arc::from(request.metadata_hash),
        collection_id: request.collection_id,
        royalty_bps: request.royalty_bps,
    };

    // Create contract service for this request
    let contract_service = create_contract_service(state.pool).await?;

    let response = contract_service.mint_nft(request.wallet_address, contract_request).await
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
    State(_state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Get current chain configuration
    let chain_config = crate::infrastructure::contracts::config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "chain_id": chain_config.chain_id,
            "chain_name": chain_config.name,
            "chain_type": match chain_config.chain_type {
                crate::infrastructure::contracts::types::ChainType::Polygon => "polygon",
                crate::infrastructure::contracts::types::ChainType::Base => "base",
            },
            "rpc_url": chain_config.rpc_url,
            "explorer_url": chain_config.explorer_url,
            "native_currency": {
                "name": chain_config.native_currency.name,
                "symbol": chain_config.native_currency.symbol,
                "decimals": chain_config.native_currency.decimals,
            },
            "gas_settings": {
                "default_gas_limit": chain_config.gas_settings.default_gas_limit,
                "max_gas_limit": chain_config.gas_settings.max_gas_limit,
                "block_time_seconds": chain_config.gas_settings.block_time_seconds,
            }
        },
        "error": null
    })))
}

/// Check contract service connection
pub async fn check_connection(
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Create contract service for this request
    let contract_service = create_contract_service(state.pool).await?;

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
    State(state): State<AppState>,
    Json(request): Json<InitiateSocialMediaNftMintApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate the request
    request.validate().map_err(ApiError::from_validation_errors)?;

    // Parse platform (validation already ensures it's valid)
    let platform = match request.platform.as_str() {
        "x" => SocialMediaPlatform::X,
        "instagram" => SocialMediaPlatform::Instagram,
        "facebook" => SocialMediaPlatform::Facebook,
        _ => return Err(ApiError::bad_request("Invalid platform. Must be 'x', 'instagram', or 'facebook'")),
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
        state.pool,
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))?;

    let response = contract_service.initiate_social_media_nft_mint(request.wallet_address.to_string(), contract_request).await
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
    State(state): State<AppState>,
    Json(request): Json<MintSocialMediaNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let wallet_address = request.wallet_address.clone();
    let social_media_id = request.social_media_id.clone();

    let contract_request = MintSocialMediaNftRequest {
        to: Arc::from(request.wallet_address),
        social_media_id: Arc::from(request.social_media_id),
        token_uri: Arc::from(request.token_uri),
        metadata_hash: Arc::from(request.metadata_hash),
        signature: Arc::from(request.signature),
        royalty_bps: request.royalty_bps,
    };

    // Create contract service for this request
    let contract_service = ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").map_err(|_| ApiError::internal_server_error("PRIVATE_KEY environment variable not set"))?,
        31337, // Default chain ID
        state.pool,
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

/// Get all collections from the contract
pub async fn get_all_collections(
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Create read-only contract service for this request
    let contract_service = create_read_only_contract_service(state.pool).await?;

    match contract_service.get_all_collections().await {
        Ok(collections) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": collections,
                "message": "Collections retrieved successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// List an NFT for sale (wallet-only operation)
pub async fn list_nft(
    State(state): State<AppState>,
    Json(request): Json<ListNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let list_request = ListNftRequest {
        nft_contract: request.nft_contract.into(),
        token_id: request.token_id,
        price: request.price.parse().unwrap_or(0),
        description: request.description.into(),
    };

    match contract_service.list_nft(request.wallet_address, list_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "NFT listed successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// List a non-NFT asset for sale (requires user authentication + wallet connection)
pub async fn list_non_nft_asset(
    State(state): State<AppState>,
    Json(request): Json<ListNonNftAssetApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    // Get authenticated user (this will be handled by auth middleware in protected routes)
    // For now, we'll create a mock user for demonstration
    let user = crate::domain::models::User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(request.wallet_address.clone()),
        is_verified: true,
        created_at: sqlx::types::chrono::Utc::now(),
    };

    let contract_service = create_contract_service(state.pool).await?;

    let list_request = ListNonNftAssetRequest {
        asset_type: request.asset_type,
        asset_id: request.asset_id.into(),
        price: request.price.parse().unwrap_or(0),
        description: request.description.clone().into(),
        metadata: request.description.into(),
        verification_proof: request.verification_proof.into(),
    };

    match contract_service.list_non_nft_asset(&user, request.wallet_address, list_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Non-NFT asset listed successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// List a social media NFT for sale (signature generated internally)
pub async fn list_social_media_nft(
    State(state): State<AppState>,
    Json(request): Json<ListSocialMediaNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let wallet_address = request.wallet_address.clone();
    match contract_service.list_social_media_nft(wallet_address, request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Social media NFT listed successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// List an NFT for auction
pub async fn list_nft_for_auction(
    State(state): State<AppState>,
    Json(request): Json<ListNftForAuctionApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let list_request = ListNftForAuctionRequest {
        listing_id: request.listing_id,
        is_nft: request.is_nft,
    };

    let wallet_address = request.wallet_address.clone();
    match contract_service.list_nft_for_auction(wallet_address, list_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "NFT listed for auction successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Buy an NFT listing
pub async fn buy_nft(
    State(state): State<AppState>,
    Json(request): Json<BuyNftApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    // Get the listing details to get the price
    let (_, _, _, price, _, _) = contract_service.get_nft_listing(request.listing_id).await
        .map_err(|e| ApiError::bad_request(format!("Failed to get listing details: {}", e)))?;

    let buy_request = BuyNftRequest {
        listing_id: request.listing_id,
    };

    let wallet_address = request.wallet_address.clone();
    match contract_service.buy_nft(wallet_address, buy_request, price).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "NFT purchased successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Buy a non-NFT asset listing
pub async fn buy_non_nft_asset(
    State(state): State<AppState>,
    Json(request): Json<BuyNonNftAssetApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let buy_request = BuyNonNftAssetRequest {
        listing_id: request.listing_id,
    };

    let wallet_address = request.wallet_address.clone();
    let price = request.price.parse().unwrap_or(0);
    match contract_service.buy_non_nft_asset(wallet_address, buy_request, price).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Non-NFT asset purchased successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Cancel an NFT listing
pub async fn cancel_nft_listing(
    State(state): State<AppState>,
    Json(request): Json<CancelNftListingApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let cancel_request = CancelNftListingRequest {
        listing_id: request.listing_id,
    };

    let wallet_address = request.wallet_address.clone();
    match contract_service.cancel_nft_listing(wallet_address, cancel_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "NFT listing cancelled successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Cancel a non-NFT asset listing
pub async fn cancel_non_nft_listing(
    State(state): State<AppState>,
    Json(request): Json<CancelNonNftListingApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate request
    request.validate().map_err(|errors| ApiError::from_validation_errors(errors))?;

    let contract_service = create_contract_service(state.pool).await?;

    let cancel_request = CancelNonNftListingRequest {
        listing_id: request.listing_id,
    };

    let wallet_address = request.wallet_address.clone();
    match contract_service.cancel_non_nft_listing(wallet_address, cancel_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Non-NFT asset listing cancelled successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Confirm transfer in escrow (buyer confirms they received the asset)
pub async fn confirm_transfer(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(request): Json<ConfirmTransferApiRequest>,
) -> ApiResult<impl IntoResponse> {

    // Get authenticated user from database
    let user = state.auth_service.get_user_profile(auth_user.user_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    // Ensure user has a connected wallet
    let wallet_address = user.wallet_address.clone()
        .ok_or_else(|| ApiError::bad_request("User must connect a wallet first"))?;

    let contract_service = create_contract_service(state.pool).await?;

    let confirm_request = ConfirmTransferRequest {
        listing_id: request.listing_id,
    };

    match contract_service.confirm_transfer(&user, wallet_address, confirm_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Transfer confirmed successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Raise a dispute in escrow
pub async fn raise_dispute(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(request): Json<RaiseDisputeApiRequest>,
) -> ApiResult<impl IntoResponse> {
    // Get authenticated user from database
    let user = state.auth_service.get_user_profile(auth_user.user_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    // Ensure user has a connected wallet
    let wallet_address = user.wallet_address.clone()
        .ok_or_else(|| ApiError::bad_request("User must connect a wallet first"))?;

    let contract_service = create_contract_service(state.pool).await?;

    let dispute_request = RaiseDisputeRequest {
        listing_id: request.listing_id,
    };

    match contract_service.raise_dispute(&user, wallet_address, dispute_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Dispute raised successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Refund escrow if deadline has passed
pub async fn refund(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(request): Json<RefundApiRequest>,
) -> ApiResult<impl IntoResponse> {

    // Get authenticated user from database
    let user = state.auth_service.get_user_profile(auth_user.user_id)
        .await
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    // Ensure user has a connected wallet
    let wallet_address = user.wallet_address.clone()
        .ok_or_else(|| ApiError::bad_request("User must connect a wallet first"))?;

    let contract_service = create_contract_service(state.pool).await?;

    let refund_request = RefundRequest {
        listing_id: request.listing_id,
    };

    match contract_service.refund(&user, wallet_address, refund_request).await {
        Ok(response) => {
            Ok(Json(serde_json::json!({
                "success": true,
                "data": response,
                "message": "Refund processed successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&e.to_string()))
        }
    }
}

/// Get all supported chains information
pub async fn get_supported_chains(
    State(_state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Get all supported chain configurations
    let supported_chains = crate::infrastructure::contracts::config::get_supported_chains()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;
    
    let chains_data: Vec<serde_json::Value> = supported_chains.into_iter().map(|chain_config| {
        serde_json::json!({
            "chain_id": chain_config.chain_id,
            "chain_name": chain_config.name,
            "chain_type": match chain_config.chain_type {
                crate::infrastructure::contracts::types::ChainType::Polygon => "polygon",
                crate::infrastructure::contracts::types::ChainType::Base => "base",
            },
            "rpc_url": chain_config.rpc_url,
            "explorer_url": chain_config.explorer_url,
            "native_currency": {
                "name": chain_config.native_currency.name,
                "symbol": chain_config.native_currency.symbol,
                "decimals": chain_config.native_currency.decimals,
            },
            "gas_settings": {
                "default_gas_limit": chain_config.gas_settings.default_gas_limit,
                "max_gas_limit": chain_config.gas_settings.max_gas_limit,
                "block_time_seconds": chain_config.gas_settings.block_time_seconds,
            }
        })
    }).collect();
    
    Ok(Json(serde_json::json!({
        "success": true,
        "data": chains_data,
        "error": null
    })))
}