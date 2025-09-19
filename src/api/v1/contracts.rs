use axum::{
    extract::{Query, State, Path},
    Json,
    response::IntoResponse,
};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use crate::{
    domain::models::{
        InitiateSocialMediaNftMintRequest,
        MintSocialMediaNftRequest,
        ListNonNftAssetRequest,
        ListNftForAuctionRequest,
        BuyNftRequest, BuyNonNftAssetRequest,
        CancelNftListingRequest, CancelNonNftListingRequest,
        ConfirmTransferRequest, RaiseDisputeRequest, RefundRequest,
    },
    domain::SocialMediaPlatform,
    application::services::ContractService,
    // application::services::contract_service::ContractService,
    api::validation::{Validator, Validate, ValidationResult, ValidationError},
    api::errors::{ApiError, ApiResult},
    handlers::AppState,
    api::middleware::auth::AuthenticatedUser,
};
use crate::infrastructure::contracts::{config, types};
use crate::infrastructure::repositories::collections_repository::CollectionsRepository;
use crate::infrastructure::repositories::nft_events_repository::NftEventsRepository;
use crate::infrastructure::repositories::nft_listing_events_repository::NftListingEventsRepository;
use crate::domain::models::Collection;

use std::sync::Arc;
use reqwest;
use serde_json::Value as JsonValue;

/// Fetch metadata from IPFS
async fn fetch_ipfs_metadata(ipfs_uri: &str) -> Result<JsonValue, ApiError> {
    // Convert IPFS URI to HTTP URL
    let http_url = if ipfs_uri.starts_with("ipfs://") {
        let hash = &ipfs_uri[7..]; // Remove "ipfs://" prefix
        format!("https://ipfs.io/ipfs/{}", hash)
    } else if ipfs_uri.starts_with("https://") {
        ipfs_uri.to_string()
    } else {
        return Err(ApiError::bad_request("Invalid IPFS URI format"));
    };

    // Fetch metadata from IPFS
    let response = reqwest::get(&http_url)
        .await
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to fetch IPFS metadata: {}", e)))?;

    if !response.status().is_success() {
        return Err(ApiError::internal_server_error(&format!("IPFS request failed with status: {}", response.status())));
    }

    let metadata: JsonValue = response.json()
        .await
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to parse IPFS metadata: {}", e)))?;

    Ok(metadata)
}

// Helper function to create contract service with current chain configuration
async fn create_contract_service(db_pool: PgPool) -> Result<ContractService, ApiError> {
    let chain_config = config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    ContractService::new_with_auto_private_key(
        chain_config.rpc_url.clone(),
        chain_config.chain_id,
        db_pool,
    ).await.map_err(|e| ApiError::internal_server_error(format!("Failed to create contract service: {}", e)))
}



// ============ REQUEST/RESPONSE TYPES ============

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
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
pub struct MintNftApiRequest {
    pub wallet_address: String,
    pub token_uri: String,
    pub metadata_hash: String,
    pub collection_id: Option<u64>,
    pub royalty_bps: Option<u16>,
}

impl Validate for MintNftApiRequest {
    fn validate(&self) -> ValidationResult<()> {
        let mut results = vec![
            Validator::validate_ethereum_address(&self.wallet_address, "wallet_address"),
            Validator::validate_ipfs_uri(&self.token_uri, "token_uri"),
            Validator::validate_hex_string(&self.metadata_hash, "metadata_hash", Some(64)),
        ];

        if let Some(royalty) = self.royalty_bps {
            results.push(Validator::validate_basis_points(royalty, "royalty_bps"));
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

/// Get all collections from the database (populated by blockchain events)
pub async fn get_all_collections(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    // Use collections repository to get collections from database
    let collections_repository = CollectionsRepository::new(state.pool);

    // Parse pagination parameters
    let limit = params.get("limit").and_then(|s| s.parse::<i64>().ok());
    let offset = params.get("offset").and_then(|s| s.parse::<i64>().ok());

    match collections_repository.get_collections_paginated(limit, offset).await {
        Ok((collections, total_count)) => {
            // Convert database collections to API response format
            let api_collections: Vec<Collection> = collections
                .into_iter()
                .map(|db_collection| Collection {
                    collection_id: db_collection.collection_id as u64,
                    chain_id: db_collection.chain_id as u64,
                    name: Arc::from(db_collection.name),
                    symbol: Arc::from(db_collection.symbol),
                    image: Arc::from(db_collection.image.unwrap_or_default()),
                    max_supply: db_collection.max_supply as u16,
                    creator: Arc::from(db_collection.creator_address),
                    current_supply: db_collection.current_supply as u16,
                    total_volume_wei: db_collection.total_volume_wei,
                    floor_price_wei: db_collection.floor_price_wei,
                })
                .collect();

            Ok(Json(serde_json::json!({
                "success": true,
                "data": {
                    "collections": api_collections,
                    "total_count": total_count,
                    "limit": limit.unwrap_or(50),
                    "offset": offset.unwrap_or(0)
                },
                "message": "Collections retrieved successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&format!("Database error: {}", e)))
        }
    }
}

/// Helper function to get collection name from collection_id
async fn get_collection_name_from_id(collection_id: Option<u64>, pool: &sqlx::PgPool) -> Option<String> {
    if let Some(id) = collection_id {
        match sqlx::query_scalar::<_, String>(
            "SELECT name FROM collections WHERE collection_id = $1"
        )
        .bind(id as i64)
        .fetch_optional(pool)
        .await {
            Ok(Some(name)) => Some(name),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Failed to fetch collection name for id {}: {}", id, e);
                None
            }
        }
    } else {
        None
    }
}

/// Determine asset type based on contract address and metadata
fn determine_asset_type(nft_contract: &str, metadata: &Option<serde_json::Value>) -> (u8, String) {
    // Check if this is a social media NFT based on metadata
    if let Some(meta) = metadata {
        if let Some(platform) = meta.get("platform").and_then(|v| v.as_str()) {
            match platform.to_lowercase().as_str() {
                "twitter" | "x" => return (1, "Social Media".to_string()),
                "instagram" => return (1, "Social Media".to_string()),
                "tiktok" => return (1, "Social Media".to_string()),
                "youtube" => return (1, "Social Media".to_string()),
                "facebook" => return (1, "Social Media".to_string()),
                "linkedin" => return (1, "Social Media".to_string()),
                _ => {}
            }
        }

        // Check for website indicators (only if it's not a marketplace URL)
        if let Some(external_url) = meta.get("external_url").and_then(|v| v.as_str()) {
            if external_url.starts_with("http") && !external_url.contains("twitter.com") && 
               !external_url.contains("instagram.com") && !external_url.contains("tiktok.com") &&
               !external_url.contains("vertix.market") && !external_url.contains("opensea.io") &&
               !external_url.contains("foundation.app") && !external_url.contains("superrare.co") {
                return (2, "Website".to_string());
            }
        }

        // Check for domain indicators
        if let Some(domain) = meta.get("domain").and_then(|v| v.as_str()) {
            if domain.contains(".") && !domain.contains("twitter") && !domain.contains("instagram") {
                return (3, "Domain".to_string());
            }
        }

        // Check for application indicators
        if let Some(application) = meta.get("application").and_then(|v| v.as_str()) {
            match application.to_lowercase().as_str() {
                "mobile_app" | "software" => return (5, "Application".to_string()),
                _ => {}
            }
        }

        // Check for youtube indicators
        if let Some(youtube) = meta.get("youtube").and_then(|v| v.as_str()) {
            match youtube.to_lowercase().as_str() {
                "youtube" => return (6, "YouTube".to_string()),
                _ => {}
            }
        }
    }

    // Check contract-specific patterns (you can expand this based on known contract addresses)
    match nft_contract.to_lowercase().as_str() {
        // Known Vertix NFT contract
        "0xf99c6514473ba9ef1c930837e1ff4eac19d2537b" => {
            // Check if this is a social media NFT based on metadata patterns
            if let Some(meta) = metadata {
                if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("twitter") || name_lower.contains("instagram") || 
                       name_lower.contains("tiktok") || name_lower.contains("youtube") {
                        return (1, "Social Media".to_string());
                    }
                }
            }
            (0, "NFT".to_string()) // Default to NFT for this contract
        },
        // Add more known contract addresses here
        _ => (0, "NFT".to_string()) // Default to NFT
    }
}

/// Get all active NFT listings in the marketplace
pub async fn get_all_listings(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    let limit = params.get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(100);

    let offset = params.get("offset")
        .and_then(|o| o.parse::<i64>().ok())
        .unwrap_or(0);


    let min_price = params.get("min_price").and_then(|p| p.parse::<f64>().ok());
    let max_price = params.get("max_price").and_then(|p| p.parse::<f64>().ok());
    let is_auction = params.get("is_auction").and_then(|a| a.parse::<bool>().ok());
    let asset_type = params.get("asset_type").and_then(|a| a.parse::<u8>().ok());

    // Get chain configuration
    let chain_config = config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    let repository = NftListingEventsRepository::new(state.pool.clone());
    let nft_events_repo = NftEventsRepository::new(state.pool.clone());

    // Convert price filters from ETH to Wei
    let min_price_wei = min_price.map(|p| (p * 1e18) as u128);
    let max_price_wei = max_price.map(|p| (p * 1e18) as u128);

    match repository.get_all_active_listings(
        chain_config.chain_id,
        Some(limit),
        Some(offset),
        asset_type,
        min_price_wei,
        max_price_wei,
        is_auction,
    ).await {
        Ok(listings) => {
            // Fetch metadata for each NFT and enrich the response
            let mut enriched_listings = Vec::new();

            for listing in listings {
                // Try to fetch metadata from IPFS if available
                let mut metadata = None;
                let mut _nft_event_data = None;

                if !listing.nft_contract.is_empty() {
                    // Get NFT metadata from the events table using token ID and seller address
                    if let Ok(Some(nft_event)) = nft_events_repo.get_nft_mint_event_by_token_and_owner(
                        chain_config.chain_id,
                        listing.token_id as u64,
                        &listing.seller_address
                    ).await {
                        _nft_event_data = Some(nft_event.clone());
                        if let Ok(metadata_json) = fetch_ipfs_metadata(&nft_event.token_uri).await {
                            metadata = Some(metadata_json);
                        }
                    }
                }

                // Determine asset type based on contract and metadata
                let asset_type = determine_asset_type(&listing.nft_contract, &metadata);

                let enriched_listing = serde_json::json!({
                    "listing_id": listing.listing_id,
                    "token_id": listing.token_id,
                    "seller_address": listing.seller_address,
                    "price_wei": listing.price_wei,
                    "is_auction": listing.is_auction,
                    "auction_end_time": listing.auction_end_time,
                    // Asset Type Information
                    "asset_type": asset_type.0, // 0=NFT, 1=Social Media, 2=Website, 3=Domain, 4=Digital Asset
                    "asset_type_name": asset_type.1,
                    // Asset Details
                    "name": metadata.as_ref().and_then(|m| m.get("name").and_then(|v| v.as_str())).unwrap_or(&format!("{} #{}{}", asset_type.1, listing.token_id, if listing.is_auction { " (Auction)" } else { "" })),
                    "image": metadata.as_ref().and_then(|m| m.get("image").and_then(|v| v.as_str())).unwrap_or("/images/placeholder-nft.svg"),
                });

                enriched_listings.push(enriched_listing);
            }

            Ok(Json(serde_json::json!({
                "success": true,
                "data": enriched_listings,
                "message": "Listings retrieved successfully"
            })))
        }
        Err(e) => {
            Err(ApiError::internal_server_error(&format!("Failed to fetch listings: {}", e)))
        }
    }
}

/// Get a single listing by ID
pub async fn get_listing_by_id(
    Path(listing_id): Path<u64>,
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let chain_config = config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    let repository = NftListingEventsRepository::new(state.pool.clone());
    let nft_events_repo = NftEventsRepository::new(state.pool.clone());

    match repository.get_listing_by_id(chain_config.chain_id, listing_id).await {
        Ok(Some(listing)) => {
            // Try to fetch metadata from IPFS if available
            let mut metadata = None;
            let mut nft_event_data = None;

            if !listing.nft_contract.is_empty() {
                // Get NFT metadata from the events table using token ID and seller address
                if let Ok(Some(nft_event)) = nft_events_repo.get_nft_mint_event_by_token_and_owner(
                    chain_config.chain_id,
                    listing.token_id as u64,
                    &listing.seller_address
                ).await {
                    nft_event_data = Some(nft_event.clone());
                    if let Ok(metadata_json) = fetch_ipfs_metadata(&nft_event.token_uri).await {
                        metadata = Some(metadata_json);
                    }
                }
            }

            // Determine asset type based on contract and metadata
            let asset_type = determine_asset_type(&listing.nft_contract, &metadata);

            let enriched_listing = serde_json::json!({
                "listing_id": listing.listing_id,
                "nft_contract": listing.nft_contract,
                "token_id": listing.token_id,
                "seller_address": listing.seller_address,
                "price_wei": listing.price_wei,
                "is_auction": listing.is_auction,
                "auction_end_time": listing.auction_end_time,
                "reserve_price_wei": listing.reserve_price_wei,
                "transaction_hash": listing.transaction_hash,
                "block_number": listing.block_number,
                "event_type": listing.event_type,
                "created_at": listing.created_at,
                // Asset Type Information
                "asset_type": asset_type.0,
                "asset_type_name": asset_type.1,
                // Asset Details
                "name": metadata.as_ref().and_then(|m| m.get("name").and_then(|v| v.as_str())).unwrap_or(&format!("{} #{}{}", asset_type.1, listing.token_id, if listing.is_auction { " (Auction)" } else { "" })),
                "description": metadata.as_ref().and_then(|m| m.get("description").and_then(|v| v.as_str())).unwrap_or(&format!("A {} listed on the marketplace", asset_type.1.to_lowercase())),
                "image": metadata.as_ref().and_then(|m| m.get("image").and_then(|v| v.as_str())).unwrap_or("/images/placeholder-nft.svg"),
                "external_url": metadata.as_ref().and_then(|m| m.get("external_url").and_then(|v| v.as_str())),
                "animation_url": metadata.as_ref().and_then(|m| m.get("animation_url").and_then(|v| v.as_str())),
                "attributes": metadata.as_ref().and_then(|m| m.get("attributes").and_then(|v| v.as_array())).unwrap_or(&vec![]),
                "collection_name": get_collection_name_from_id(nft_event_data.as_ref().and_then(|e| e.collection_id.map(|id| id as u64)), &state.pool).await,
                "royalty_recipient": nft_event_data.as_ref().map(|e| e.royalty_recipient.clone()).unwrap_or_default(),
                "royalty_bps": nft_event_data.as_ref().map(|e| e.royalty_bps).unwrap_or(0),
                "token_uri": nft_event_data.as_ref().map(|e| e.token_uri.clone()).unwrap_or_default(),
                "metadata_hash": nft_event_data.as_ref().map(|e| e.metadata_hash.clone()).unwrap_or_default(),
                "metadata": metadata
            });

            Ok(Json(serde_json::json!({
                "success": true,
                "data": enriched_listing,
                "message": "Listing retrieved successfully"
            })))
        }
        Ok(None) => {
            Err(ApiError::not_found("Listing not found"))
        }
        Err(e) => {
            tracing::error!("Failed to fetch listing {}: {}", listing_id, e);
            Err(ApiError::internal_server_error("Failed to fetch listing"))
        }
    }
}

/// Get NFTs owned by a user
pub async fn get_user_nfts(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    let wallet_address = params.get("wallet_address")
        .ok_or_else(|| ApiError::BadRequest("wallet_address parameter is required".to_string()))?;

    let limit = params.get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(100);

    let offset = params.get("offset")
        .and_then(|o| o.parse::<i64>().ok())
        .unwrap_or(0);

    // Use the NFT events repository to get real data from the database
    let nft_events_repository = NftEventsRepository::new(state.pool.clone());
    let collections_repository = CollectionsRepository::new(state.pool.clone());
    let listing_events_repository = NftListingEventsRepository::new(state.pool.clone());

    match nft_events_repository.get_nft_mint_events_by_address(wallet_address, Some(limit), Some(offset)).await {
        Ok(nft_events) => {
            // Get all collections to enhance NFT data
            let collections = collections_repository.get_all_collections(None, None).await.unwrap_or_default();
            let collections_map: std::collections::HashMap<i64, _> = collections
                .into_iter()
                .map(|c| (c.collection_id, c))
                .collect();

            // Convert NFT mint events to API response format with real metadata
            let mut nfts = Vec::new();
            for event in nft_events {
                let collection_name = event.collection_id
                    .and_then(|id| collections_map.get(&id))
                    .map(|c| c.name.clone())
                    .unwrap_or_default();

                // Try to fetch real metadata from IPFS if token_uri is available
                let (name, description, image, metadata_uri) = if !event.token_uri.is_empty() {
                    match fetch_ipfs_metadata(&event.token_uri).await {
                        Ok(metadata) => {
                            // Extract fields from metadata
                            let name = metadata.get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();

                            let description = metadata.get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();

                            let image = metadata.get("image")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string();

                            (name, description, image, event.token_uri.clone())
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch metadata for token {}: {:?}", event.token_id, e);
                            // Return empty values if metadata fetch fails
                            (
                                String::new(),
                                String::new(),
                                String::new(),
                                event.token_uri.clone(),
                            )
                        }
                    }
                } else {
                    // No token_uri available, return empty values
                    (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    )
                };

                // Check if this NFT is currently listed
                let listing_info = if let Some(collection_id) = event.collection_id {
                    // For collection NFTs, we need to get the contract address
                    // For now, we'll use a placeholder - in production, you'd get this from the collection
                    let nft_contract = format!("0x{:040x}", collection_id); // Placeholder contract address
                    listing_events_repository.get_active_listing_for_nft(
                        event.chain_id as u64,
                        &nft_contract,
                        event.token_id as u64,
                    ).await.unwrap_or(None)
                } else {
                    None
                };

                let (is_listed, listing_price, listing_id, is_auction) = if let Some(listing) = listing_info {
                    (
                        true,
                        Some(listing.price_wei),
                        Some(listing.listing_id),
                        listing.is_auction,
                    )
                } else {
                    (false, None, None, false)
                };

                nfts.push(serde_json::json!({
                    "id": event.id.to_string(),
                    "token_id": event.token_id,
                    "collection_id": event.collection_id,
                    "collection_name": collection_name,
                    "chain_id": event.chain_id,
                    "owner": event.to_address,
                    "transaction_hash": event.transaction_hash,
                    "block_number": event.block_number,
                    "minted_at": event.created_at.to_rfc3339(),
                    "name": name,
                    "description": description,
                    "image": image,
                    "metadata_uri": metadata_uri,
                    "is_listed": is_listed,
                    "listing_price": listing_price,
                    "listing_id": listing_id,
                    "is_auction": is_auction,
                    "royalty_bps": event.royalty_bps,
                }));
            }

            Ok(Json(serde_json::json!({
                "success": true,
                "data": nfts,
                "message": format!("Found {} NFTs for address {}", nfts.len(), wallet_address)
            })))
        }
        Err(e) => {
            tracing::error!("Failed to get NFT mint events: {}", e);
            Ok(Json(serde_json::json!({
                "success": true,
                "data": [],
                "message": format!("Database error: {}", e)
            })))
        }
    }
}

/// Get creator dashboard overview stats
pub async fn get_creator_overview(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    let wallet_address = params.get("wallet_address")
        .ok_or_else(|| ApiError::BadRequest("wallet_address parameter is required".to_string()))?;

    // Get repositories
    let nft_events_repository = NftEventsRepository::new(state.pool.clone());
    let collections_repository = CollectionsRepository::new(state.pool.clone());
    let listing_events_repository = NftListingEventsRepository::new(state.pool.clone());

    // Get all collections created by the creator across all chains
    let collections = collections_repository
        .get_collections_by_creator(wallet_address)
        .await
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to get collections: {}", e)))?;

    let total_collections = collections.len() as u32;

    // Calculate total volume from all collections across all chains
    let total_volume_wei: u128 = collections
        .iter()
        .filter_map(|c| c.total_volume_wei.as_ref())
        .filter_map(|v| v.parse::<u128>().ok())
        .sum();

    // Convert wei to ETH (assuming 18 decimals)
    let total_volume_eth = total_volume_wei as f64 / 1e18;

    // Get total NFTs owned by the creator across all chains
    let total_nfts = nft_events_repository
        .get_nft_mint_events_by_address(wallet_address, None, None)
        .await
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to get NFTs: {}", e)))?
        .len() as u32;

    // Get listed NFTs count across all chains
    let mut total_listed_nfts = 0u32;
    for collection in &collections {
        let listed_nfts = listing_events_repository
            .get_active_listings_for_seller(collection.chain_id as u64, wallet_address, None, None)
            .await
            .map_err(|e| ApiError::internal_server_error(&format!("Failed to get listings for chain {}: {}", collection.chain_id, e)))?;
        total_listed_nfts += listed_nfts.len() as u32;
    }

    // Get recent activity (last 10 NFT events across all chains)
    let recent_nfts = nft_events_repository
        .get_nft_mint_events_by_address(wallet_address, Some(10), Some(0))
        .await
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to get recent NFTs: {}", e)))?;

    let recent_activity: Vec<serde_json::Value> = recent_nfts
        .into_iter()
        .map(|nft| {
            serde_json::json!({
                "id": nft.id.to_string(),
                "type": "mint",
                "nftName": format!("Token #{}", nft.token_id),
                "timestamp": nft.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                "collectionId": nft.collection_id,
                "tokenId": nft.token_id,
                "chainId": nft.chain_id
            })
        })
        .collect();

    // Get chain-specific breakdown
    let chain_breakdown: Vec<serde_json::Value> = collections
        .iter()
        .map(|collection| {
            serde_json::json!({
                "chainId": collection.chain_id,
                "collectionId": collection.collection_id,
                "name": collection.name,
                "totalVolume": collection.total_volume_wei.as_ref()
                    .and_then(|v| v.parse::<u128>().ok())
                    .map(|wei| wei as f64 / 1e18)
                    .unwrap_or(0.0),
                "floorPrice": collection.floor_price_wei.as_ref()
                    .and_then(|v| v.parse::<u128>().ok())
                    .map(|wei| wei as f64 / 1e18)
                    .unwrap_or(0.0),
                "currentSupply": collection.current_supply,
                "maxSupply": collection.max_supply
            })
        })
        .collect();

    let overview_data = serde_json::json!({
        "totalNfts": total_nfts,
        "totalCollections": total_collections,
        "listedNfts": total_listed_nfts,
        "totalVolume": total_volume_eth,
        "recentActivity": recent_activity,
        "chainBreakdown": chain_breakdown
    });

    Ok(Json(serde_json::json!({
        "success": true,
        "data": overview_data,
        "message": "Creator overview retrieved successfully"
    })))
}

/// Get current chain configuration and contract addresses
pub async fn get_chain_info(
    State(_state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Get current chain configuration
    let chain_config = config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&format!("Failed to get chain config: {}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "chain": {
                "id": chain_config.chain_id,
                "name": chain_config.name,
                "type": format!("{:?}", chain_config.chain_type),
                "rpc_url": chain_config.rpc_url,
                "explorer_url": chain_config.explorer_url,
                "native_currency": {
                    "name": chain_config.native_currency.name,
                    "symbol": chain_config.native_currency.symbol,
                    "decimals": chain_config.native_currency.decimals
                }
            },
            "contracts": {
                "vertix_nft": format!("{:?}", chain_config.contract_addresses.vertix_nft),
                "vertix_escrow": format!("{:?}", chain_config.contract_addresses.vertix_escrow),
                "vertix_governance": format!("{:?}", chain_config.contract_addresses.vertix_governance)
            }
        },
        "message": "Chain information retrieved successfully"
    })))
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

// ============ UTILITY OPERATIONS ============

/// Get network information
pub async fn get_network_info(
    State(_state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Get current chain configuration
    let chain_config = config::get_current_chain_config()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "chain_id": chain_config.chain_id,
            "chain_name": chain_config.name,
            "chain_type": match chain_config.chain_type {
                types::ChainType::Polygon => "polygon",
                types::ChainType::Base => "base",
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

/// Get all supported chains information
pub async fn get_supported_chains(
    State(_state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    // Get all supported chain configurations
    let supported_chains = config::get_supported_chains()
        .map_err(|e| ApiError::internal_server_error(&e.to_string()))?;

    let chains_data: Vec<serde_json::Value> = supported_chains.into_iter().map(|chain_config| {
        serde_json::json!({
            "chain_id": chain_config.chain_id,
            "chain_name": chain_config.name,
            "chain_type": match chain_config.chain_type {
                types::ChainType::Polygon => "polygon",
                types::ChainType::Base => "base",
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