use axum::{
    extract::{State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use crate::{
    handlers::routes::AppState,
    domain::models::{MintNftRequest, MintNftResponse},
    infrastructure::contracts::types::NetworkConfig,
    application::services::contract_service::ContractService,
};

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

// ============ NFT OPERATIONS ============

/// Mint a new NFT
pub async fn mint_nft(
    State(_state): State<AppState>,
    Json(request): Json<MintNftApiRequest>,
) -> Result<Json<ApiResponse<MintNftResponse>>, StatusCode> {
    let contract_request = MintNftRequest {
        to: Arc::from(request.wallet_address.clone()),
        token_uri: Arc::from(request.token_uri),
        metadata_hash: Arc::from(request.metadata_hash),
        collection_id: request.collection_id,
        royalty_bps: request.royalty_bps,
    };

    // Create contract service for this request
    let contract_service = match ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"),
        31337, // Default chain ID
    ).await {
        Ok(service) => service,
        Err(e) => {
            return Ok(Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create contract service: {}", e)),
            }));
        }
    };

    match contract_service.mint_nft(request.wallet_address.to_string(), contract_request).await {
        Ok(response) => {
            Ok(Json(ApiResponse {
                success: true,
                data: Some(response),
                error: None,
            }))
        }
        Err(e) => {
            Ok(Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to mint NFT: {}", e)),
            }))
        }
    }
}


// ============ UTILITY OPERATIONS ============

/// Get network information
pub async fn get_network_info(
    State(_state): State<AppState>,
) -> Result<Json<ApiResponse<NetworkConfig>>, StatusCode> {
    // Create contract service for this request
    let contract_service = match ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"),
        31337, // Default chain ID
    ).await {
        Ok(service) => service,
        Err(e) => {
            return Ok(Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create contract service: {}", e)),
            }));
        }
    };

    let network_config = contract_service.get_network_config().clone();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(network_config),
        error: None,
    }))
}

/// Check contract service connection
pub async fn check_connection(
    State(_state): State<AppState>,
) -> Result<Json<ApiResponse<bool>>, StatusCode> {
    // Create contract service for this request
    let contract_service = match ContractService::new(
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"),
        31337, // Default chain ID
    ).await {
        Ok(service) => service,
        Err(e) => {
            return Ok(Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create contract service: {}", e)),
            }));
        }
    };

    let is_connected = contract_service.is_connected().await;
    Ok(Json(ApiResponse {
        success: true,
        data: Some(is_connected),
        error: None,
    }))
} 