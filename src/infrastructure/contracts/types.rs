use serde::{Deserialize, Serialize};
use ethers::types::{Address};

// ============ CONTRACT INTERACTION TYPES ============

/// Request to mint an NFT
#[derive(Debug, Serialize, Deserialize)]
pub struct MintNftRequest {
    pub token_uri: String,
    pub metadata_hash: String,
    pub collection_id: Option<u64>,
    pub royalty_bps: Option<u64>, // Royalty percentage in basis points (e.g., 500 = 5%)
}

/// Request to list an NFT for sale
#[derive(Debug, Serialize, Deserialize)]
pub struct ListNftRequest {
    pub nft_contract: String,
    pub token_id: u64,
    pub price: String, // Price in wei as string
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

/// Request to place a bid
#[derive(Debug, Serialize, Deserialize)]
pub struct PlaceBidRequest {
    pub listing_id: u64,
}

/// Request to list a non-NFT asset (social media account, website, etc.)
#[derive(Debug, Serialize, Deserialize)]
pub struct ListNonNftAssetRequest {
    pub asset_type: u8, // 1 = SocialMedia, 2 = Website, 3 = Domain, etc.
    pub asset_id: String,
    pub price: String,
    pub description: String,
    pub verification_proof: String,
}

/// Request to buy a non-NFT asset
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNonNftAssetRequest {
    pub listing_id: u64,
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

// ============ RESPONSE TYPES ============

/// Response for NFT minting
#[derive(Debug, Serialize, Deserialize)]
pub struct MintNftResponse {
    pub token_id: u64,
    pub transaction_hash: String,
    pub block_number: u64,
}

/// Response for listing creation
#[derive(Debug, Serialize, Deserialize)]
pub struct ListNftResponse {
    pub listing_id: u64,
    pub transaction_hash: String,
}

/// Response for NFT purchase
#[derive(Debug, Serialize, Deserialize)]
pub struct BuyNftResponse {
    pub transaction_hash: String,
    pub new_owner: String,
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

/// Response for asset bridging
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeAssetResponse {
    pub request_id: String,
    pub transaction_hash: String,
    pub bridge_fee: String,
}

// ============ CONTRACT STATE TYPES ============

/// NFT listing information
#[derive(Debug, Serialize, Deserialize)]
pub struct NftListing {
    pub listing_id: u64,
    pub seller: String,
    pub nft_contract: String,
    pub token_id: u64,
    pub price: String,
    pub active: bool,
    pub is_auction: bool,
    pub created_at: u64,
}

/// Auction information
#[derive(Debug, Serialize, Deserialize)]
pub struct Auction {
    pub listing_id: u64,
    pub seller: String,
    pub nft_contract: String,
    pub token_id: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub reserve_price: String,
    pub current_bid: Option<String>,
    pub current_bidder: Option<String>,
    pub active: bool,
}

/// Non-NFT asset listing
#[derive(Debug, Serialize, Deserialize)]
pub struct NonNftListing {
    pub listing_id: u64,
    pub seller: String,
    pub asset_type: u8,
    pub asset_id: String,
    pub price: String,
    pub description: String,
    pub verification_proof: String,
    pub active: bool,
    pub created_at: u64,
}

/// Escrow information
#[derive(Debug, Serialize, Deserialize)]
pub struct Escrow {
    pub listing_id: u64,
    pub seller: String,
    pub buyer: String,
    pub amount: String,
    pub completed: bool,
    pub disputed: bool,
    pub created_at: u64,
}

// ============ CONTRACT CONFIGURATION TYPES ============

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub explorer_url: String,
    pub native_currency: NativeCurrency,
}

/// Native currency information
#[derive(Debug, Clone)]
pub struct NativeCurrency {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

/// Contract addresses for a network
#[derive(Debug, Clone)]
pub struct ContractAddresses {
    pub vertix_nft: Address,
    pub vertix_governance: Address,
    pub vertix_escrow: Address,
    pub marketplace_core: Address,
    pub marketplace_auctions: Address,
    pub marketplace_fees: Address,
    pub marketplace_storage: Address,
    pub marketplace_proxy: Address,
    pub cross_chain_bridge: Address,
    pub cross_chain_registry: Address,
}

// ============ ERROR TYPES ============

/// Contract interaction errors
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Transaction failed: {0}")]
    TransactionError(String),

    #[error("Contract call failed: {0}")]
    ContractCallError(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: String, available: String },

    #[error("Listing not found: {listing_id}")]
    ListingNotFound { listing_id: u64 },

    #[error("Auction not found: {auction_id}")]
    AuctionNotFound { auction_id: u64 },

    #[error("Auction ended: {auction_id}")]
    AuctionEnded { auction_id: u64 },

    #[error("Bid too low: current {current}, minimum {minimum}")]
    BidTooLow { current: String, minimum: String },

    #[error("Not authorized: {operation}")]
    NotAuthorized { operation: String },

    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("Bridge error: {reason}")]
    BridgeError { reason: String },

    #[error("Escrow error: {reason}")]
    EscrowError { reason: String },

    #[error("Invalid uint96 value: {reason}")]
    InvalidUint96Value { reason: String },
}

// ============ UTILITY TYPES ============

/// Asset types supported by the marketplace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    Nft = 1,
    SocialMedia = 2,
    Website = 3,
    Domain = 4,
    Application = 5,
}

/// Chain types for cross-chain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Polygon = 1,
    Base = 2,
}

/// Transaction status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Bridge status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
} 