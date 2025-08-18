use serde::{Deserialize, Serialize};
use ethers::types::{Address};

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

/// Chain-specific configuration
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub chain_type: ChainType,
    pub name: String,
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub explorer_url: String,
    pub native_currency: NativeCurrency,
    pub gas_settings: GasSettings,
    pub contract_addresses: ContractAddresses,
}

/// Gas settings for different chains
#[derive(Debug, Clone)]
pub struct GasSettings {
    pub default_gas_limit: u64,
    pub max_gas_limit: u64,
    pub gas_price_strategy: GasPriceStrategy,
    pub block_time_seconds: u64,
}

/// Gas price strategy for different chains
#[derive(Debug, Clone)]
pub enum GasPriceStrategy {
    Fixed(u64),
    Dynamic,
    Eip1559,
}

/// Multi-chain configuration
#[derive(Debug, Clone)]
pub struct MultiChainConfig {
    pub current_chain: ChainConfig,
    pub supported_chains: Vec<ChainConfig>,
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