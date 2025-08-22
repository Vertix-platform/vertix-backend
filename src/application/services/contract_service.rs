use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use regex;
use crate::infrastructure::contracts::client::{ContractClient, ReadOnlyContractClient};
use crate::infrastructure::contracts::config::{get_current_chain_config, get_private_key};
use crate::infrastructure::contracts::types::ChainConfig;
use crate::infrastructure::repositories::{
    ListingRepository,
    NftListingData,
    NonNftListingData,
    SocialMediaNftListingData,
    CombinedListingData
};
use crate::domain::models::{
    MintNftRequest, MintNftResponse, User,
    ListNonNftAssetRequest, ListNonNftAssetResponse,
    CreateCollectionRequest, CreateCollectionResponse,
    MintNftToCollectionRequest, MintNftToCollectionResponse,
    MintSocialMediaNftRequest, MintSocialMediaNftResponse,
    InitiateSocialMediaNftMintRequest, InitiateSocialMediaNftMintResponse,
    ListNftRequest, ListNftResponse,
    ListSocialMediaNftRequest, ListNftForAuctionRequest, ListNftForAuctionResponse,
    BuyNftRequest, BuyNftResponse, BuyNonNftAssetRequest, BuyNonNftAssetResponse,
    CancelNftListingRequest, CancelNftListingResponse, CancelNonNftListingRequest, CancelNonNftListingResponse,
    ConfirmTransferRequest, ConfirmTransferResponse, RaiseDisputeRequest, RaiseDisputeResponse,
    RefundRequest, RefundResponse, Escrow,
    // NftListing, NonNftListing, SocialMediaNftListing,
};

// Marketplace statistics
#[derive(Debug, Clone)]
pub struct MarketplaceStats {
    pub total_active_listings: u64,
    pub nft_listings: u64,
    pub non_nft_listings: u64,
    pub social_media_nft_listings: u64,
}
use crate::domain::services::ContractError;
use crate::infrastructure::contracts::utils::verification::VerificationService;
use crate::api::v1::contracts::ListSocialMediaNftApiRequest;
use crate::domain::models::Collection;
/// Service layer for contract operations
/// This provides a higher-level interface that handles wallet connection and business logic
pub struct ContractService {
    client: Arc<RwLock<ContractClient>>,
    chain_config: ChainConfig,
    listing_repository: ListingRepository,
}

pub struct ReadOnlyContractService {
    client: Arc<RwLock<ReadOnlyContractClient>>,
    chain_config: ChainConfig,
    listing_repository: ListingRepository,
}

impl ContractService {
    /// Create a new contract service using current chain configuration
    pub async fn new(
        rpc_url: String,
        private_key: String,
        chain_id: u64,
        db_pool: PgPool,
    ) -> Result<Self, ContractError> {
        // Get current chain configuration
        let chain_config = get_current_chain_config()?;

        // Validate that the requested chain ID matches the current configuration
        if chain_config.chain_id != chain_id {
            return Err(ContractError::InvalidAddress(format!(
                "Chain ID mismatch: requested {}, configured {}",
                chain_id, chain_config.chain_id
            )));
        }

        // Create verification service
        let verification_service = VerificationService::new(&private_key)?;

        // Create contract client
        let client = ContractClient::new(
            rpc_url,
            private_key,
            chain_config.clone(),
            verification_service,
        ).await?;

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            chain_config,
            listing_repository: ListingRepository::new(db_pool),
        })
    }

    /// Create a new contract service with automatic private key handling
    pub async fn new_with_auto_private_key(
        rpc_url: String,
        chain_id: u64,
        db_pool: PgPool,
    ) -> Result<Self, ContractError> {
        let private_key = get_private_key()?;
        Self::new(rpc_url, private_key, chain_id, db_pool).await
    }

    /// Create a read-only contract service for view functions
    pub async fn new_read_only(
        rpc_url: String,
        chain_id: u64,
        db_pool: PgPool,
    ) -> Result<ReadOnlyContractService, ContractError> {
        // Get current chain configuration
        let chain_config = get_current_chain_config()?;

        // Validate that the requested chain ID matches the current configuration
        if chain_config.chain_id != chain_id {
            return Err(ContractError::InvalidAddress(format!(
                "Chain ID mismatch: requested {}, configured {}", 
                chain_id, chain_config.chain_id
            )));
        }

        // Create read-only contract client
        let client = ReadOnlyContractClient::new(
            rpc_url,
            chain_config.clone(),
        ).await?;

        Ok(ReadOnlyContractService {
            client: Arc::new(RwLock::new(client)),
            chain_config,
            listing_repository: ListingRepository::new(db_pool),
        })
    }

    /// Create a collection (requires wallet connection only)
    pub async fn create_collection(&self, wallet_address: String, request: CreateCollectionRequest) -> Result<CreateCollectionResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to create the collection
        let client = self.client.read().await;
        client.create_collection(request).await
    }

    /// Mint an NFT to a collection (requires wallet connection only)
    pub async fn mint_nft_to_collection(&self, wallet_address: String, request: MintNftToCollectionRequest) -> Result<MintNftToCollectionResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to mint the NFT to the collection
        let client = self.client.read().await;
        client.mint_nft_to_collection(request).await
    }

    /// Mint an NFT (requires wallet connection only)
    pub async fn mint_nft(&self, wallet_address: String, request: MintNftRequest) -> Result<MintNftResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to mint the NFT
        let client = self.client.read().await;
        client.mint_nft(request).await
    }

    pub async fn mint_social_media_nft(&self, wallet_address: String, request: MintSocialMediaNftRequest) -> Result<MintSocialMediaNftResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to mint the social media NFT
        let client = self.client.read().await;
        client.mint_social_media_nft(request).await
    }

    /// Initiate social media NFT minting process
    /// This function generates all necessary data including signature for the minting process
    pub async fn initiate_social_media_nft_mint(
        &self,
        wallet_address: String,
        request: InitiateSocialMediaNftMintRequest,
    ) -> Result<InitiateSocialMediaNftMintResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Get wallet address for signature generation
        let client = self.client.read().await;
        let user_address = client.get_wallet_address();

        // Use verification service to process the request and generate signature
        let verification_service = client.get_verification_service();
        verification_service.process_social_media_nft_mint(&user_address, &request).await
    }

    // AUTHENTICATED OPERATIONS

    /// Confirm transfer in escrow (buyer confirms they received the asset)
    pub async fn confirm_transfer(
        &self,
        user: &User,
        wallet_address: String,
        request: ConfirmTransferRequest
    ) -> Result<ConfirmTransferResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to confirm transfer
        let client = self.client.read().await;
        client.confirm_transfer(request).await
    }

    /// Raise a dispute in escrow (can be called by either seller or buyer)
    pub async fn raise_dispute(
        &self,
        user: &User,
        wallet_address: String,
        request: RaiseDisputeRequest
    ) -> Result<RaiseDisputeResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to raise dispute
        let client = self.client.read().await;
        client.raise_dispute(request).await
    }

    /// Refund escrow if deadline has passed (anyone can call this)
    pub async fn refund(
        &self,
        user: &User,
        wallet_address: String,
        request: RefundRequest
    ) -> Result<RefundResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to process refund
        let client = self.client.read().await;
        client.refund(request).await
    }

    /// List an NFT for sale (wallet-only operation)
    pub async fn list_nft(
        &self,
        wallet_address: String,
        request: ListNftRequest
    ) -> Result<ListNftResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to list NFT
        let client = self.client.read().await;
        let response = client.list_nft(request.clone()).await?;

        // Store listing in database
        let db_listing = NftListingData {
            id: uuid::Uuid::new_v4(),
            listing_id: response.listing_id as i64,
            creator_address: response.creator.to_string(),
            nft_contract: request.nft_contract.to_string(),
            token_id: request.token_id as i64,
            price: request.price as i64,
            description: request.description.to_string(),
            active: response.active,
            is_auction: response.is_auction,
            metadata_uri: None, // Could be added later if needed
            transaction_hash: response.transaction_hash.clone(),
            block_number: response.block_number as i64,
            created_at: sqlx::types::chrono::Utc::now(),
            updated_at: sqlx::types::chrono::Utc::now(),
        };

        self.listing_repository.create_nft_listing(&db_listing).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        Ok(response)
    }

    /// List a non-NFT asset for sale (requires user authentication + wallet connection)
    pub async fn list_non_nft_asset(
        &self,
        user: &User,
        wallet_address: String,
        request: ListNonNftAssetRequest
    ) -> Result<ListNonNftAssetResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Validate request parameters
        self.validate_non_nft_listing_request(&request).await?;

        // Call the client to list non-NFT asset
        let client = self.client.read().await;
        let response = client.list_non_nft_asset(request.clone()).await?;

        // Parse asset identifier to extract platform and identifier
        let (platform, identifier) = self.parse_asset_identifier(&request.asset_id, request.asset_type)?;

        // Store listing in database
        let db_listing = NonNftListingData {
            id: uuid::Uuid::new_v4(),
            listing_id: response.listing_id as i64,
            creator_address: response.creator.to_string(),
            asset_type: request.asset_type as i16,
            asset_id: request.asset_id.to_string(),
            price: request.price as i64,
            description: request.description.to_string(),
            platform: Some(platform),
            identifier: Some(identifier),
            metadata_uri: Some(response.metadata.to_string()),
            verification_proof: Some(response.verification_proof.to_string()),
            transaction_hash: response.transaction_hash.to_string(),
            block_number: response.block_number as i64,
            created_at: sqlx::types::chrono::Utc::now(),
            updated_at: sqlx::types::chrono::Utc::now(),
        };

        self.listing_repository.create_non_nft_listing(&db_listing).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        Ok(response)
    }

    /// Validate non-NFT listing request parameters
    async fn validate_non_nft_listing_request(&self, request: &ListNonNftAssetRequest) -> Result<(), ContractError> {

        // Validate asset type
        if request.asset_type < 1 || request.asset_type > 5 {
            return Err(ContractError::ContractCallError(
                format!("Invalid asset type: {}. Must be between 1-5", request.asset_type)
            ));
        }

        // Validate price
        if request.price == 0 {
            return Err(ContractError::ContractCallError(
                "Price must be greater than 0".to_string()
            ));
        }

        // Validate asset ID
        if request.asset_id.is_empty() {
            return Err(ContractError::ContractCallError(
                "Asset ID cannot be empty".to_string()
            ));
        }

        // Validate metadata
        if request.metadata.is_empty() {
            return Err(ContractError::ContractCallError(
                "Metadata cannot be empty".to_string()
            ));
        }

        // Validate verification proof
        if request.verification_proof.is_empty() {
            return Err(ContractError::ContractCallError(
                "Verification proof cannot be empty".to_string()
            ));
        }

        // Validate description
        if request.description.is_empty() {
            return Err(ContractError::ContractCallError(
                "Description cannot be empty".to_string()
            ));
        }

        Ok(())
    }

    /// List a social media NFT for sale
    pub async fn list_social_media_nft(
        &self,
        wallet_address: String,
        request: ListSocialMediaNftApiRequest
    ) -> Result<ListNftResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Parse price from string
        let price = request.price.parse::<u64>()
            .map_err(|e| ContractError::ContractCallError(format!("Invalid price format: {}", e)))?;

        // Generate signature internally using verification service
        let client = self.client.read().await;
        let verification_service = client.get_verification_service();
        let wallet_address_parsed = wallet_address.parse::<ethers::types::Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        let signature = verification_service.generate_listing_signature(
            &wallet_address_parsed,
            request.token_id,
            price,
            &request.social_media_id,
        ).await?;

        // Create the internal request with generated signature
        let internal_request = ListSocialMediaNftRequest {
            token_id: request.token_id,
            price,
            social_media_id: request.social_media_id.clone().into(),
            signature: signature.clone().into(),
            description: request.description.clone().into(),
        };

        // Call the client to list social media NFT
        let client = self.client.read().await;
        let response = client.list_social_media_nft(internal_request).await?;

        // // Store listing in database
        let db_listing = SocialMediaNftListingData {
            id: uuid::Uuid::new_v4(),
            listing_id: response.listing_id as i64,
            creator_address: response.creator.to_string(),
            token_id: request.token_id as i64,
            price: request.price.parse::<i64>().unwrap_or(0),
            description: request.description.to_string(),
            social_media_id: request.social_media_id.to_string(),
            signature: signature.to_string(),
            active: response.active,
            is_auction: response.is_auction,
            transaction_hash: response.transaction_hash.clone(),
            block_number: response.block_number as i64,
            created_at: sqlx::types::chrono::Utc::now(),
            updated_at: sqlx::types::chrono::Utc::now(),
        };

        self.listing_repository.create_social_media_nft_listing(&db_listing).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        Ok(response)
    }

    /// Verify that the provided wallet address matches the connected wallet
    async fn verify_wallet_connection(&self, wallet_address: &str) -> Result<(), ContractError> {
        let client = self.client.read().await;
        let connected_address = client.get_wallet_address();

        // Parse the provided wallet address
        let provided_address = wallet_address.parse::<ethers::types::Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Check if addresses match
        if provided_address != connected_address {
            return Err(ContractError::WalletMismatch {
                provided: wallet_address.to_string(),
                connected: format!("{:?}", connected_address),
            });
        }

        Ok(())
    }

    /// Verify that the wallet has sufficient balance for gas fees
    async fn verify_wallet_balance(&self) -> Result<(), ContractError> {
        let balance = self.get_wallet_balance().await?;

        // Check if balance is sufficient (minimum 0.01 ETH for gas)
        let min_balance = ethers::types::U256::from(10_000_000_000_000_000u128); // 0.01 ETH in wei

        if balance < min_balance {
            return Err(ContractError::InsufficientBalance {
                current: format!("{:?}", balance),
                required: "0.01 ETH".to_string(),
            });
        }

        Ok(())
    }

    /// Verify that the wallet has sufficient balance for purchase + gas fees
    async fn verify_wallet_balance_for_purchase(&self, price: u64) -> Result<(), ContractError> {
        let balance = self.get_wallet_balance().await?;

        // Calculate required balance: price + gas fees (estimate 0.01 ETH for gas)
        let gas_estimate = ethers::types::U256::from(10_000_000_000_000_000u128); // 0.01 ETH in wei
        let price_u256 = ethers::types::U256::from(price);
        let required_balance = gas_estimate + price_u256;

        if balance < required_balance {
            return Err(ContractError::InsufficientBalance {
                current: format!("{:?}", balance),
                required: format!("{:?} (price: {:?} + gas: {:?})", required_balance, price_u256, gas_estimate),
            });
        }

        Ok(())
    }

    //  AUTHENTICATION VERIFICATION METHODS

    /// Verify that the user is authenticated and verified
    async fn verify_user_authentication(&self, user: &User) -> Result<(), ContractError> {
        // Check if user is verified (has completed KYC/signup process)
        if !user.is_verified {
            return Err(ContractError::UserNotVerified {
                user_id: user.id.to_string(),
                reason: "User must complete signup and verification process".to_string(),
            });
        }

        Ok(())
    }

    /// Verify that the provided wallet address matches the user's connected wallet
    async fn verify_user_wallet_match(&self, user: &User, wallet_address: &str) -> Result<(), ContractError> {
        // Check if user has a connected wallet
        let user_wallet = user.wallet_address.as_ref()
            .ok_or_else(|| ContractError::UserWalletNotConnected {
                user_id: user.id.to_string(),
                reason: "User must connect a wallet to perform this operation".to_string(),
            })?;

        // Parse the provided wallet address
        let provided_address = wallet_address.parse::<alloy::primitives::Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Parse the user's wallet address
        let user_address = user_wallet.parse::<alloy::primitives::Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Check if addresses match
        if provided_address != user_address {
            return Err(ContractError::UserWalletMismatch {
                user_id: user.id.to_string(),
                provided: wallet_address.to_string(),
                connected: user_wallet.clone(),
            });
        }

        Ok(())
    }

    // UTILITY METHODS

    /// Get the current network configuration
    pub fn get_network_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    /// Get the wallet address
    pub async fn get_wallet_address(&self) -> String {
        let client = self.client.read().await;
        format!("0x{:x}", client.get_wallet_address())
    }

    /// Get wallet balance
    pub async fn get_wallet_balance(&self) -> Result<ethers::types::U256, ContractError> {
        let client = self.client.read().await;
        let wallet_address = client.get_wallet_address();
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_wallet_balance(wallet_address).await
    }

    /// Check if a collection exists
    pub async fn check_collection_exists(&self, collection_id: u64) -> Result<bool, ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.check_collection_exists(collection_id).await
    }

    /// Get NFT listing details
    pub async fn get_nft_listing(&self, listing_id: u64) -> Result<(String, String, u64, u64, bool, bool), ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_nft_listing(listing_id).await
    }

    /// Get NFT listing from database with full details
    pub async fn get_nft_listing_details(&self, listing_id: u64) -> Result<Option<NftListingData>, ContractError> {
        self.listing_repository.get_nft_listing(listing_id as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get active NFT listings with pagination
    pub async fn get_active_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<NftListingData>, ContractError> {
        self.listing_repository.get_active_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Search NFT listings by description
    pub async fn search_nft_listings(&self, query: &str, limit: u64, offset: u64) -> Result<Vec<NftListingData>, ContractError> {
        self.listing_repository.search_nft_listings(query, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get non-NFT listing details
    pub async fn get_non_nft_listing(&self, listing_id: u64) -> Result<(String, u64, u8, bool, u8, String, String), ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_non_nft_listing(listing_id).await
    }

    /// Get non-NFT listing from database with full details
    pub async fn get_non_nft_listing_details(&self, listing_id: u64) -> Result<Option<NonNftListingData>, ContractError> {
        self.listing_repository.get_non_nft_listing(listing_id as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get active non-NFT listings with pagination
    pub async fn get_active_non_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<NonNftListingData>, ContractError> {
        self.listing_repository.get_active_non_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get non-NFT listings by asset type
    pub async fn get_non_nft_listings_by_asset_type(&self, asset_type: u8, limit: u64, offset: u64) -> Result<Vec<NonNftListingData>, ContractError> {
        self.listing_repository.get_non_nft_listings_by_asset_type(asset_type as i16, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Search non-NFT listings by description
    pub async fn search_non_nft_listings(&self, query: &str, limit: u64, offset: u64) -> Result<Vec<NonNftListingData>, ContractError> {
        self.listing_repository.search_non_nft_listings(query, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get social media NFT listing from database with full details
    pub async fn get_social_media_nft_listing_details(&self, listing_id: u64) -> Result<Option<SocialMediaNftListingData>, ContractError> {
        self.listing_repository.get_social_media_nft_listing(listing_id as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get active social media NFT listings with pagination
    pub async fn get_active_social_media_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<SocialMediaNftListingData>, ContractError> {
        self.listing_repository.get_active_social_media_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get all listings by creator address (combined across all types)
    pub async fn get_listings_by_creator(&self, creator_address: &str, limit: u64, offset: u64) -> Result<Vec<CombinedListingData>, ContractError> {
        self.listing_repository.get_listings_by_creator(creator_address, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get total count of listings by creator
    pub async fn get_listing_count_by_creator(&self, creator_address: &str) -> Result<u64, ContractError> {
        let count = self.listing_repository.get_listing_count_by_creator(creator_address).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?;
        Ok(count as u64)
    }

    /// Get listings by price range (combined across all types)
    pub async fn get_listings_by_price_range(&self, min_price: u64, max_price: u64, limit: u64, offset: u64) -> Result<Vec<CombinedListingData>, ContractError> {
        self.listing_repository.get_listings_by_price_range(min_price as i64, max_price as i64, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Search across all listing types
    pub async fn search_all_listings(&self, query: &str, limit: u64, offset: u64) -> Result<Vec<CombinedListingData>, ContractError> {
        self.listing_repository.search_all_listings(query, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get marketplace statistics
    pub async fn get_marketplace_stats(&self) -> Result<MarketplaceStats, ContractError> {
        // Get counts from database
        let nft_count = self.listing_repository.get_active_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        let non_nft_count = self.listing_repository.get_active_non_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        let social_media_count = self.listing_repository.get_active_social_media_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        Ok(MarketplaceStats {
            total_active_listings: nft_count + non_nft_count + social_media_count,
            nft_listings: nft_count,
            non_nft_listings: non_nft_count,
            social_media_nft_listings: social_media_count,
        })
    }

    /// Get all collections
    pub async fn get_all_collections(&self) -> Result<Vec<Collection>, ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_all_collections().await
    }

    /// Get collection by ID
    pub async fn get_collection_by_id(&self, collection_id: u64) -> Result<Collection, ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_collection_by_id(collection_id).await
    }

    /// Get collections by creator
    pub async fn get_collections_by_creator(&self, creator_address: String) -> Result<Vec<Collection>, ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_collections_by_creator(creator_address).await
    }

    /// Get escrow details for a listing
    pub async fn get_escrow(&self, listing_id: u64) -> Result<Escrow, ContractError> {
        let client = self.client.read().await;
        let read_only_client = ReadOnlyContractClient::new(
            client.get_provider_url(),
            client.get_network_config().clone(),
        ).await?;
        read_only_client.get_escrow(listing_id).await
    }

    /// Get the underlying contract client (for operations that need wallet)
    pub async fn get_client(&self) -> ContractClient {
        self.client.read().await.clone()
    }

    /// Check if the service is connected to the blockchain
    pub async fn is_connected(&self) -> bool {
        // Try to get the latest block number to test connection
        let _client = self.client.read().await;
        // This would need to be implemented in the client
        true // For now, assume connected
    }

    /// Parse asset identifier to extract platform and identifier
    fn parse_asset_identifier(&self, asset_id: &str, asset_type: u8) -> Result<(String, String), ContractError> {
        // First convert asset_type to string representation
        let asset_type_str = match asset_type {
            1 => "social_media",
            2 => "domain",
            3 => "app",
            4 => "website",
            5 => "youtube",
            6 => "other",
            _ => return Err(ContractError::ContractCallError(format!("Invalid asset type: {}", asset_type))),
        };

        // Parse based on asset type
        match asset_type_str {
            "social_media" => self.parse_social_media_identifier(asset_id),
            "website" => self.parse_website_identifier(asset_id),
            "domain" => self.parse_domain_identifier(asset_id),
            "youtube" => self.parse_youtube_identifier(asset_id),
            "app" => self.parse_app_identifier(asset_id),
            _ => Ok(("unknown".to_string(), asset_id.to_string())),
        }
    }

    /// Parse social media identifier (username or URL)
    fn parse_social_media_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Handle URLs like https://x.com/username
        // Special handling for YouTube channel URLs
        if asset_id.contains("youtube.com/channel/") {
            let channel_pattern = regex::Regex::new(r"https?://(?:www\.)?youtube\.com/channel/([^/\s?]+)").unwrap();
            if let Some(captures) = channel_pattern.captures(asset_id) {
                let channel_id = captures.get(1).unwrap().as_str();
                return Ok(("youtube".to_string(), channel_id.to_string()));
            }
        }

        // Handle other social media URLs
        let url_pattern = regex::Regex::new(r"https?://(?:www\.)?(x\.com|instagram\.com|facebook\.com|youtube\.com|youtu\.be)/([^/\s?]+)").unwrap();

        if let Some(captures) = url_pattern.captures(asset_id) {
            let domain = captures.get(1).unwrap().as_str();
            let username = captures.get(2).unwrap().as_str();

            let platform = match domain {
                "x.com" => "x",
                "instagram.com" => "instagram",
                "facebook.com" => "facebook",
                "youtube.com" | "youtu.be" => "youtube",
                _ => return Err(ContractError::ContractCallError(format!("Unsupported social media platform: {}", domain))),
            };

            return Ok((platform.to_string(), username.to_string()));
        }

        // Handle direct usernames (require platform specification)
        if !asset_id.contains('/') && !asset_id.contains('.') {
            return Err(ContractError::ContractCallError("Platform must be specified for social media identifiers. Use format: platform/username (e.g., x/username, instagram/username)".to_string()));
        }

        Err(ContractError::ContractCallError(format!("Invalid social media identifier format: {}", asset_id)))
    }

    /// Parse website identifier
    fn parse_website_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Remove protocol and www if present
        let clean_url = asset_id
            .replace("https://", "")
            .replace("http://", "")
            .replace("www.", "");

        Ok(("website".to_string(), clean_url))
    }

    /// Parse domain identifier
    fn parse_domain_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Remove protocol if present
        let clean_domain = asset_id
            .replace("https://", "")
            .replace("http://", "");

        Ok(("domain".to_string(), clean_domain))
    }

    /// Parse YouTube identifier
    fn parse_youtube_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Handle YouTube channel URLs
        if asset_id.contains("youtube.com/channel/") {
            let channel_pattern = regex::Regex::new(r"https?://(?:www\.)?youtube\.com/channel/([^/\s?]+)").unwrap();
            if let Some(captures) = channel_pattern.captures(asset_id) {
                let channel_id = captures.get(1).unwrap().as_str();
                return Ok(("youtube".to_string(), channel_id.to_string()));
            }
        }

        // Handle YouTube user URLs
        if asset_id.contains("youtube.com/user/") {
            let user_pattern = regex::Regex::new(r"https?://(?:www\.)?youtube\.com/user/([^/\s?]+)").unwrap();
            if let Some(captures) = user_pattern.captures(asset_id) {
                let username = captures.get(1).unwrap().as_str();
                return Ok(("youtube".to_string(), username.to_string()));
            }
        }

        // Handle YouTube @username URLs
        if asset_id.contains("youtube.com/@") {
            let at_pattern = regex::Regex::new(r"https?://(?:www\.)?youtube\.com/@([^/\s?]+)").unwrap();
            if let Some(captures) = at_pattern.captures(asset_id) {
                let username = captures.get(1).unwrap().as_str();
                return Ok(("youtube".to_string(), username.to_string()));
            }
        }

        // Handle direct YouTube identifiers
        if !asset_id.contains("youtube.com") && !asset_id.contains("youtu.be") {
            return Ok(("youtube".to_string(), asset_id.to_string()));
        }

        Err(ContractError::ContractCallError(format!("Invalid YouTube identifier format: {}", asset_id)))
    }

    /// Parse app identifier
    fn parse_app_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Handle app store URLs
        if asset_id.contains("apps.apple.com") {
            let app_pattern = regex::Regex::new(r"https?://(?:www\.)?apps\.apple\.com/[^/]+/app/[^/]+/id(\d+)").unwrap();
            if let Some(captures) = app_pattern.captures(asset_id) {
                let app_id = captures.get(1).unwrap().as_str();
                return Ok(("ios".to_string(), app_id.to_string()));
            }
        }

        if asset_id.contains("play.google.com") {
            let app_pattern = regex::Regex::new(r"https?://(?:www\.)?play\.google\.com/store/apps/details\?id=([^&\s]+)").unwrap();
            if let Some(captures) = app_pattern.captures(asset_id) {
                let app_id = captures.get(1).unwrap().as_str();
                return Ok(("android".to_string(), app_id.to_string()));
            }
        }

        // Handle direct app identifiers
        if !asset_id.contains("apps.apple.com") && !asset_id.contains("play.google.com") {
            return Ok(("app".to_string(), asset_id.to_string()));
        }

        Err(ContractError::ContractCallError(format!("Invalid app identifier format: {}", asset_id)))
    }

    /// List an NFT for auction
    pub async fn list_nft_for_auction(
        &self,
        wallet_address: String,
        request: ListNftForAuctionRequest,
    ) -> Result<ListNftForAuctionResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to list for auction
        let client = self.client.read().await;

        if request.is_nft {
            client.list_nft_for_auction(request.listing_id).await
        } else {
            client.list_non_nft_for_auction(request.listing_id).await
        }
    }

    /// Buy an NFT listing
    pub async fn buy_nft(
        &self,
        wallet_address: String,
        request: BuyNftRequest,
        price: u64,
    ) -> Result<BuyNftResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for purchase + gas
        self.verify_wallet_balance_for_purchase(price).await?;

        // Call the client to buy NFT
        let client = self.client.read().await;
        client.buy_nft(request.listing_id, price).await
    }

    /// Buy a non-NFT asset listing
    pub async fn buy_non_nft_asset(
        &self,
        wallet_address: String,
        request: BuyNonNftAssetRequest,
        price: u64,
    ) -> Result<BuyNonNftAssetResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet has sufficient balance for purchase + gas
        self.verify_wallet_balance_for_purchase(price).await?;

        // Call the client to buy non-NFT asset
        let client = self.client.read().await;
        client.buy_non_nft_asset(request.listing_id, price).await
    }

    /// Cancel an NFT listing
    pub async fn cancel_nft_listing(
        &self,
        wallet_address: String,
        request: CancelNftListingRequest,
    ) -> Result<CancelNftListingResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Call the client to cancel NFT listing
        let client = self.client.read().await;
        client.cancel_nft_listing(request.listing_id).await
    }

    /// Cancel a non-NFT asset listing
    pub async fn cancel_non_nft_listing(
        &self,
        wallet_address: String,
        request: CancelNonNftListingRequest,
    ) -> Result<CancelNonNftListingResponse, ContractError> {
        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Call the client to cancel non-NFT asset listing
        let client = self.client.read().await;
        client.cancel_non_nft_listing(request.listing_id).await
    }


}

impl ReadOnlyContractService {
    /// Get all collections from the contract
    pub async fn get_all_collections(&self) -> Result<Vec<Collection>, ContractError> {
        let client = self.client.read().await;
        client.get_all_collections().await
    }

    /// Get a specific collection by ID
    pub async fn get_collection_by_id(&self, collection_id: u64) -> Result<Collection, ContractError> {
        let client = self.client.read().await;
        client.get_collection_by_id(collection_id).await
    }

    pub async fn get_collections_by_creator(&self, creator_address: String) -> Result<Vec<Collection>, ContractError> {
        let client = self.client.read().await;
        client.get_collections_by_creator(creator_address).await
    }

    pub fn get_network_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    // Read-only listing operations
    /// Get active NFT listings with pagination
    pub async fn get_active_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<NftListingData>, ContractError> {
        self.listing_repository.get_active_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get active non-NFT listings with pagination
    pub async fn get_active_non_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<NonNftListingData>, ContractError> {
        self.listing_repository.get_active_non_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get active social media NFT listings with pagination
    pub async fn get_active_social_media_nft_listings(&self, limit: u64, offset: u64) -> Result<Vec<SocialMediaNftListingData>, ContractError> {
        self.listing_repository.get_active_social_media_nft_listings(limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Search across all listing types
    pub async fn search_all_listings(&self, query: &str, limit: u64, offset: u64) -> Result<Vec<CombinedListingData>, ContractError> {
        self.listing_repository.search_all_listings(query, limit as i64, offset as i64).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))
    }

    /// Get marketplace statistics
    pub async fn get_marketplace_stats(&self) -> Result<MarketplaceStats, ContractError> {
        // Get counts from database
        let nft_count = self.listing_repository.get_active_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        let non_nft_count = self.listing_repository.get_active_non_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        let social_media_count = self.listing_repository.get_active_social_media_nft_listings(1, 0).await
            .map_err(|e| ContractError::DatabaseError(e.to_string()))?
            .len() as u64;

        Ok(MarketplaceStats {
            total_active_listings: nft_count + non_nft_count + social_media_count,
            nft_listings: nft_count,
            non_nft_listings: non_nft_count,
            social_media_nft_listings: social_media_count,
        })
    }
}