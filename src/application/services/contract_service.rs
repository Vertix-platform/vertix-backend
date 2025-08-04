use std::sync::Arc;
use tokio::sync::RwLock;
use crate::infrastructure::contracts::client::ContractClient;
use crate::domain::models::{
    MintNftRequest, MintNftResponse, User,
    CreateEscrowRequest, CreateEscrowResponse,
    ListAssetRequest, ListAssetResponse,
    CreateCollectionRequest, CreateCollectionResponse,
    MintNftToCollectionRequest, MintNftToCollectionResponse
};
use crate::domain::services::ContractError;
use crate::infrastructure::contracts::addresses;

/// Service layer for contract operations
/// This provides a higher-level interface that handles wallet connection and business logic
pub struct ContractService {
    client: Arc<RwLock<ContractClient>>,
    network_config: crate::infrastructure::contracts::types::NetworkConfig,
}

impl ContractService {
    /// Create a new contract service
    pub async fn new(
        rpc_url: String,
        private_key: String,
        chain_id: u64,
    ) -> Result<Self, ContractError> {
        // Get network configuration
        let network_config = addresses::get_network_config_by_chain_id(chain_id)?;

        // Get contract addresses
        let contract_addresses = addresses::get_contract_addresses_by_chain_id(chain_id)?;

        // Create contract client
        let client = ContractClient::new(
            rpc_url,
            private_key,
            network_config.clone(),
            contract_addresses,
        ).await?;

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            network_config,
        })
    }

    // WALLET-CONNECTED OPERATIONS
    // These operations require wallet connection but not user authentication
    // Suitable for NFT-related operations that are trustless and on-chain

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

    // AUTHENTICATED OPERATIONS
    // These operations require both user authentication AND wallet connection
    // Suitable for non-NFT assets like manual transfers, escrow, etc.

    /// Create an escrow for manual transfer (requires user authentication + wallet connection)
    pub async fn create_escrow(
        &self,
        user: &User,
        wallet_address: String,
        request: CreateEscrowRequest
    ) -> Result<CreateEscrowResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to create escrow
        let client = self.client.read().await;
        client.create_escrow(request).await
    }

    /// List a non-NFT asset (requires user authentication + wallet connection)
    pub async fn list_non_nft_asset(
        &self,
        user: &User,
        wallet_address: String,
        request: ListAssetRequest
    ) -> Result<ListAssetResponse, ContractError> {
        // Verify user is authenticated and verified
        self.verify_user_authentication(user).await?;

        // Verify wallet connection
        self.verify_wallet_connection(&wallet_address).await?;

        // Verify wallet matches user's connected wallet
        self.verify_user_wallet_match(user, &wallet_address).await?;

        // Verify wallet has sufficient balance for gas
        self.verify_wallet_balance().await?;

        // Call the client to list asset
        let client = self.client.read().await;
        client.list_asset(request).await
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
        let client = self.client.read().await;
        let balance = client.get_wallet_balance().await?;

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
        let provided_address = wallet_address.parse::<ethers::types::Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Parse the user's wallet address
        let user_address = user_wallet.parse::<ethers::types::Address>()
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
    pub fn get_network_config(&self) -> &crate::infrastructure::contracts::types::NetworkConfig {
        &self.network_config
    }

    /// Get the current wallet address
    pub async fn get_wallet_address(&self) -> String {
        let client = self.client.read().await;
        format!("{:?}", client.get_wallet_address())
    }

    /// Check if the service is connected to the blockchain
    pub async fn is_connected(&self) -> bool {
        // Try to get the latest block number to test connection
        let _client = self.client.read().await;
        // This would need to be implemented in the client
        true // For now, assume connected
    }

    /// Get wallet balance
    pub async fn get_wallet_balance(&self) -> Result<ethers::types::U256, ContractError> {
        let client = self.client.read().await;
        client.get_wallet_balance().await
    }

    /// Get the underlying contract client
    pub async fn get_client(&self) -> ContractClient {
        self.client.read().await.clone()
    }
}