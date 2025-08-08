use ethers::{
    providers::{Http, Provider, Middleware},
    signers::{LocalWallet, Signer},
    contract::{Contract},
    types::{Address, U256, TransactionReceipt, H160, H256},
};
use std::sync::Arc;
use crate::domain::models::{
    MintNftRequest, MintNftResponse,
    CreateEscrowRequest, CreateEscrowResponse,
    ListAssetRequest, ListAssetResponse,
    CreateCollectionRequest, CreateCollectionResponse,
    MintNftToCollectionRequest, MintNftToCollectionResponse,
    MintSocialMediaNftRequest, MintSocialMediaNftResponse
};
use crate::domain::services::ContractError;
use crate::infrastructure::contracts::types::*;
use crate::infrastructure::contracts::abis;
use crate::infrastructure::contracts::utils::uint96::Uint96;
use crate::infrastructure::contracts::utils::verification::VerificationService;


// Main contract client for interacting with Vertix smart contracts
#[derive(Clone)]
pub struct ContractClient {
    provider: Arc<Provider<Http>>,
    wallet: LocalWallet,
    network_config: NetworkConfig,
    contract_addresses: ContractAddresses,
    verification_service: VerificationService,

    // Contract instances for each contract
    vertix_nft: Contract<Provider<Http>>,
    vertix_escrow: Contract<Provider<Http>>,
    marketplace_proxy: Contract<Provider<Http>>,
}

impl ContractClient {
    pub async fn new(
        rpc_url: String,
        private_key: String,
        network_config: NetworkConfig,
        contract_addresses: ContractAddresses,
        verification_service: VerificationService,
    ) -> Result<Self, ContractError> {
        // Create provider
        let provider = Provider::<Http>::try_from(&rpc_url)
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let provider = Arc::new(provider);

        // Create wallet
        let wallet = private_key
            .parse::<LocalWallet>()
            .map_err(|e| ContractError::InvalidSignature { reason: e.to_string() })?;

        // Load ABIs
        let nft_abi = abis::load_vertix_nft_abi()?;
        let escrow_abi = abis::load_vertix_escrow_abi()?;
        let marketplace_abi = abis::load_marketplace_core_abi()?;

        // Create contract instances
        let vertix_nft = Contract::new(contract_addresses.vertix_nft, nft_abi, provider.clone());
        let vertix_escrow = Contract::new(contract_addresses.vertix_escrow, escrow_abi, provider.clone());
        let marketplace_proxy = Contract::new(contract_addresses.marketplace_proxy, marketplace_abi, provider.clone());

        Ok(Self {
            provider,
            wallet,
            network_config,
            contract_addresses,
            vertix_nft,
            vertix_escrow,
            marketplace_proxy,
            verification_service,
        })
    }

    // ============ NFT OPERATIONS ============

    /// Create a new collection
    pub async fn create_collection(&self, request: CreateCollectionRequest) -> Result<CreateCollectionResponse, ContractError> {
        let to = self.wallet.address();
        let name = request.name;
        let symbol = request.symbol;
        let image = request.image;
        let max_supply = request.max_supply.unwrap_or(1000);

        // convert max_supply to u16
        let max_supply_u16 = max_supply as u16;
        // call the createCollection function on the vertix_nft contract
        match self.vertix_nft.method::<_, String>("name", ()) {
            Ok(call) => {
                match call.call().await {
                    Ok(name) => println!("   Debug: Contract name: {}", name),
                    Err(e) => println!("   Debug: Failed to get contract name: {}", e),
                }
            },
            Err(e) => println!("   Debug: Failed to create name() call: {}", e),
        }

        let call = self.vertix_nft
            .method::<_, ()>("createCollection", (name.to_string(), symbol.to_string(), image.to_string(), max_supply_u16))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // send the transaction
        let call_with_sender = call.from(to);
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // wait for the transaction to be mined
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("Transaction failed".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Transaction reverted".to_string()));
            }
        }

        // extract the collection id from the receipt
        let collection_id_u256 = self.extract_collection_id_from_receipt(&receipt)?;

        let collection_id = if collection_id_u256 > U256::from(u64::MAX) {
            u64::MAX
        } else {
            collection_id_u256.as_u64()
        };

        Ok(CreateCollectionResponse {
            collection_id,
            creator: Arc::from(to.to_string()),
            name: Arc::from(name.to_string()),
            symbol: Arc::from(symbol.to_string()),
            image: Arc::from(image.to_string()),
            max_supply,
            current_supply: 0,
            token_ids: vec![],
            transaction_hash: Arc::from(format!("{:?}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Mint a new NFT to a collection
    pub async fn mint_nft_to_collection(&self, request: MintNftToCollectionRequest) -> Result<MintNftToCollectionResponse, ContractError> {
        let to = self.wallet.address();
        let collection_id = request.collection_id;
        let token_uri = request.token_uri;
        let metadata_hash = request.metadata_hash;
        let royalty_bps = request.royalty_bps.unwrap_or(500); // Default 5% royalty

        // Validate that the collection exists before attempting to mint
        let collection_exists = self.check_collection_exists(collection_id).await?;
        if !collection_exists {
            return Err(ContractError::ContractCallError(format!("Collection {} does not exist", collection_id)));
        }

        // Convert royalty_bps to Uint96
        let royalty_uint96 = Uint96::from_u256(U256::from(royalty_bps))
            .map_err(|e| ContractError::InvalidUint96Value { reason: e.to_string() })?;

        // Convert metadata_hash from "0x..." string to [u8; 32]
        let metadata_hash_bytes: [u8; 32] = {
            let bytes = hex::decode(&metadata_hash[2..]) // Remove "0x" prefix
                .map_err(|e| ContractError::ContractCallError(format!("Invalid metadata hash: {}", e)))?;

            if bytes.len() != 32 {
                return Err(ContractError::ContractCallError("Metadata hash must be 32 bytes".into()));
            }

            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        };

        // Call mintToCollection function with fixed gas limit
        let call = self.vertix_nft
            .method::<_, ()>("mintToCollection", (
                to,
                collection_id,
                token_uri.to_string(),
                metadata_hash_bytes,
                royalty_uint96.0
            ))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with fixed gas limit
        let call_with_gas = call.gas(500000u64); // Fixed gas limit
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("Transaction failed".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Transaction reverted".to_string()));
            }
        }

        // Extract token ID from logs
        let token_id = self.extract_token_id_from_receipt(&receipt)?;

        Ok(MintNftToCollectionResponse {
            to: Arc::from(to.to_string()),
            collection_id,
            token_id,
            uri: token_uri,
            metadata_hash,
            royalty_recipient: Arc::from(self.wallet.address().to_string()),
            royalty_bps,
            transaction_hash: Arc::from(format!("{:?}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Mint a new NFT
    pub async fn mint_nft(&self, request: MintNftRequest) -> Result<MintNftResponse, ContractError> {
        let to = self.wallet.address();
        let token_uri = request.token_uri;
        let metadata_hash = request.metadata_hash;
        let royalty_bps = request.royalty_bps.unwrap_or(500); // Default 5% royalty

        // Convert royalty_bps to Uint96
        let royalty_uint96 = Uint96::from_u256(U256::from(royalty_bps))
            .map_err(|e| ContractError::InvalidUint96Value { reason: e.to_string() })?;

        // Convert metadata_hash from "0x..." string to [u8; 32]
        let metadata_hash_bytes: [u8; 32] = {
            let bytes = hex::decode(&metadata_hash[2..]) // Remove "0x" prefix
                .map_err(|e| ContractError::ContractCallError(format!("Invalid metadata hash: {}", e)))?;

            if bytes.len() != 32 {
                return Err(ContractError::ContractCallError("Metadata hash must be 32 bytes".into()));
            }

            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        };

        // Call mintSingleNft function with fixed gas limit
        let call = self.vertix_nft
            .method::<_, ()>("mintSingleNft", (
                to,
                token_uri.to_string(),
                metadata_hash_bytes,
                royalty_uint96.0
            ))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with fixed gas limit
        let call_with_gas = call.gas(500000u64); // Fixed gas limit
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("Transaction failed".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Transaction reverted".to_string()));
            }
        }

        // Extract token ID from logs
        let token_id = self.extract_token_id_from_receipt(&receipt)?;

        Ok(MintNftResponse {
            to: Arc::from(to.to_string()),
            token_id,
            collection_id: None,
            uri: Arc::from(token_uri.to_string()),
            metadata_hash: Arc::from(metadata_hash.to_string()),
            royalty_recipient: Arc::from(self.wallet.address().to_string()),
            royalty_bps,
            transaction_hash: Arc::from(format!("{:?}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Mint social media NFT with signature verification
    pub async fn mint_social_media_nft(&self, request: MintSocialMediaNftRequest) -> Result<MintSocialMediaNftResponse, ContractError> {
        let to: Address = self.wallet.address();
        let social_media_id = request.social_media_id;
        let token_uri = request.token_uri;
        let metadata_hash = request.metadata_hash;
        let royalty_bps = request.royalty_bps.unwrap_or(500); // Default 5% royalty
        let signature = request.signature;

        // Convert royalty_bps to U256 for ethers (which handles uint96 conversion automatically)
        let royalty_u256 = U256::from(royalty_bps);

        // Convert metadata_hash from "0x..." string to [u8; 32]
        let metadata_hash_bytes: [u8; 32] = {
            let bytes = hex::decode(&metadata_hash[2..]) // Remove "0x" prefix
                .map_err(|e| ContractError::ContractCallError(format!("Invalid metadata hash: {}", e)))?;

            if bytes.len() != 32 {
                return Err(ContractError::ContractCallError("Metadata hash must be 32 bytes".into()));
            }

            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        };

        // Convert signature to ethers::types::Bytes for Solidity
        let signature_bytes = ethers::types::Bytes::from(
            hex::decode(&signature[2..])
                .map_err(|e| ContractError::ContractCallError(format!("Invalid signature: {}", e)))?
        );

        // Test if contract instance is working by calling a simple view function
        match self.vertix_nft.method::<_, String>("name", ()) {
            Ok(call) => {
                match call.call().await {
                    Ok(name) => println!("   Debug: Contract name: {}", name),
                    Err(e) => println!("   Debug: Failed to get contract name: {}", e),
                }
            },
            Err(e) => println!("   Debug: Failed to create name() call: {}", e),
        }

        // Call mintSocialMediaNft function with fixed gas limit
        let call = self.vertix_nft
            .method::<_, ()>("mintSocialMediaNft", (
                to,
                social_media_id.to_string(),
                token_uri.to_string(),
                metadata_hash_bytes,
                royalty_u256,
                signature_bytes
            ))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with fixed gas limit
        let call_with_gas = call.gas(500000u64); // Fixed gas limit
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| {
                println!("   Debug: Transaction send error: {:?}", e);
                ContractError::TransactionError(e.to_string())
            })?;

        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| {
                println!("   Debug: Transaction confirmation error: {:?}", e);
                ContractError::TransactionError(e.to_string())
            })?
            .ok_or_else(|| ContractError::TransactionError("Transaction failed".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Transaction reverted".to_string()));
            }
        }

        // Extract token ID from logs
        let token_id = self.extract_social_media_token_id_from_receipt(&receipt)?;

        Ok(MintSocialMediaNftResponse {
            to: Arc::from(to.to_string()),
            token_id,
            social_media_id: Arc::from(social_media_id.to_string()),
            uri: Arc::from(token_uri.to_string()),
            metadata_hash: Arc::from(metadata_hash.to_string()),
            royalty_recipient: Arc::from(self.wallet.address().to_string()),
            royalty_bps: royalty_bps as u16,
            transaction_hash: Arc::from(format!("{:?}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Extract token ID from transaction receipt
    fn extract_token_id_from_receipt(&self, receipt: &TransactionReceipt) -> Result<u64, ContractError> {
        // Look for NFTMinted event in the logs
        for log in &receipt.logs {
            // Check if this log is from our NFT contract
            if log.address == self.contract_addresses.vertix_nft {
                // Try to parse as NFTMinted event
                // NFTMinted event signature: NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)
                // The tokenId is the fourth indexed parameter (index 3)
                if log.topics.len() >= 4 {
                    // First topic is the event signature
                    // Fourth topic (index 3) should be the tokenId
                    if let Some(token_id_topic) = log.topics.get(3) {
                        // Convert the topic to u64 safely
                        let token_id = U256::from_big_endian(&token_id_topic.as_bytes());
                        // Check if the value fits in u64
                        if token_id > U256::from(u64::MAX) {
                            return Ok(u64::MAX);
                        }
                        return Ok(token_id.as_u64());
                    }
                }
            }
        }

        // If no NFTMinted event found, try to extract from Transfer event (ERC721 standard)
        for log in &receipt.logs {
            if log.address == self.contract_addresses.vertix_nft {
                // Transfer event signature: Transfer(address,address,uint256)
                // The tokenId is the third topic (index 2)
                if log.topics.len() >= 3 {
                    if let Some(token_id_topic) = log.topics.get(2) {
                        let token_id = U256::from_big_endian(&token_id_topic.as_bytes());
                        // Check if the value fits in u64
                        if token_id > U256::from(u64::MAX) {
                            return Ok(u64::MAX);
                        }
                        return Ok(token_id.as_u64());
                    }
                }
            }
        }

        // Fallback: return 0 if no token ID found
        // This could happen if the transaction failed or didn't emit expected events
        Ok(0)
    }

    /// Extract collection ID from transaction receipt
    fn extract_collection_id_from_receipt(&self, receipt: &TransactionReceipt) -> Result<U256, ContractError> {        
        // Look for CollectionCreated event in the logs
        for (_i, log) in receipt.logs.iter().enumerate() {

            if log.address == self.contract_addresses.vertix_nft {
                // CollectionCreated event signature: CollectionCreated(uint256 indexed collectionId, address indexed creator, string name, string symbol, string image, uint256 maxSupply)
                // The collectionId is the first indexed parameter (Topic 1, index 1)
                if log.topics.len() >= 2 {
                    // First topic (index 1) should be the collectionId
                    if let Some(collection_id_topic) = log.topics.get(1) {
                        // Convert the topic to U256
                        let collection_id = U256::from_big_endian(&collection_id_topic.as_bytes());
                        return Ok(collection_id);
                    }
                }
            }
        }
        Ok(U256::from(0))
    }

    /// Extract token ID from social media NFT transaction receipt
    fn extract_social_media_token_id_from_receipt(&self, receipt: &TransactionReceipt) -> Result<u64, ContractError> {

        // Look for SocialMediaNFTMinted event in the logs
        for (_log_index, log) in receipt.logs.iter().enumerate() {

            // Check if this log is from our NFT contract
            if log.address == H160::from_slice(&self.contract_addresses.vertix_nft.0.as_slice()) {

                // Check if this is the SocialMediaNFTMinted event by signature
                let social_media_nft_minted_signature = H256::from_slice(&hex::decode("a070a1c2e676dbcadfab71a2357b2423de00020d93af644115c7ea4959da267c").unwrap());
                if log.topics.len() > 0 && log.topics[0] == social_media_nft_minted_signature {

                    // SocialMediaNFTMinted event signature: SocialMediaNFTMinted(address indexed to, uint256 indexed tokenId, string socialMediaId, string uri, bytes32 metadataHash, address indexed royaltyRecipient, uint96 royaltyBps)
                    // The tokenId is the second indexed parameter (Topic 2, index 2)
                    if log.topics.len() >= 4 {
                        // Topic 0: Event signature
                        // Topic 1: address indexed to
                        // Topic 2: uint256 indexed tokenId ← This is what we want
                        // Topic 3: address indexed royaltyRecipient
                        if let Some(token_id_topic) = log.topics.get(2) {

                            // Convert the topic to u64 safely
                            let token_id = U256::from_big_endian(&token_id_topic.as_bytes());

                            // Check if the value fits in u64
                            if token_id > U256::from(u64::MAX) {
                                return Ok(u64::MAX);
                            }
                            let token_id_u64 = token_id.try_into().unwrap_or(0);
                            return Ok(token_id_u64);
                        }
                    }
                }
            }
        }

        // If no SocialMediaNFTMinted event found, try to extract from Transfer event (ERC721 standard)
        for log in &receipt.logs {
            if log.address == H160::from_slice(&self.contract_addresses.vertix_nft.0.as_slice()) {
                // Transfer event signature: Transfer(address,address,uint256)
                // The tokenId is the third topic (index 2)
                if log.topics.len() >= 3 {
                    if let Some(token_id_topic) = log.topics.get(2) {
                        let token_id = U256::from_big_endian(&token_id_topic.as_bytes());
                        // Check if the value fits in u64
                        if token_id > U256::from(u64::MAX) {
                            return Ok(u64::MAX);
                        }
                        return Ok(token_id.try_into().unwrap_or(0));
                    }
                }
            }
        }

        // Fallback: return 0 if no token ID found
        Ok(0)
    }

    /// Get the current wallet address
    pub fn get_wallet_address(&self) -> Address {
        self.wallet.address()
    }

    /// Get the current network configuration
    pub fn get_network_config(&self) -> &NetworkConfig {
        &self.network_config
    }

    pub fn get_verification_service(&self) -> &VerificationService {
        &self.verification_service
    }

    /// Get wallet balance
    pub async fn get_wallet_balance(&self) -> Result<U256, ContractError> {
        let balance = self.provider
            .get_balance(self.wallet.address(), None)
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        Ok(balance)
    }

    /// Check if a collection exists
    pub async fn check_collection_exists(&self, collection_id: u64) -> Result<bool, ContractError> {
        let call = self.vertix_nft
            .method::<_, (Address, String, String, String, u16, u16)>("collections", (U256::from(collection_id),))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        match call.call().await {
            Ok((creator, name, symbol, _image, _max_supply, _current_supply)) => {
                println!("   Debug: Collection {} - Creator: {:?}, Name: {}, Symbol: {}", collection_id, creator, name, symbol);
                // If creator is not zero address, collection exists
                Ok(creator != Address::zero())
            },
            Err(e) => {
                println!("   Debug: Collection {} check failed: {}", collection_id, e);
                Ok(false)
            },
        }
    }

    // /// Test if the NFT contract is accessible
    // pub async fn test_contract_access(&self) -> Result<String, ContractError> {
    //     // Try to call a simple view function like name()
    //     let name = self.vertix_nft
    //         .method::<_, String>("name", ())
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to call name(): {}", e)))?
    //         .call()
    //         .await
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to execute name(): {}", e)))?;

    //     // Also try to get the owner to verify the contract is working
    //     let owner = self.vertix_nft
    //         .method::<_, Address>("owner", ())
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to call owner(): {}", e)))?
    //         .call()
    //         .await
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to execute owner(): {}", e)))?;

    //     println!("   Debug: Contract owner: {:?}", owner);

    //     // Try to get balance to verify the contract is working
    //     let balance = self.vertix_nft
    //         .method::<_, U256>("balanceOf", (self.wallet.address(),))
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to call balanceOf(): {}", e)))?
    //         .call()
    //         .await
    //         .map_err(|e| ContractError::ContractCallError(format!("Failed to execute balanceOf(): {}", e)))?;

    //     println!("   Debug: Wallet balance: {:?}", balance);

    //     Ok(name)
    // }



    // ============ NON-NFT ASSET OPERATIONS ============

    pub async fn create_escrow(&self, request: CreateEscrowRequest) -> Result<CreateEscrowResponse, ContractError> {
        let price = U256::from_dec_str(&request.price)
            .map_err(|e| ContractError::ContractCallError(format!("Invalid price format: {}", e)))?;

        // Create the call first
        let mut call = self.vertix_escrow
            .method::<_, String>("createEscrow", (
                request.asset_type,
                request.asset_id,
                price,
                request.description
            ))?;

        // Then configure it
        call = call.from(self.wallet.address());

        // Finally execute it
        let pending_tx = call.send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        let escrow_id = format!("escrow_{}", receipt.transaction_hash);
        let escrow_address = format!("0x{}", hex::encode(&receipt.transaction_hash.as_bytes()[..20]));

        Ok(CreateEscrowResponse {
            escrow_id,
            transaction_hash: format!("{:?}", receipt.transaction_hash),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
            escrow_address,
        })
    }

    pub async fn list_asset(&self, request: ListAssetRequest) -> Result<ListAssetResponse, ContractError> {
        let price = U256::from_dec_str(&request.price)
            .map_err(|e| ContractError::ContractCallError(format!("Invalid price format: {}", e)))?;

        let mut call = self.marketplace_proxy
            .method::<_, String>("listAsset", (
                request.asset_type,
                request.asset_id,
                price,
                request.description
            ))?;

        call = call.from(self.wallet.address());

        let pending_tx = call.send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        let listing_id = format!("listing_{}", receipt.transaction_hash);

        Ok(ListAssetResponse {
            listing_id,
            transaction_hash: format!("{:?}", receipt.transaction_hash),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }
}