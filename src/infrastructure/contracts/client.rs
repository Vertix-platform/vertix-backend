use ethers::{
    providers::{Http, Provider, Middleware},
    signers::{LocalWallet, Signer},
    contract::{Contract},
    types::{Address, U256, TransactionReceipt, H160, H256, Bytes, TransactionRequest},
    abi::Token,
    utils::keccak256,
};
use std::sync::Arc;
use crate::domain::models::{
    MintNftRequest, MintNftResponse,
    ListSocialMediaNftRequest,
    CreateCollectionRequest, CreateCollectionResponse,
    MintNftToCollectionRequest, MintNftToCollectionResponse,
    MintSocialMediaNftRequest, MintSocialMediaNftResponse,
    Collection, Escrow, ListNonNftAssetRequest, ListNonNftAssetResponse,
    ListNftRequest, ListNftResponse, ListNftForAuctionResponse,
    BuyNftResponse, BuyNonNftAssetResponse,
    CancelNftListingResponse, CancelNonNftListingResponse,
    ConfirmTransferRequest, ConfirmTransferResponse,
    RaiseDisputeRequest, RaiseDisputeResponse,
    RefundRequest, RefundResponse,
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
    chain_config: ChainConfig,
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
        chain_config: ChainConfig,
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
        let marketplace_abi = abis::load_marketplace_proxy_abi()?;

        // Create contract instances
        let vertix_nft = Contract::new(chain_config.contract_addresses.vertix_nft, nft_abi, provider.clone());
        let vertix_escrow = Contract::new(chain_config.contract_addresses.vertix_escrow, escrow_abi, provider.clone());
        let marketplace_proxy = Contract::new(chain_config.contract_addresses.marketplace_proxy, marketplace_abi, provider.clone());

        Ok(Self {
            provider,
            wallet,
            chain_config,
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

                if let Some(gas_used) = receipt.gas_used {
                    return Err(ContractError::TransactionError(format!("Collection creation transaction reverted. Gas used: {}", gas_used)));
                }
                return Err(ContractError::TransactionError("Collection creation transaction reverted".to_string()));
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
        let read_only_client = ReadOnlyContractClient::new(
            self.provider.url().to_string(),
            self.chain_config.clone(),
        ).await?;
        let collection_exists = read_only_client.check_collection_exists(collection_id).await?;
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
        let call_with_gas = call.gas(5000000u64); // Fixed gas limit
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

        // Call mintSingleNft function
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

        // Convert signature to Bytes for Solidity
        let signature_bytes = Bytes::from(
            hex::decode(&signature[2..])
                .map_err(|e| ContractError::ContractCallError(format!("Invalid signature: {}", e)))?
        );



        // Call mintSocialMediaNft function
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

        // Send transaction
        let call_with_gas = call.gas(500000u64);
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
        let token_id = self.extract_social_media_token_id_from_receipt(&receipt)?;

        Ok(MintSocialMediaNftResponse {
            to: Arc::from(to.to_string()),
            token_id,
            social_media_id: Arc::from(social_media_id.to_string()),
            uri: Arc::from(token_uri.to_string()),
            metadata_hash: Arc::from(metadata_hash.to_string()),
            signature: Arc::from(signature.to_string()),
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
            if log.address == self.chain_config.contract_addresses.vertix_nft {
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
            if log.address == self.chain_config.contract_addresses.vertix_nft {
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

            if log.address == self.chain_config.contract_addresses.vertix_nft {
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
            if log.address == H160::from_slice(&self.chain_config.contract_addresses.vertix_nft.0.as_slice()) {

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
            if log.address == H160::from_slice(&self.chain_config.contract_addresses.vertix_nft.0.as_slice()) {
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
    pub fn get_network_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    pub fn get_verification_service(&self) -> &VerificationService {
        &self.verification_service
    }

    /// Get contract addresses
    pub fn get_contract_addresses(&self) -> &ContractAddresses {
        &self.chain_config.contract_addresses
    }

    /// Get provider URL
    pub fn get_provider_url(&self) -> String {
        self.provider.url().to_string()
    }

    /// Get provider
    pub fn get_provider(&self) -> Arc<Provider<Http>> {
        self.provider.clone()
    }

    /// Approve an NFT for the marketplace
    pub async fn approve_nft_for_marketplace(&self, token_id: u64) -> Result<(), ContractError> {
        // First check if we own the token
        let owner: Address = self.vertix_nft
            .method("ownerOf", token_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        println!("   Token {} owner: {:?}, Current wallet: {:?}", token_id, owner, self.wallet.address());

        if owner != self.wallet.address() {
            return Err(ContractError::ContractCallError(format!("Not owner of token {}", token_id)));
        }

        // Check if the token is already approved for the marketplace proxy
        let approved_address: Address = self.vertix_nft
            .method("getApproved", token_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // If already approved to the marketplace proxy, we're good
        if approved_address == self.marketplace_proxy.address() {
            return Ok(());
        }

        // Approve the specific token for the marketplace proxy
        let call = self.vertix_nft
            .method::<_, ()>("approve", (self.marketplace_proxy.address(), token_id))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Add gas limit to the approval transaction
        let call_with_gas = call.gas(200000u64);
        let pending_tx = call_with_gas.send().await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("NFT approval transaction reverted".to_string()));
            }
        }

        Ok(())
    }



    // ============ NON-NFT ASSET OPERATIONS ============


    /// List a non-NFT asset for sale
    pub async fn list_non_nft_asset(&self, request: ListNonNftAssetRequest) -> Result<ListNonNftAssetResponse, ContractError> {
        let price_u96 = U256::from(request.price);

        // Create the function selector for "listNonNftAsset(uint8,string,uint96,string,bytes)"
        let function_selector = keccak256("listNonNftAsset(uint8,string,uint96,string,bytes)")[0..4].to_vec();

        // Encode the parameters
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(request.asset_type)),
            Token::String(request.asset_id.to_string()),
            Token::Uint(price_u96),
            Token::String(request.metadata.to_string()),
            Token::Bytes(request.verification_proof.as_bytes().to_vec()),
        ]);

        // Combine selector and parameters
        let mut calldata = function_selector;
        calldata.extend_from_slice(&params);

        // Create the transaction request
        let tx_request = TransactionRequest::new()
            .to(self.marketplace_proxy.address())
            .data(Bytes::from(calldata))
            .from(self.wallet.address());

        // Send the transaction
        let pending_tx = self.provider
            .send_transaction(tx_request, None)
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Non-NFT asset listing transaction reverted".to_string()));
            }
        }

        // Extract listing ID from events
        let listing_id = self.extract_listing_id_from_receipt(&receipt)?;

        Ok(ListNonNftAssetResponse {
            listing_id,
            creator: self.wallet.address().to_string().into(),
            asset_type: request.asset_type,
            asset_id: request.asset_id,
            price: request.price,
            description: request.description,
            metadata: request.metadata,
            verification_proof: request.verification_proof,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
            chain_id: self.chain_config.chain_id,
        })
    }

        /// List an NFT for sale
    pub async fn list_nft(&self, request: ListNftRequest) -> Result<ListNftResponse, ContractError> {
        let nft_contract = request.nft_contract.parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Convert royalty_bps to Uint96
        let price_u96 = Uint96::from_u256(U256::from(request.price))
            .map_err(|e| ContractError::InvalidUint96Value { reason: e.to_string() })?;


        // Create the function selector for "listNft(address,uint256,uint96)"
        let function_selector = keccak256("listNft(address,uint256,uint96)")[0..4].to_vec();

        // Encode the parameters
        let params = ethers::abi::encode(&[
            Token::Address(nft_contract),
            Token::Uint(U256::from(request.token_id)),
            Token::Uint(U256::from(price_u96.0)),
        ]);

        // Combine selector and parameters
        let mut calldata = function_selector;
        calldata.extend_from_slice(&params);

        // Create the transaction request
        let tx_request = TransactionRequest::new()
            .to(self.marketplace_proxy.address())
            .data(Bytes::from(calldata))
            .from(self.wallet.address());

        // Send the transaction
        let pending_tx = self.provider
            .send_transaction(tx_request, None)
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("NFT listing transaction reverted".to_string()));
            }
        }

        // Extract listing ID from events
        let listing_id = self.extract_listing_id_from_receipt(&receipt)?;

        Ok(ListNftResponse {
            listing_id,
            creator: self.wallet.address().to_string().into(),
            nft_contract: request.nft_contract.into(),
            token_id: request.token_id,
            price: request.price,
            description: request.description,
            active: true,
            is_auction: false,
            created_at: receipt.block_number.unwrap_or_default().as_u64(),
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
            chain_id: self.chain_config.chain_id,
        })
    }

    /// List a social media NFT for sale
    pub async fn list_social_media_nft(&self, request: ListSocialMediaNftRequest) -> Result<ListNftResponse, ContractError> {
        let price_u96 = U256::from(request.price);

        // Create the function selector for "listSocialMediaNft(uint256,uint96,string,bytes)"
        let function_selector = keccak256("listSocialMediaNft(uint256,uint96,string,bytes)")[0..4].to_vec();

        // Decode signature from hex string to bytes
        let signature_bytes = hex::decode(request.signature.trim_start_matches("0x"))
            .map_err(|e| ContractError::ContractCallError(format!("Invalid signature format: {}", e)))?;

        // Encode the parameters
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(request.token_id)),
            Token::Uint(price_u96),
            Token::String(request.social_media_id.to_string()),
            Token::Bytes(signature_bytes),
        ]);

        // Combine selector and parameters
        let mut calldata = function_selector;
        calldata.extend_from_slice(&params);

        // Create the transaction request
        let tx_request = TransactionRequest::new()
            .to(self.marketplace_proxy.address())
            .data(Bytes::from(calldata))
            .from(self.wallet.address());

        // Send the transaction
        let pending_tx = self.provider
            .send_transaction(tx_request, None)
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Social media NFT listing transaction reverted".to_string()));
            }
        }

        // Extract listing ID from events
        let listing_id = self.extract_listing_id_from_receipt(&receipt)?;

        Ok(ListNftResponse {
            listing_id,
            creator: self.wallet.address().to_string().into(),
            nft_contract: "".into(), // Social media NFTs don't have a separate contract
            token_id: request.token_id,
            price: price_u96.as_u64(),
            description: request.description,
            active: true,
            is_auction: false,
            created_at: receipt.block_number.unwrap_or_default().as_u64(),
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
            chain_id: self.chain_config.chain_id,
        })
    }

    /// Extract listing ID from transaction receipt
    fn extract_listing_id_from_receipt(&self, receipt: &TransactionReceipt) -> Result<u64, ContractError> {
        // NFTListed event signature: NFTListed(uint256 indexed listingId, address indexed seller, address nftContract, uint256 tokenId, uint256 price)
        let nft_listed_signature = keccak256("NFTListed(uint256,address,address,uint256,uint256)");

        // NonNFTListed event signature: NonNFTListed(uint256 indexed listingId, address indexed seller, uint8 assetType, string assetId, uint256 price)
        let non_nft_listed_signature = keccak256("NonNFTListed(uint256,address,uint8,string,uint256)");

        // Look for listing events in the transaction logs
        for log in &receipt.logs {
            // Check if this is a listing event from the marketplace
            if log.address == self.marketplace_proxy.address() {
                // Check if this is the NFTListed event
                if log.topics.len() > 0 && log.topics[0] == H256::from_slice(&nft_listed_signature) {
                    // The listing ID is the first indexed parameter (Topic 1, index 1)
                    if log.topics.len() >= 2 {
                        if let Some(listing_id_topic) = log.topics.get(1) {
                            let listing_id = U256::from_big_endian(&listing_id_topic.as_bytes());
                            if listing_id <= U256::from(u64::MAX) {
                                return Ok(listing_id.as_u64());
                            }
                        }
                    }
                }

                // Check if this is the NonNFTListed event
                if log.topics.len() > 0 && log.topics[0] == H256::from_slice(&non_nft_listed_signature) {
                    // The listing ID is the first indexed parameter (Topic 1, index 1)
                    if log.topics.len() >= 2 {
                        if let Some(listing_id_topic) = log.topics.get(1) {
                            let listing_id = U256::from_big_endian(&listing_id_topic.as_bytes());
                            if listing_id <= U256::from(u64::MAX) {
                                return Ok(listing_id.as_u64());
                            }
                        }
                    }
                }
            }
        }

        // If no listing event found, try to get the next listing ID from the marketplace
        // This is a fallback approach
        Ok(1) // Default to 1 if we can't extract from events
    }

    /// Extract fee information from NFTBought event
    fn extract_nft_bought_fees_from_receipt(&self, receipt: &TransactionReceipt) -> Result<(u64, String, u64, String), ContractError> {
        // NFTBought event signature: NFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 royaltyAmount, address royaltyRecipient, uint256 platformFee, address feeRecipient)
        let nft_bought_signature = keccak256("NFTBought(uint256,address,uint256,uint256,address,uint256,address)");

        for log in &receipt.logs {
            if log.address == self.marketplace_proxy.address() {
                if log.topics.len() > 0 && log.topics[0] == H256::from_slice(&nft_bought_signature) {
                    // NFTBought event has 7 parameters: listingId, buyer, price, royaltyAmount, royaltyRecipient, platformFee, feeRecipient
                    // Topics: [0] = event signature, [1] = listingId (indexed), [2] = buyer (indexed)
                    // Data: [0:32] = price, [32:64] = royaltyAmount, [64:96] = royaltyRecipient, [96:128] = platformFee, [128:160] = feeRecipient

                    if log.data.len() >= 160 {
                        let data = &log.data;

                        // Extract royalty amount (bytes 32-64)
                        let royalty_amount = U256::from_big_endian(&data[32..64]);

                        // Extract royalty recipient (bytes 64-96) - address is 20 bytes, padded to 32
                        let royalty_recipient = H160::from_slice(&data[76..96]); // Last 20 bytes of the 32-byte slot

                        // Extract platform fee (bytes 96-128)
                        let platform_fee = U256::from_big_endian(&data[96..128]);

                        // Extract platform recipient (bytes 128-160) - address is 20 bytes, padded to 32
                        let platform_recipient = H160::from_slice(&data[140..160]); // Last 20 bytes of the 32-byte slot

                        return Ok((
                            royalty_amount.as_u64(),
                            format!("0x{:x}", royalty_recipient),
                            platform_fee.as_u64(),
                            format!("0x{:x}", platform_recipient)
                        ));
                    }
                }
            }
        }

        // Return default values if event not found
        Ok((0, "0x0000000000000000000000000000000000000000".to_string(), 0, "0x0000000000000000000000000000000000000000".to_string()))
    }

    /// Extract fee information from NonNFTBought event
    fn extract_non_nft_bought_fees_from_receipt(&self, receipt: &TransactionReceipt) -> Result<(u64, u64, String), ContractError> {
        // NonNFTBought event signature: NonNFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 sellerAmount, uint256 platformFee, address feeRecipient)
        let non_nft_bought_signature = keccak256("NonNFTBought(uint256,address,uint256,uint256,uint256,address)");

        for log in &receipt.logs {
            if log.address == self.marketplace_proxy.address() {
                if log.topics.len() > 0 && log.topics[0] == H256::from_slice(&non_nft_bought_signature) {
                    // NonNFTBought event has 6 parameters: listingId, buyer, price, sellerAmount, platformFee, feeRecipient
                    // Topics: [0] = event signature, [1] = listingId (indexed), [2] = buyer (indexed)
                    // Data: [0:32] = price, [32:64] = sellerAmount, [64:96] = platformFee, [96:128] = feeRecipient

                    if log.data.len() >= 128 {
                        let data = &log.data;

                        // Extract seller amount (bytes 32-64)
                        let seller_amount = U256::from_big_endian(&data[32..64]);

                        // Extract platform fee (bytes 64-96)
                        let platform_fee = U256::from_big_endian(&data[64..96]);

                        // Extract platform recipient (bytes 96-128) - address is 20 bytes, padded to 32
                        let platform_recipient = H160::from_slice(&data[108..128]); // Last 20 bytes of the 32-byte slot

                        return Ok((
                            seller_amount.as_u64(),
                            platform_fee.as_u64(),
                            format!("0x{:x}", platform_recipient)
                        ));
                    }
                }
            }
        }

        // Return default values if event not found
        Ok((0, 0, "0x0000000000000000000000000000000000000000".to_string()))
    }

    /// List an NFT for auction
    pub async fn list_nft_for_auction(&self, listing_id: u64) -> Result<ListNftForAuctionResponse, ContractError> {
        println!("   Listing NFT {} for auction...", listing_id);

        // Create the function selector for "listForAuction(uint256,bool)"
        let function_selector = keccak256("listForAuction(uint256,bool)")[0..4].to_vec();

        // Encode the parameters (listing_id, isNft=true)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
            Token::Bool(true), // isNft = true
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data)
            .gas(200000u64); // Add gas limit

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send list for auction transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   NFT listed for auction successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        // Extract listing ID from events if possible
        let listing_id_from_events = self.extract_listing_id_from_auction_events(&receipt).unwrap_or(listing_id);

        Ok(ListNftForAuctionResponse {
            listing_id: listing_id_from_events,
            is_nft: true,
            transaction_hash: Arc::from(format!("0x{:x}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// List a non-NFT asset for auction
    pub async fn list_non_nft_for_auction(&self, listing_id: u64) -> Result<ListNftForAuctionResponse, ContractError> {
        println!("   Listing non-NFT {} for auction...", listing_id);

        // Create the function selector for "listForAuction(uint256,bool)"
        let function_selector = keccak256("listForAuction(uint256,bool)")[0..4].to_vec();

        // Encode the parameters (listing_id, isNft=false)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
            Token::Bool(false), // isNft = false
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data);

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send list for auction transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   Non-NFT listed for auction successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        // Extract listing ID from events if possible
        let listing_id_from_events = self.extract_listing_id_from_auction_events(&receipt).unwrap_or(listing_id);

        Ok(ListNftForAuctionResponse {
            listing_id: listing_id_from_events,
            is_nft: false,
            transaction_hash: Arc::from(format!("0x{:x}", receipt.transaction_hash)),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Buy an NFT listing
    pub async fn buy_nft(&self, listing_id: u64, price: u64) -> Result<BuyNftResponse, ContractError> {
        println!("   Buying NFT listing {} for {} wei...", listing_id, price);

        // Create the function selector for "buyNft(uint256)"
        let function_selector = keccak256("buyNft(uint256)")[0..4].to_vec();

        // Encode the parameters (listing_id)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction with value (price)
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data)
            .value(price)
            .gas(300000u64); // Add gas limit

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send buy NFT transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   NFT purchased successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        // Extract fee information from NFTBought event
        let (royalty_amount, royalty_recipient, platform_fee, platform_recipient) = 
            self.extract_nft_bought_fees_from_receipt(&receipt)?;

        Ok(BuyNftResponse {
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            new_owner: self.wallet.address().to_string(),
            price,
            royalty_amount,
            royalty_recipient,
            platform_fee,
            platform_recipient,
        })
    }

    /// Buy a non-NFT asset listing
    pub async fn buy_non_nft_asset(&self, listing_id: u64, price: u64) -> Result<BuyNonNftAssetResponse, ContractError> {
        println!("   Buying non-NFT listing {} for {} wei...", listing_id, price);

        // Create the function selector for "buyNonNftAsset(uint256)"
        let function_selector = keccak256("buyNonNftAsset(uint256)")[0..4].to_vec();

        // Encode the parameters (listing_id)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction with value (price)
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data)
            .value(price)
            .gas(300000u64); // Add gas limit

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send buy non-NFT transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   Non-NFT purchased successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        // Extract fee information from NonNFTBought event
        let (seller_amount, platform_fee, platform_recipient) = 
            self.extract_non_nft_bought_fees_from_receipt(&receipt)?;

        Ok(BuyNonNftAssetResponse {
            listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            buyer: self.wallet.address().to_string(),
            price,
            seller_amount,
            platform_fee,
            platform_recipient,
        })
    }

    /// Cancel an NFT listing
    pub async fn cancel_nft_listing(&self, listing_id: u64) -> Result<CancelNftListingResponse, ContractError> {
        println!("   Cancelling NFT listing {}...", listing_id);

        // Create the function selector for "cancelNftListing(uint256)"
        let function_selector = keccak256("cancelNftListing(uint256)")[0..4].to_vec();

        // Encode the parameters (listing_id)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data)
            .from(self.wallet.address());

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send cancel NFT listing transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   NFT listing cancelled successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(CancelNftListingResponse {
            listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            seller: self.wallet.address().to_string(),
            is_nft: true,
        })
    }

    /// Cancel a non-NFT asset listing
    pub async fn cancel_non_nft_listing(&self, listing_id: u64) -> Result<CancelNonNftListingResponse, ContractError> {
        println!("   Cancelling non-NFT listing {}...", listing_id);

        // Create the function selector for "cancelNonNftListing(uint256)"
        let function_selector = keccak256("cancelNonNftListing(uint256)")[0..4].to_vec();

        // Encode the parameters (listing_id)
        let params = ethers::abi::encode(&[
            Token::Uint(U256::from(listing_id)),
        ]);

        // Combine function selector with parameters
        let data = [function_selector, params].concat();

        // Create transaction
        let tx = TransactionRequest::new()
            .to(self.chain_config.contract_addresses.marketplace_proxy)
            .data(data)
            .from(self.wallet.address());

        // Send transaction
        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to send cancel non-NFT listing transaction: {}", e)))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to get transaction receipt: {}", e)))?
            .ok_or_else(|| ContractError::ContractCallError("Transaction receipt not found".to_string()))?;

        println!("   Non-NFT listing cancelled successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(CancelNonNftListingResponse {
            listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash),
            seller: self.wallet.address().to_string(),
            is_nft: false,
        })
    }

    /// Confirm transfer in escrow (buyer confirms they received the asset)
    pub async fn confirm_transfer(&self, request: ConfirmTransferRequest) -> Result<ConfirmTransferResponse, ContractError> {
        println!("   Confirming transfer for listing {}...", request.listing_id);

        // First, get the escrow details to verify the current wallet is the buyer
        let read_only_client = ReadOnlyContractClient::new(
            self.provider.url().to_string(),
            self.chain_config.clone(),
        ).await?;

        let escrow = read_only_client.get_escrow(request.listing_id).await?;
        let current_wallet = format!("0x{:x}", self.wallet.address());

        if escrow.buyer.to_string() != current_wallet {
            return Err(ContractError::NotAuthorized {
                operation: format!("Only the buyer ({}) can confirm transfer, current wallet: {}", escrow.buyer, current_wallet) 
            });
        }

        if escrow.completed {
            return Err(ContractError::ContractCallError("Escrow is already completed".to_string()));
        }

        if escrow.disputed {
            return Err(ContractError::ContractCallError("Cannot confirm transfer while escrow is in dispute".to_string()));
        }

        // Call the confirmTransfer function on the escrow contract
        let call = self.vertix_escrow
            .method::<_, ()>("confirmTransfer", request.listing_id)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with gas limit
        let call_with_gas = call.gas(200000u64);
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Confirm transfer transaction reverted".to_string()));
            }
        }

        println!("   Transfer confirmed successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);
        println!("     Amount released to seller: {} wei", escrow.amount);

        Ok(ConfirmTransferResponse {
            listing_id: request.listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            seller: escrow.seller,
            amount: escrow.amount,
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Raise a dispute in escrow (can be called by either seller or buyer)
    pub async fn raise_dispute(&self, request: RaiseDisputeRequest) -> Result<RaiseDisputeResponse, ContractError> {
        println!("   Raising dispute for listing {}...", request.listing_id);

        // First, get the escrow details to verify the current wallet is a participant
        let read_only_client = ReadOnlyContractClient::new(
            self.provider.url().to_string(),
            self.chain_config.clone(),
        ).await?;

        let escrow = read_only_client.get_escrow(request.listing_id).await?;
        let current_wallet = format!("0x{:x}", self.wallet.address());

        if escrow.seller.to_string() != current_wallet && escrow.buyer.to_string() != current_wallet {
            return Err(ContractError::NotAuthorized {
                operation: format!("Only escrow participants can raise dispute. Seller: {}, Buyer: {}, Current: {}",
                    escrow.seller, escrow.buyer, current_wallet)
            });
        }

        if escrow.completed {
            return Err(ContractError::ContractCallError("Cannot raise dispute on completed escrow".to_string()));
        }

        if escrow.disputed {
            return Err(ContractError::ContractCallError("Dispute already raised for this escrow".to_string()));
        }

        // Call the raiseDispute function on the escrow contract
        let call = self.vertix_escrow
            .method::<_, ()>("raiseDispute", request.listing_id)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with gas limit
        let call_with_gas = call.gas(200000u64);
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Raise dispute transaction reverted".to_string()));
            }
        }

        println!("   Dispute raised successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);
        println!("     Raised by: {}", current_wallet);

        Ok(RaiseDisputeResponse {
            listing_id: request.listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            raiser: current_wallet.into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Refund escrow if deadline has passed (anyone can call this)
    pub async fn refund(&self, request: RefundRequest) -> Result<RefundResponse, ContractError> {
        println!("   Processing refund for listing {}...", request.listing_id);

        // First, get the escrow details to check deadline and status
        let read_only_client = ReadOnlyContractClient::new(
            self.provider.url().to_string(),
            self.chain_config.clone(),
        ).await?;

        let escrow = read_only_client.get_escrow(request.listing_id).await?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if escrow.deadline > current_time {
            return Err(ContractError::ContractCallError(format!(
                "Deadline not passed yet. Deadline: {}, Current time: {}", escrow.deadline, current_time
            )));
        }

        if escrow.completed {
            return Err(ContractError::ContractCallError("Escrow is already completed".to_string()));
        }

        if escrow.disputed {
            return Err(ContractError::ContractCallError("Cannot refund while escrow is in dispute".to_string()));
        }

        // Call the refund function on the escrow contract
        let call = self.vertix_escrow
            .method::<_, ()>("refund", request.listing_id)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction with gas limit
        let call_with_gas = call.gas(200000u64);
        let pending_tx = call_with_gas
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Refund transaction reverted".to_string()));
            }
        }

        println!("   Refund processed successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);
        println!("     Amount refunded to buyer: {} wei", escrow.amount);

        Ok(RefundResponse {
            listing_id: request.listing_id,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            buyer: escrow.buyer,
            amount: escrow.amount,
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Extract listing ID from ListedForAuction events
    fn extract_listing_id_from_auction_events(&self, receipt: &TransactionReceipt) -> Option<u64> {
        // Look for ListedForAuction event
        // Event signature: ListedForAuction(uint256 indexed listingId, bool isNft, bool isListedForAuction)
        let event_signature = keccak256("ListedForAuction(uint256,bool,bool)");

        for log in &receipt.logs {
            if log.topics.len() >= 2 && log.topics[0] == event_signature.into() {
                // Extract listing ID from the first indexed parameter
                if let Some(listing_id_topic) = log.topics.get(1) {
                    let listing_id_bytes = listing_id_topic.as_bytes();
                    if listing_id_bytes.len() >= 8 {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&listing_id_bytes[listing_id_bytes.len() - 8..]);
                        let listing_id = u64::from_be_bytes(bytes);
                        return Some(listing_id);
                    }
                }
            }
        }

        None
    }
}

/// Read-only contract client for view functions (no wallet required)
pub struct ReadOnlyContractClient {
    provider: Arc<Provider<Http>>,
    chain_config: ChainConfig,
    vertix_nft: Contract<Provider<Http>>,
    marketplace_proxy: Contract<Provider<Http>>,
    vertix_escrow: Contract<Provider<Http>>,
}

impl ReadOnlyContractClient {
    /// Create a new read-only contract client
    pub async fn new(
        rpc_url: String,
        chain_config: ChainConfig,
    ) -> Result<Self, ContractError> {
        // Create provider
        let provider = Provider::<Http>::try_from(&rpc_url)
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let provider = Arc::new(provider);

        // Load ABIs
        let nft_abi = abis::load_vertix_nft_abi()?;
        let marketplace_abi = abis::load_marketplace_proxy_abi()?;
        let escrow_abi = abis::load_vertix_escrow_abi()?;

        // Create contract instances
        let vertix_nft = Contract::new(chain_config.contract_addresses.vertix_nft, nft_abi, provider.clone());
        let marketplace_proxy = Contract::new(chain_config.contract_addresses.marketplace_proxy, marketplace_abi, provider.clone());
        let vertix_escrow = Contract::new(chain_config.contract_addresses.vertix_escrow, escrow_abi, provider.clone());

        Ok(Self {
            provider,
            chain_config,
            vertix_nft,
            marketplace_proxy,
            vertix_escrow,
        })
    }

    /// Get wallet balance for a specific address
    pub async fn get_wallet_balance(&self, address: Address) -> Result<U256, ContractError> {
        let balance = self.provider
            .get_balance(address, None)
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
            Ok((creator, _name, _symbol, _image, _max_supply, _current_supply)) => {
                // If creator is not zero address, collection exists
                Ok(creator != Address::zero())
            },
            Err(_) => {
                Ok(false)
            },
        }
    }

    /// Get NFT listing details
    pub async fn get_nft_listing(&self, listing_id: u64) -> Result<(String, String, u64, u64, bool, bool), ContractError> {
        // Call the getNftListing function on the marketplace proxy contract
        let result: (Address, Address, U256, U256, u8, u8, bool) = self.marketplace_proxy
            .method("getNftListing", listing_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        let (seller, nft_contract, token_id, price, flags, _origin_chain, _is_cross_chain) = result;

        // Extract active and is_auction from flags
        let active = (flags & 1) == 1;
        let is_auction = (flags & 2) == 2;

        Ok((
            format!("0x{:x}", seller),
            format!("0x{:x}", nft_contract),
            token_id.as_u64(),
            price.as_u64(),
            active,
            is_auction
        ))
    }

    /// Get non-NFT listing details
    pub async fn get_non_nft_listing(&self, listing_id: u64) -> Result<(String, u64, u8, bool, u8, String, String), ContractError> {
        // Call the getNonNftListing function on the marketplace storage contract
        let result: (Address, U256, u8, bool, bool, String, String, [u8; 32]) = self.marketplace_proxy
            .method("getNonNftListing", listing_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        let (seller, price, asset_type, active, auction_listed, asset_id, metadata, _verification_hash) = result;

        Ok((
            format!("0x{:x}", seller),
            price.as_u64(),
            asset_type,
            active,
            if auction_listed { 1 } else { 0 }, // Convert bool to u8 for origin_chain
            asset_id,
            metadata
        ))
    }

    /// Get all collections from the contract
    pub async fn get_all_collections(&self) -> Result<Vec<Collection>, ContractError> {
        let mut collections = Vec::new();
        let mut collection_id = 1u64;

        // Try to get collections until we find one that doesn't exist
        // We'll limit to a reasonable number to avoid infinite loops
        while collection_id <= 1000 {
            match self.get_collection_by_id(collection_id).await {
                Ok(collection) => {
                    collections.push(collection);
                    collection_id += 1;
                }
                Err(_) => {
                    // Collection doesn't exist, we've found all collections
                    break;
                }
            }
        }

        Ok(collections)
    }

    /// Get a specific collection by ID
    pub async fn get_collection_by_id(&self, collection_id: u64) -> Result<Collection, ContractError> {
        // Call the getCollectionDetails function to get collection data
        let collection_data: (Address, String, String, String, U256, U256) = self
            .vertix_nft
            .method("getCollectionDetails", collection_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        let (creator, name, symbol, image, max_supply, current_supply) = collection_data;

        Ok(Collection {
            collection_id,
            chain_id: self.chain_config.chain_id,
            name: name.into(),
            symbol: symbol.into(),
            image: image.into(),
            max_supply: max_supply.as_u128() as u16,
            creator: format!("{:?}", creator).into(),
            current_supply: current_supply.as_u128() as u16,
            total_volume_wei: None, // Not available from contract call
            floor_price_wei: None, // Not available from contract call
        })
    }

    /// Get collections by creator address
    pub async fn get_collections_by_creator(&self, creator_address: String) -> Result<Vec<Collection>, ContractError> {
        let mut collections = Vec::new();
        let mut collection_id = 1u64;

        // Try to get collections until we find one that doesn't exist
        loop {
            match self.get_collection_by_id(collection_id).await {
                Ok(collection) => {
                    if collection.creator.to_lowercase() == creator_address.to_lowercase() {
                        collections.push(collection);
                    }
                    collection_id += 1;
                }
                Err(_) => {
                    // Collection doesn't exist, stop searching
                    break;
                }
            }
        }

        Ok(collections)
    }

    /// Get contract addresses
    pub fn get_contract_addresses(&self) -> &ContractAddresses {
        &self.chain_config.contract_addresses
    }

    /// Get escrow details for a listing
    pub async fn get_escrow(&self, listing_id: u64) -> Result<Escrow, ContractError> {
        // Call the getEscrow function on the escrow contract
        let escrow_data: (Address, Address, U256, U256, bool, bool) = self.vertix_escrow
            .method("getEscrow", listing_id)?
            .call()
            .await
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        let (seller, buyer, amount, deadline, completed, disputed) = escrow_data;

        Ok(Escrow {
            listing_id,
            seller: format!("0x{:x}", seller).into(),
            buyer: format!("0x{:x}", buyer).into(),
            amount: amount.as_u64(),
            deadline: deadline.as_u64(),
            completed,
            disputed,
        })
    }
}