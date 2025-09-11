use ethers::{
    providers::{Http, Provider, Middleware},
    types::{BlockNumber, Log, Address, U256},
};
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{info, error, warn};
use sqlx::PgPool;
use std::collections::HashMap;

use crate::infrastructure::repositories::collections_repository::CollectionsRepository;
use crate::infrastructure::repositories::nft_events_repository::NftEventsRepository;
use crate::infrastructure::repositories::social_media_events_repository::SocialMediaEventsRepository;
use crate::infrastructure::repositories::listing_repository::ListingRepository;
use crate::infrastructure::contracts::config::get_supported_chains;
use crate::infrastructure::contracts::types::ChainConfig;
use crate::domain::services::ContractError;

/// Multi-chain blockchain listener that monitors all supported chains simultaneously
pub struct MultiChainListener {
    chain_listeners: HashMap<u64, ChainListener>,
    collections_repository: CollectionsRepository,
    nft_events_repository: NftEventsRepository,
    social_media_events_repository: SocialMediaEventsRepository,
    listing_repository: ListingRepository,
    poll_interval: Duration,
    running: bool,
}

/// Individual chain listener for a specific network
struct ChainListener {
    chain_config: ChainConfig,
    provider: Arc<Provider<Http>>,
    contract_addresses: HashMap<String, Address>,
    last_processed_block: u64,
    running: bool,
    collections_repository: CollectionsRepository,
    nft_events_repository: NftEventsRepository,
    social_media_events_repository: SocialMediaEventsRepository,
    listing_repository: ListingRepository,
}

impl MultiChainListener {
    pub fn new(
        db_pool: PgPool,
        poll_interval: Duration,
    ) -> Result<Self, ContractError> {
        let collections_repository = CollectionsRepository::new(db_pool.clone());
        let nft_events_repository = NftEventsRepository::new(db_pool.clone());
        let social_media_events_repository = SocialMediaEventsRepository::new(db_pool.clone());
        let listing_repository = ListingRepository::new(db_pool);

        Ok(Self {
            chain_listeners: HashMap::new(),
            collections_repository,
            nft_events_repository,
            social_media_events_repository,
            listing_repository,
            poll_interval,
            running: false,
        })
    }

    /// Start monitoring all supported chains
    pub async fn start(&mut self) -> Result<(), ContractError> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting multi-chain blockchain listener...");

        // Get all supported chains
        let supported_chains = get_supported_chains()?;
        info!("Found {} supported chains", supported_chains.len());

        // Initialize listeners for each chain
        for chain_config in supported_chains {
            let chain_id = chain_config.chain_id;
            if let Err(e) = self.add_chain_listener(chain_config).await {
                error!("Failed to add listener for chain {}: {}", chain_id, e);
                continue;
            }
        }

        if self.chain_listeners.is_empty() {
            warn!("No chain listeners were successfully initialized");
            return Ok(());
        }

        info!("Successfully initialized {} chain listeners", self.chain_listeners.len());

        // Start monitoring loop
        let mut interval = interval(self.poll_interval);
        while self.running {
            interval.tick().await;

            // Process all chains sequentially to avoid borrowing issues
            for (chain_id, listener) in &mut self.chain_listeners {
                if listener.running {
                    if let Err(e) = listener.process_new_blocks().await {
                        error!("Error processing chain {}: {}", chain_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Stop monitoring all chains
    pub fn stop(&mut self) {
        self.running = false;
        for listener in self.chain_listeners.values_mut() {
            listener.running = false;
        }
        info!("Stopping multi-chain blockchain listener...");
    }

    /// Add a new chain listener
    async fn add_chain_listener(&mut self, chain_config: ChainConfig) -> Result<(), ContractError> {
        let chain_id = chain_config.chain_id;

        // Create provider for this chain
        let provider = Arc::new(Provider::<Http>::try_from(chain_config.rpc_url.clone())
            .map_err(|e| ContractError::RpcError(format!("Failed to create provider for chain {}: {}", chain_id, e)))?);

        // Test connection
        let current_block = provider.get_block_number().await
            .map_err(|e| ContractError::RpcError(format!("Failed to connect to chain {}: {}", chain_id, e)))?;

        info!("Connected to chain {} ({}): Block {}", 
              chain_id, chain_config.name, current_block);

        // Extract contract addresses
        let contract_addresses = self.extract_contract_addresses(&chain_config)?;

        // Start from 500 blocks back to catch recent transactions
        let start_block = if current_block.as_u64() > 500 {
            current_block.as_u64() - 500
        } else {
            0
        };

        let listener = ChainListener {
            chain_config: chain_config.clone(),
            provider,
            contract_addresses,
            last_processed_block: start_block,
            running: true,
            collections_repository: self.collections_repository.clone(),
            nft_events_repository: self.nft_events_repository.clone(),
            social_media_events_repository: self.social_media_events_repository.clone(),
            listing_repository: self.listing_repository.clone(),
        };

        info!("Starting chain listener from block {} (current: {})", start_block, current_block.as_u64());

        self.chain_listeners.insert(chain_id, listener);
        Ok(())
    }

    /// Extract contract addresses from chain configuration
    fn extract_contract_addresses(&self, chain_config: &ChainConfig) -> Result<HashMap<String, Address>, ContractError> {
        let mut addresses = HashMap::new();

        addresses.insert("vertix_nft".to_string(), chain_config.contract_addresses.vertix_nft);
        addresses.insert("vertix_escrow".to_string(), chain_config.contract_addresses.vertix_escrow);
        addresses.insert("vertix_governance".to_string(), chain_config.contract_addresses.vertix_governance);

        Ok(addresses)
    }



    /// Get all active chain IDs
    pub fn get_active_chain_ids(&self) -> Vec<u64> {
        self.chain_listeners.keys().cloned().collect()
    }
}

impl ChainListener {
    /// Process new blocks for this chain
    async fn process_new_blocks(&mut self) -> Result<(), ContractError> {
        let current_block = self.provider
            .get_block_number()
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let current_block_num = current_block.as_u64();

        if current_block_num <= self.last_processed_block {
            return Ok(());
        }



        for block_num in (self.last_processed_block + 1)..=current_block_num {
            if let Err(e) = self.process_block(block_num).await {
                error!("Error processing block {} on chain {}: {}", 
                       block_num, self.chain_config.chain_id, e);
                continue;
            }
        }

        self.last_processed_block = current_block_num;
        Ok(())
    }

    /// Process a specific block
    async fn process_block(&self, block_num: u64) -> Result<(), ContractError> {
        let block = self.provider
            .get_block_with_txs(BlockNumber::Number(block_num.into()))
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?
            .ok_or_else(|| ContractError::RpcError("Block not found".to_string()))?;

        info!("Processing block {} on chain {} ({}) - {} transactions", 
              block_num, self.chain_config.chain_id, self.chain_config.name, block.transactions.len());

        // Process logs for events
        for tx in block.transactions {
            if let Some(receipt) = self.provider
                .get_transaction_receipt(tx.hash)
                .await
                .map_err(|e| ContractError::RpcError(e.to_string()))?
            {
                self.process_transaction_logs(&receipt.logs, block_num).await?;
            }
        }

        Ok(())
    }

    /// Process transaction logs for events
    async fn process_transaction_logs(&self, logs: &[Log], block_number: u64) -> Result<(), ContractError> {
        for log in logs {
            if self.is_our_contract_log(log) {
                self.handle_contract_event(log, block_number).await?;
            }
        }
        Ok(())
    }

    /// Check if log is from our contracts
    fn is_our_contract_log(&self, log: &Log) -> bool {
        let is_ours = self.contract_addresses.values().any(|&address| log.address == address);
        if is_ours {
            info!("Found event from our contract at address {:?} on chain {}", log.address, self.chain_config.chain_id);
        }
        is_ours
    }

    /// Handle contract events dynamically
    async fn handle_contract_event(&self, log: &Log, block_number: u64) -> Result<(), ContractError> {
        // Store event in database with chain information
        if let Some(tx_hash) = &log.transaction_hash {
            let tx_hash_bytes: [u8; 32] = tx_hash.as_bytes().try_into()
                .map_err(|e| ContractError::ContractCallError(format!("Invalid transaction hash: {}", e)))?;

            // Store in blockchain events repository with chain ID
            self.store_event_with_chain(log, block_number, &tx_hash_bytes).await?;
        }

        Ok(())
    }

    /// Store event in database with chain information
    async fn store_event_with_chain(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Get event signature from first topic
        let signature = if let Some(topic) = log.topics.get(0) {
            format!("0x{}", hex::encode(topic.as_bytes()))
        } else {
            return Ok(());
        };

        // Extract event data based on signature
        match signature.as_str() {
            // CollectionCreated event: CollectionCreated(uint256,address,string,string,string,uint256)
            "0x5e4b3a0fb63342b938f4f873f16127a2687698a0eb8c0eba5e470b32bba9d85b" => {
                self.handle_collection_created_event(log, block_number, tx_hash).await?;
            },
            // NFTMinted event: NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)
            "0xf223b61344ba5afacd4809990cbc46788d1166f1f02a8d9825ef806cfbe88a5c" => {
                self.handle_nft_minted_event(log, block_number, tx_hash).await?;
            },
            // SocialMediaNFTMinted event: SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)
            "0x250071de8d32b6287a32c74629e965f9936ae550fdbabc1df7fd4a0cb343f026" => {
                self.handle_social_media_nft_minted_event(log, block_number, tx_hash).await?;
            },
            // NFTListingCreated event: NFTListingCreated(uint256,address,uint256,uint256,uint256)
            "0x4a25d94a3f1c1e7e0f0c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8" => {
                self.handle_nft_listing_created_event(log, block_number, tx_hash).await?;
            },
            // NFTListingSold event: NFTListingSold(uint256,address,uint256)
            "0x8a25d94a3f1c1e7e0f0c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8" => {
                self.handle_nft_listing_sold_event(log, block_number, tx_hash).await?;
            },
            // NFTListingCancelled event: NFTListingCancelled(uint256,address)
            "0x9a25d94a3f1c1e7e0f0c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8" => {
                self.handle_nft_listing_cancelled_event(log, block_number, tx_hash).await?;
            },

            _ => {
                info!("Unknown event signature {} on chain {}: {} - Contract address: {:?}", 
                      signature, self.chain_config.chain_id, self.chain_config.name, log.address);
                // Also log the full log for debugging
                info!("Full log data: topics={:?}, data_len={}", log.topics, log.data.len());
            }
        }

        Ok(())
    }

    /// Handle CollectionCreated event
    async fn handle_collection_created_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: CollectionCreated(uint256,address,string,string,string,uint256)
        if log.topics.len() < 3 || log.data.len() < 96 {
            return Ok(());
        }

        let collection_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let _creator_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..])); // Last 20 bytes

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 96 {
            return Ok(());
        }

        // Extract name, symbol, image, maxSupply from data
        let name = self.extract_string_from_data(data, 0)?;
        let symbol = self.extract_string_from_data(data, 32)?;
        let image = self.extract_string_from_data(data, 64)?;
        let max_supply = U256::from_big_endian(&data[96..128]).as_u64();

        // Store collection in database
        let creator_address_bytes: [u8; 20] = log.topics[2].as_bytes()[12..].try_into()
            .map_err(|_| ContractError::ContractCallError("Invalid creator address".to_string()))?;

        if let Err(e) = self.collections_repository.store_collection(
            collection_id,
            self.chain_config.chain_id,
            &name,
            &symbol,
            Some(&image),
            max_supply,
            0, // current_supply starts at 0
            creator_address_bytes.into(),
            tx_hash,
            block_number,
        ).await {
            error!("Failed to store collection {} on chain {}: {}", 
                   collection_id, self.chain_config.chain_id, e);
        }

        info!("Stored CollectionCreated event: collection_id={}, chain_id={}, name={}", 
              collection_id, self.chain_config.chain_id, name);

        Ok(())
    }

    /// Handle NFTMinted event
    async fn handle_nft_minted_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)
        if log.topics.len() < 4 {
            return Ok(());
        }

        let to_address = format!("0x{}", hex::encode(&log.topics[1].as_bytes()[12..]));
        let token_id = U256::from_big_endian(&log.topics[2].as_bytes()).as_u64();
        let collection_id = U256::from_big_endian(&log.topics[3].as_bytes()).as_u64();

        // Store NFT mint event in database
        if let Err(e) = self.nft_events_repository.store_nft_mint_event(
            self.chain_config.chain_id,
            &to_address,
            token_id,
            Some(collection_id),
            tx_hash,
            block_number,
        ).await {
            error!("Failed to store NFT mint event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTMinted event: token_id={}, collection_id={}, chain_id={}", 
              token_id, collection_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle SocialMediaNFTMinted event
    async fn handle_social_media_nft_minted_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let to_address = format!("0x{}", hex::encode(&log.topics[1].as_bytes()[12..]));
        let token_id = U256::from_big_endian(&log.topics[2].as_bytes()).as_u64();

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 64 {
            return Ok(());
        }

        let social_media_id = self.extract_string_from_data(data, 0)?;
        let _social_media_type = self.extract_string_from_data(data, 32)?;

        // Store social media NFT mint event in database
        if let Err(e) = self.social_media_events_repository.store_social_media_nft_minted_event(
            self.chain_config.chain_id,
            &to_address,
            token_id,
            &social_media_id,
            tx_hash,
            block_number,
        ).await {
            error!("Failed to store social media NFT mint event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored SocialMediaNFTMinted event: token_id={}, social_media_id={}, chain_id={}", 
              token_id, social_media_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTListingCreated event
    async fn handle_nft_listing_created_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTListingCreated(uint256,address,uint256,uint256,uint256)
        if log.topics.len() < 4 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));
        let nft_contract = format!("0x{}", hex::encode(&log.topics[3].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 64 {
            return Ok(());
        }

        let token_id = U256::from_big_endian(&data[0..32]).as_u64();
        let price = U256::from_big_endian(&data[32..64]).as_u128();

        // Store NFT listing created event in database
        if let Err(e) = self.listing_repository.create_nft_listing_from_event(
            self.chain_config.chain_id,
            listing_id,
            &nft_contract,
            token_id,
            &seller_address,
            price,
            tx_hash,
            block_number,
        ).await {
            error!("Failed to store NFT listing created event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTListingCreated event: listing_id={}, nft_contract={}, token_id={}, chain_id={}", 
              listing_id, nft_contract, token_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTListingSold event
    async fn handle_nft_listing_sold_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTListingSold(uint256,address,uint256)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let buyer_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 32 {
            return Ok(());
        }

        let sale_price = U256::from_big_endian(&data[0..32]).as_u128();

        // Mark NFT listing as sold in database
        if let Err(e) = self.listing_repository.mark_nft_listing_sold(
            self.chain_config.chain_id,
            listing_id,
            &buyer_address,
            sale_price,
            tx_hash,
            block_number,
        ).await {
            error!("Failed to mark NFT listing as sold on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTListingSold event: listing_id={}, buyer={}, sale_price={}, chain_id={}", 
              listing_id, buyer_address, sale_price, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTListingCancelled event
    async fn handle_nft_listing_cancelled_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTListingCancelled(uint256,address)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Mark NFT listing as cancelled in database
        if let Err(e) = self.listing_repository.mark_nft_listing_cancelled(
            self.chain_config.chain_id,
            listing_id,
            &seller_address,
            tx_hash,
            block_number,
        ).await {
            error!("Failed to mark NFT listing as cancelled on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTListingCancelled event: listing_id={}, seller={}, chain_id={}", 
              listing_id, seller_address, self.chain_config.chain_id);

        Ok(())
    }







    /// Extract string from event data
    fn extract_string_from_data(&self, data: &[u8], offset: usize) -> Result<String, ContractError> {
        if offset + 32 > data.len() {
            return Err(ContractError::ContractCallError("Data too short for string extraction".to_string()));
        }

        let length = U256::from_big_endian(&data[offset..offset + 32]).as_usize();
        if offset + 32 + length > data.len() {
            return Err(ContractError::ContractCallError("String data extends beyond available data".to_string()));
        }

        let string_data = &data[offset + 32..offset + 32 + length];
        String::from_utf8(string_data.to_vec())
            .map_err(|e| ContractError::ContractCallError(format!("Invalid UTF-8 string: {}", e)))
    }
}
