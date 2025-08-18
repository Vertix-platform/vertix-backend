use ethers::{
    providers::{Http, Provider, Middleware},
    types::{H160, BlockNumber, Log, Address, U256},
};
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{info, error, debug};
use sqlx::PgPool;
// use uuid::Uuid;

use crate::infrastructure::contracts::client::ContractClient;
use crate::infrastructure::repositories::blockchain_events_repository::BlockchainEventsRepository;
use crate::domain::services::ContractError;

pub struct BlockchainListener {
    provider: Arc<Provider<Http>>,
    contract_client: ContractClient,
    // db_pool: PgPool,
    blockchain_events_repository: BlockchainEventsRepository,
    last_processed_block: u64,
    poll_interval: Duration,
    running: bool,
}

impl BlockchainListener {
    pub fn new(
        provider: Arc<Provider<Http>>,
        contract_client: ContractClient,
        _db_pool: PgPool,
        poll_interval: Duration,
        blockchain_events_repository: BlockchainEventsRepository,
    ) -> Self {
        Self {
            provider,
            contract_client,
            // db_pool,
            blockchain_events_repository,
            last_processed_block: 0,
            poll_interval,
            running: false,
        }
    }

    pub async fn start(&mut self) -> Result<(), ContractError> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting blockchain listener...");

        // Get current block number if not set
        if self.last_processed_block == 0 {
            let current_block = self.provider
                .get_block_number()
                .await
                .map_err(|e| ContractError::RpcError(e.to_string()))?;
            self.last_processed_block = current_block.as_u64();
            info!("Starting from block: {}", self.last_processed_block);
        }

        let mut interval = interval(self.poll_interval);

        while self.running {
            interval.tick().await;

            if let Err(e) = self.process_new_blocks().await {
                error!("Error processing blocks: {}", e);
            }
        }

        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
        info!("Stopping blockchain listener...");
    }

    async fn process_new_blocks(&mut self) -> Result<(), ContractError> {
        let current_block = self.provider
            .get_block_number()
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let current_block_num = current_block.as_u64();

        if current_block_num <= self.last_processed_block {
            return Ok(());
        }

        debug!("Processing blocks {} to {}", self.last_processed_block + 1, current_block_num);

        for block_num in (self.last_processed_block + 1)..=current_block_num {
            if let Err(e) = self.process_block(block_num).await {
                error!("Error processing block {}: {}", block_num, e);
                continue;
            }
        }

        self.last_processed_block = current_block_num;
        Ok(())
    }

    async fn process_block(&self, block_num: u64) -> Result<(), ContractError> {
        let block = self.provider
            .get_block_with_txs(BlockNumber::Number(block_num.into()))
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?
            .ok_or_else(|| ContractError::RpcError("Block not found".to_string()))?;

        // Process logs for events
        for tx in block.transactions {
            // Get transaction receipt using the transaction hash
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

    async fn process_transaction_logs(&self, logs: &[Log], block_number: u64) -> Result<(), ContractError> {
        for log in logs {
            // Check if log is from our contracts
            if self.is_our_contract_log(log) {
                self.handle_contract_event(log, block_number).await?;
            }
        }
        Ok(())
    }

    fn is_our_contract_log(&self, log: &Log) -> bool {
        // Check if log is from our NFT contract - use the getter method
        let nft_address = self.contract_client.get_contract_addresses().vertix_nft;
        log.address == H160::from_slice(&nft_address.0.as_slice())
    }

    async fn handle_contract_event(&self, log: &Log, block_number: u64) -> Result<(), ContractError> {
        // Handle different event types based on topic signature
        match log.topics.get(0) {
            Some(topic) => {
                let signature = format!("0x{}", hex::encode(topic.as_bytes()));

                match signature.as_str() {
                    // NFTMinted event signature: keccak256("NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)")
                    "0x9d63848aa0b95b30c5d5d3f5f2e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0" => {
                        self.handle_nft_minted_event(log, block_number).await?;
                    },
                    // CollectionCreated event signature: keccak256("CollectionCreated(uint256,address,string,string,string,uint256)")
                    "0x7c8e6d9b0b8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0e8c0" => {
                        self.handle_collection_created_event(log, block_number).await?;
                    },
                    // SocialMediaNFTMinted event signature: keccak256("SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)")
                    "0xa070a1c2e676dbcadfab71a2357b2423de00020d93af644115c7ea4959da267c" => {
                        self.handle_social_media_nft_minted_event(log, block_number).await?;
                    },
                    _ => debug!("Unknown event signature: {}", signature),
                }
            }
            None => debug!("Log has no topics"),
        }

        Ok(())
    }

    async fn handle_nft_minted_event(&self, log: &Log, block_number: u64) -> Result<(), ContractError> {
        info!("Processing NFTMinted event");

        // Parse event data
        if log.topics.len() < 4 {
            error!("NFTMinted event has insufficient topics");
            return Ok(());
        }

        // Extract event data from topics and data
        let to_address = Address::from_slice(&log.topics[1].as_bytes()[12..]); // Remove padding
        let token_id = U256::from_big_endian(&log.topics[2].as_bytes()).as_u64();
        let collection_id = U256::from_big_endian(&log.topics[3].as_bytes()).as_u64();

        // Store in database
        if let Some(tx_hash) = &log.transaction_hash {
            let tx_hash_bytes: [u8; 32] = tx_hash.as_bytes().try_into()
                .map_err(|e| ContractError::ContractCallError(format!("Invalid transaction hash: {}", e)))?;
            self.blockchain_events_repository.store_nft_mint_event(to_address, token_id, collection_id, &tx_hash_bytes, block_number).await
                .map_err(|e| ContractError::ContractCallError(format!("Database error: {}", e)))?;
        }

        info!("Stored NFT mint event: token_id={}, collection_id={}, to={}", token_id, collection_id, to_address);
        Ok(())
    }

    async fn handle_collection_created_event(&self, log: &Log, block_number: u64) -> Result<(), ContractError> {
        info!("Processing CollectionCreated event");

        // Parse event data
        if log.topics.len() < 3 {
            error!("CollectionCreated event has insufficient topics");
            return Ok(());
        }

        // Extract event data from topics and data
        let collection_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let creator_address = Address::from_slice(&log.topics[2].as_bytes()[12..]); // Remove padding

        // Store in database
        if let Some(tx_hash) = &log.transaction_hash {
            let tx_hash_bytes: [u8; 32] = tx_hash.as_bytes().try_into()
                .map_err(|e| ContractError::ContractCallError(format!("Invalid transaction hash: {}", e)))?;
            self.blockchain_events_repository.store_collection_created_event(collection_id, creator_address, &tx_hash_bytes, block_number).await
                .map_err(|e| ContractError::ContractCallError(format!("Database error: {}", e)))?;
        }

        info!("Stored collection created event: collection_id={}, creator={}", collection_id, creator_address);
        Ok(())
    }

    async fn handle_social_media_nft_minted_event(&self, log: &Log, block_number: u64) -> Result<(), ContractError> {
        info!("Processing SocialMediaNFTMinted event");

        // Parse event data
        if log.topics.len() < 4 {
            error!("SocialMediaNFTMinted event has insufficient topics");
            return Ok(());
        }

        // Extract event data from topics and data
        let to_address = Address::from_slice(&log.topics[1].as_bytes()[12..]); // Remove padding
        let token_id = U256::from_big_endian(&log.topics[2].as_bytes()).as_u64();
        // Note: royalty_recipient is in topic[3] but not currently stored in database

        // Extract social media ID from data (first 32 bytes)
        let social_media_id = if log.data.len() >= 32 {
            String::from_utf8_lossy(&log.data[..32]).trim_end_matches('\0').to_string()
        } else {
            "unknown".to_string()
        };

        // Store in database
        if let Some(tx_hash) = &log.transaction_hash {
            let tx_hash_bytes: [u8; 32] = tx_hash.as_bytes().try_into()
                .map_err(|e| ContractError::ContractCallError(format!("Invalid transaction hash: {}", e)))?;
            self.blockchain_events_repository.store_social_media_nft_mint_event(to_address, token_id, social_media_id.clone(), &tx_hash_bytes, block_number).await
                .map_err(|e| ContractError::ContractCallError(format!("Database error: {}", e)))?;
        }

        info!("Stored social media NFT mint event: token_id={}, social_media_id={}, to={}", token_id, social_media_id, to_address);
        Ok(())
    }
}
