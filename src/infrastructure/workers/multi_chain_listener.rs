use ethers::{
    providers::{Http, Ws, Provider, Middleware, StreamExt},
    types::{BlockNumber, Log, Address, U256, Filter},
};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio::sync::Mutex;
use tracing::{info, error, warn};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
// Removed unused imports

use crate::infrastructure::repositories::collections_repository::CollectionsRepository;
use crate::infrastructure::repositories::nft_events_repository::NftEventsRepository;
use crate::infrastructure::repositories::social_media_events_repository::SocialMediaEventsRepository;
use crate::infrastructure::repositories::nft_listing_events_repository::NftListingEventsRepository;
use crate::infrastructure::contracts::config::get_supported_chains;
use crate::infrastructure::contracts::types::ChainConfig;
use crate::domain::services::ContractError;

/// Multi-chain blockchain listener that monitors all supported chains simultaneously using WebSocket subscriptions
pub struct MultiChainListener {
    chain_listeners: HashMap<u64, ChainListener>,
    collections_repository: CollectionsRepository,
    nft_events_repository: NftEventsRepository,
    social_media_events_repository: SocialMediaEventsRepository,
    listing_events_repository: NftListingEventsRepository,
    running: bool,
}

/// Individual chain listener for a specific network
struct ChainListener {
    chain_config: ChainConfig,
    ws_provider: Option<Arc<Provider<Ws>>>, // Optional WebSocket provider
    http_provider: Arc<Provider<Http>>, // HTTP provider for historical data and fallback
    contract_addresses: HashMap<String, Address>,
    last_processed_block: u64,
    running: Arc<Mutex<bool>>,
    collections_repository: CollectionsRepository,
    nft_events_repository: NftEventsRepository,
    social_media_events_repository: SocialMediaEventsRepository,
    listing_events_repository: NftListingEventsRepository,
}

impl MultiChainListener {
    pub fn new(
        db_pool: PgPool,
    ) -> Result<Self, ContractError> {
        let collections_repository = CollectionsRepository::new(db_pool.clone());
        let nft_events_repository = NftEventsRepository::new(db_pool.clone());
        let social_media_events_repository = SocialMediaEventsRepository::new(db_pool.clone());
        let listing_events_repository = NftListingEventsRepository::new(db_pool);

        Ok(Self {
            chain_listeners: HashMap::new(),
            collections_repository,
            nft_events_repository,
            social_media_events_repository,
            listing_events_repository,
            running: false,
        })
    }

    /// Get the starting block for a chain from the database
    async fn get_starting_block_from_db(&self, chain_id: u64) -> Option<u64> {
        // We need access to the database pool, so we'll use one of the repositories
        // Since all repositories share the same pool, we can use any of them
        let result = sqlx::query(
            "SELECT starting_block_number FROM chain_starting_blocks WHERE chain_id = $1"
        )
        .bind(chain_id as i64)
        .fetch_optional(self.collections_repository.pool())
        .await;

        match result {
            Ok(Some(row)) => {
                let block_number: i64 = row.get("starting_block_number");
                info!("Found stored starting block {} for chain {}", block_number, chain_id);
                Some(block_number as u64)
            }
            Ok(None) => {
                info!("No stored starting block found for chain {}, using fallback", chain_id);
                None
            }
            Err(e) => {
                warn!("Failed to get starting block for chain {}: {}", chain_id, e);
                None
            }
        }
    }

    /// Start monitoring all supported chains using WebSocket subscriptions
    pub async fn start(&mut self) -> Result<(), ContractError> {
        if self.running {
            return Ok(());
        }

        self.running = true;
        info!("Starting multi-chain blockchain listener with WebSocket subscriptions...");

        // Get all supported chains
        let supported_chains = get_supported_chains()?;
        info!("Found {} supported chains", supported_chains.len());

        // Initialize listeners for each chain
        let mut chain_handles = Vec::new();
        for chain_config in supported_chains {
            let chain_id = chain_config.chain_id;
            match self.add_chain_listener(chain_config).await {
                Ok(handle) => {
                    chain_handles.push(handle);
                    info!("Successfully initialized WebSocket listener for chain {}", chain_id);
                }
                Err(e) => {
                    error!("Failed to add WebSocket listener for chain {}: {}", chain_id, e);
                continue;
                }
            }
        }

        if chain_handles.is_empty() {
            warn!("No chain listeners were successfully initialized");
            return Ok(());
        }

        info!("Successfully initialized {} WebSocket chain listeners", chain_handles.len());

        // Wait for all chain listeners to complete
        futures::future::join_all(chain_handles).await;

        Ok(())
    }

    /// Stop monitoring all chains
    pub fn stop(&mut self) {
        self.running = false;
        info!("Stopping multi-chain blockchain listener...");
    }

    /// Add a new chain listener with WebSocket subscription
    async fn add_chain_listener(&mut self, chain_config: ChainConfig) -> Result<tokio::task::JoinHandle<()>, ContractError> {
        let chain_id = chain_config.chain_id;

        // Create HTTP provider for historical data
        let http_provider = Arc::new(Provider::<Http>::try_from(chain_config.rpc_url.clone())
            .map_err(|e| ContractError::RpcError(format!("Failed to create HTTP provider for chain {}: {}", chain_id, e)))?);

        // Test HTTP connection first
        let current_block = http_provider.get_block_number().await
            .map_err(|e| ContractError::RpcError(format!("Failed to connect to chain {}: {}", chain_id, e)))?;

        info!("Connected to chain {} ({}): Block {} via HTTP", 
              chain_id, chain_config.name, current_block);

        // Try to create WebSocket provider
        let ws_provider = if let Some(ws_url) = &chain_config.ws_url {
            // Use explicit WebSocket URL if provided
            match Provider::<Ws>::connect(ws_url).await {
                Ok(provider) => {
                    info!("WebSocket connection established for chain {} using URL: {}", chain_id, ws_url);
                    Some(Arc::new(provider))
                }
                Err(e) => {
                    warn!("Failed to connect to WebSocket for chain {}: {}. Falling back to polling.", chain_id, e);
                    None
                }
            }
        } else {
            // Try to convert HTTP URL to WebSocket URL
            let ws_url = chain_config.rpc_url.replace("http://", "ws://").replace("https://", "wss://");
            match Provider::<Ws>::connect(&ws_url).await {
                Ok(provider) => {
                    info!("WebSocket connection established for chain {} using converted URL: {}", chain_id, ws_url);
                    Some(Arc::new(provider))
                }
                Err(e) => {
                    warn!("Failed to connect to WebSocket for chain {} using converted URL {}: {}. Falling back to polling.", chain_id, ws_url, e);
                    None
                }
            }
        };

        // Extract contract addresses
        let contract_addresses = self.extract_contract_addresses(&chain_config)?;

        // Get starting block from database, fallback to much earlier block to catch missed events
        let start_block = self.get_starting_block_from_db(chain_id).await
            .unwrap_or_else(|| {
                if current_block.as_u64() > 500 {
                    current_block.as_u64() - 500
                } else {
                    0
                }
            });

        // Create filter for our contract addresses
        let contract_addresses_vec: Vec<Address> = contract_addresses.values().cloned().collect();
        let filter = Filter::new().address(contract_addresses_vec);

        if ws_provider.is_some() {
            info!("Starting WebSocket listener for chain {} from block {} (current: {})", 
                  chain_id, start_block, current_block.as_u64());
        } else {
            info!("Starting polling listener for chain {} from block {} (current: {})", 
                  chain_id, start_block, current_block.as_u64());
        }

        // Create the listener
        let listener = ChainListener {
            chain_config: chain_config.clone(),
            ws_provider,
            http_provider,
            contract_addresses,
            last_processed_block: start_block,
            running: Arc::new(Mutex::new(true)),
            collections_repository: self.collections_repository.clone(),
            nft_events_repository: self.nft_events_repository.clone(),
            social_media_events_repository: self.social_media_events_repository.clone(),
            listing_events_repository: self.listing_events_repository.clone(),
        };

        // Start the listener task (WebSocket or polling)
        let handle = tokio::spawn(async move {
            if let Err(e) = listener.start_listening(filter).await {
                error!("Listener failed for chain {}: {}", chain_id, e);
            }
        });

        Ok(handle)
    }

    /// Extract contract addresses from chain configuration
    fn extract_contract_addresses(&self, chain_config: &ChainConfig) -> Result<HashMap<String, Address>, ContractError> {
        let mut addresses = HashMap::new();

        addresses.insert("vertix_nft".to_string(), chain_config.contract_addresses.vertix_nft);
        addresses.insert("vertix_escrow".to_string(), chain_config.contract_addresses.vertix_escrow);
        addresses.insert("vertix_governance".to_string(), chain_config.contract_addresses.vertix_governance);
        addresses.insert("marketplace_core".to_string(), chain_config.contract_addresses.marketplace_core);
        addresses.insert("marketplace_auctions".to_string(), chain_config.contract_addresses.marketplace_auctions);
        addresses.insert("marketplace_fees".to_string(), chain_config.contract_addresses.marketplace_fees);
        addresses.insert("marketplace_storage".to_string(), chain_config.contract_addresses.marketplace_storage);
        addresses.insert("marketplace_proxy".to_string(), chain_config.contract_addresses.marketplace_proxy);
        addresses.insert("cross_chain_bridge".to_string(), chain_config.contract_addresses.cross_chain_bridge);
        addresses.insert("cross_chain_registry".to_string(), chain_config.contract_addresses.cross_chain_registry);
        Ok(addresses)
    }



    /// Get all active chain IDs
    pub fn get_active_chain_ids(&self) -> Vec<u64> {
        self.chain_listeners.keys().cloned().collect()
    }
}

impl ChainListener {
    /// Start listening for events (WebSocket if available, otherwise polling)
    async fn start_listening(self, filter: Filter) -> Result<(), ContractError> {
        // First, process any historical events from the last processed block
        // This only runs once, regardless of whether we use WebSocket or polling
        if let Err(e) = self.process_historical_events().await {
            error!("Failed to process historical events for chain {}: {}",
                   self.chain_config.chain_id, e);
        }

        if self.ws_provider.is_some() {
            self.start_websocket_subscription(filter).await
        } else {
            self.start_polling_listener(filter).await
        }
    }

    /// Start WebSocket subscription for real-time event listening with reconnection logic
    async fn start_websocket_subscription(self, filter: Filter) -> Result<(), ContractError> {
        info!("Starting WebSocket subscription for chain {} ({})",
              self.chain_config.chain_id, self.chain_config.name);

        let mut reconnect_attempts = 0;
        const MAX_RECONNECT_ATTEMPTS: u32 = 10;
        const RECONNECT_DELAY: Duration = Duration::from_secs(5);

        loop {
            let running = *self.running.lock().await;
            if !running {
                info!("Stopping WebSocket subscription for chain {}", self.chain_config.chain_id);
                break;
            }

            // Create the subscription stream
            match self.ws_provider.as_ref().unwrap().subscribe_logs(&filter).await {
                Ok(mut subscription) => {
                    info!("WebSocket subscription established for chain {} ({})", 
                          self.chain_config.chain_id, self.chain_config.name);

                    reconnect_attempts = 0; // Reset on successful connection

                    // Process events from the subscription stream
                    while let Some(log) = subscription.next().await {
                        let running = *self.running.lock().await;
                        if !running {
                            info!("Stopping WebSocket subscription for chain {}", self.chain_config.chain_id);
                            return Ok(());
                        }

                        // Process the event
                        let block_number = log.block_number.map(|bn| bn.as_u64()).unwrap_or(0);
                        if let Err(e) = self.handle_contract_event(&log, block_number).await {
                            error!("Error processing WebSocket event on chain {}: {}", 
                                   self.chain_config.chain_id, e);
                        }
                    }

                    // If we reach here, the subscription ended unexpectedly
                    warn!("WebSocket subscription ended unexpectedly for chain {}", self.chain_config.chain_id);
                }
                Err(e) => {
                    error!("Failed to establish WebSocket subscription for chain {}: {}", 
                           self.chain_config.chain_id, e);
                }
            }

            // Attempt reconnection
            reconnect_attempts += 1;
            if reconnect_attempts > MAX_RECONNECT_ATTEMPTS {
                error!("Max reconnection attempts reached for chain {}. Stopping.", self.chain_config.chain_id);
                break;
            }

            warn!("Attempting to reconnect WebSocket for chain {} (attempt {}/{})", 
                  self.chain_config.chain_id, reconnect_attempts, MAX_RECONNECT_ATTEMPTS);

            sleep(RECONNECT_DELAY).await;
        }

        info!("WebSocket subscription ended for chain {}", self.chain_config.chain_id);
        Ok(())
    }

    /// Start polling listener as fallback when WebSocket is not available
    async fn start_polling_listener(self, _filter: Filter) -> Result<(), ContractError> {
        info!("Starting polling listener for chain {} ({})",
              self.chain_config.chain_id, self.chain_config.name);

        // Note: Historical events are processed in start_listening() before calling this method
        // This method only handles real-time polling

        let mut interval = tokio::time::interval(Duration::from_secs(15)); // Poll every 15 seconds

        loop {
            let running = *self.running.lock().await;
            if !running {
                info!("Stopping polling listener for chain {}", self.chain_config.chain_id);
                break;
            }

            interval.tick().await;

            // Process new blocks
            if let Err(e) = self.process_new_blocks().await {
                error!("Error processing blocks for chain {}: {}", 
                       self.chain_config.chain_id, e);
            }
        }

        info!("Polling listener ended for chain {}", self.chain_config.chain_id);
        Ok(())
    }

    /// Process new blocks for this chain (used by polling listener)
    async fn process_new_blocks(&self) -> Result<(), ContractError> {
        let current_block = self.http_provider
            .get_block_number()
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let current_block_num = current_block.as_u64();

        if current_block_num <= self.last_processed_block {
            return Ok(());
        }

        // Process historical blocks in batches for efficiency
        if self.last_processed_block < current_block_num - 1000 {
            // For large gaps, use batch processing
            self.process_historical_blocks_batch(self.last_processed_block + 1, current_block_num).await?;
        } else {
            // For small gaps, process individually
            for block_num in (self.last_processed_block + 1)..=current_block_num {
                if let Err(e) = self.process_block(block_num).await {
                    error!("Error processing block {} on chain {}: {}", 
                           block_num, self.chain_config.chain_id, e);
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Process historical events from the last processed block to current
    async fn process_historical_events(&self) -> Result<(), ContractError> {
        let current_block = self.http_provider
            .get_block_number()
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?;
        let current_block_num = current_block.as_u64();

        if current_block_num <= self.last_processed_block {
            return Ok(());
        }

        info!("Processing historical events for chain {} from block {} to {}", 
              self.chain_config.chain_id, self.last_processed_block + 1, current_block_num);

        // Process historical blocks in batches for efficiency
        if self.last_processed_block < current_block_num - 1000 {
            // For large gaps, use batch processing
            self.process_historical_blocks_batch(self.last_processed_block + 1, current_block_num).await?;
        } else {
            // For small gaps, process individually
            for block_num in (self.last_processed_block + 1)..=current_block_num {
                if let Err(e) = self.process_block(block_num).await {
                    error!("Error processing block {} on chain {}: {}", 
                           block_num, self.chain_config.chain_id, e);
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Process historical blocks in batches using eth_getLogs
    async fn process_historical_blocks_batch(&self, from_block: u64, to_block: u64) -> Result<(), ContractError> {
        info!("Processing historical blocks {} to {} in batches on chain {} ({})", 
              from_block, to_block, self.chain_config.chain_id, self.chain_config.name);

        // Get all contract addresses
        let contract_addresses: Vec<Address> = self.contract_addresses.values().cloned().collect();

        // Process in chunks of 2000 blocks (RPC limit)
        let chunk_size = 2000;
        let mut current_from = from_block;

        while current_from <= to_block {
            let current_to = std::cmp::min(current_from + chunk_size - 1, to_block);

            info!("Processing batch: blocks {} to {}", current_from, current_to);

            // Get all logs for this range
            let filter = Filter::new()
                .from_block(current_from)
                .to_block(current_to)
                .address(contract_addresses.clone());

            match self.http_provider.get_logs(&filter).await {
                Ok(logs) => {
                    info!("Found {} events in blocks {} to {}", logs.len(), current_from, current_to);

                    // Process all logs
                    for log in logs {
                        if let Err(e) = self.handle_contract_event(&log, current_to).await {
                            error!("Error processing event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error getting logs for blocks {} to {}: {}", current_from, current_to, e);
                    // Fallback to individual block processing for this chunk
                    for block_num in current_from..=current_to {
                        if let Err(e) = self.process_block(block_num).await {
                            error!("Error processing block {}: {}", block_num, e);
                        }
                    }
                }
            }

            current_from = current_to + 1;
        }

        Ok(())
    }

    /// Process a specific block
    async fn process_block(&self, block_num: u64) -> Result<(), ContractError> {
        let block = self.http_provider
            .get_block_with_txs(BlockNumber::Number(block_num.into()))
            .await
            .map_err(|e| ContractError::RpcError(e.to_string()))?
            .ok_or_else(|| ContractError::RpcError("Block not found".to_string()))?;

        info!("Processing block {} on chain {} ({}) - {} transactions", 
              block_num, self.chain_config.chain_id, self.chain_config.name, block.transactions.len());

        // Process logs for events
        for tx in block.transactions {
            if let Some(receipt) = self.http_provider
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
            "0x2ed0e63d22dc25cb0ab433d70fad78bd57e33c6c7e2b4078c212c2568fd20059" => {
                self.handle_nft_minted_event(log, block_number, tx_hash).await?;
            },
            // SocialMediaNFTMinted event: SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)
            "0xa070a1c2e676dbcadfab71a2357b2423de00020d93af644115c7ea4959da267c" => {
                self.handle_social_media_nft_minted_event(log, block_number, tx_hash).await?;
            },
            // NFTListed event: NFTListed(uint256 indexed listingId, address indexed seller, address nftContract, uint256 tokenId, uint256 price)
            "0xb0fe4922ac99799c17a4130d5c045ba2ecdf6e15b75b9ea84aaf0dc28724a42b" => {
                self.handle_nft_listed_event(log, block_number, tx_hash).await?;
            },
            // NonNFTListed event: NonNFTListed(uint256 indexed listingId, address indexed seller, uint8 assetType, string assetId, uint256 price)
            "0xcfe1329382dc514395953d9b57e64247e2fa8438e4d99594adfe77c1a667b907" => {
                self.handle_non_nft_listed_event(log, block_number, tx_hash).await?;
            },
            // NFTBought event: NFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 royaltyAmount, address royaltyRecipient, uint256 platformFee, address feeRecipient)
            "0x8c80e3dc6b4935ee2865ab63c3f13d8e7a3e47a840688b1902d60cb1929bbf6c" => {
                self.handle_nft_bought_event(log, block_number, tx_hash).await?;
            },
            // NonNFTBought event: NonNFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 sellerAmount, uint256 platformFee, address feeRecipient)
            "0xbc6ed63ae8bd7ec2800ad29c39e4f954b1cb0b894fd5f29f7a5a10c3c1c4982d" => {
                self.handle_non_nft_bought_event(log, block_number, tx_hash).await?;
            },
            // NFTListingCancelled event: NFTListingCancelled(uint256 indexed listingId, address indexed seller, bool isNft)
            "0x3aae0b757bcff9d7d299cb21614c760f215fec5b39f9c5c1084b4937d8427be8" => {
                self.handle_nft_listing_cancelled_event(log, block_number, tx_hash).await?;
            },
            // NonNFTListingCancelled event: NonNFTListingCancelled(uint256 indexed listingId, address indexed seller, bool isNft)
            "0x38e2b372ec37d385b875391fced5f399102e7ad3e39d5712dca8356d654f7603" => {
                self.handle_non_nft_listing_cancelled_event(log, block_number, tx_hash).await?;
            },
            // ListedForAuction event: ListedForAuction(uint256 indexed listingId, bool isNft, bool isListedForAuction)
            "0x7ab59389dd6cb93429575d8fff8658a00c15badc087c66c8367970603eedbb61" => {
                self.handle_listed_for_auction_event(log, block_number, tx_hash).await?;
            },
            // NFTAuctionStarted event: NFTAuctionStarted(uint256 indexed auctionId, address indexed seller, uint256 startTime, uint24 duration, uint256 price, address nftContract, uint256 tokenId)
            "0x89da8907b7791fb9b04c76ef526cffa267db5121cd1bb9175b2d267553388975" => {
                self.handle_nft_auction_started_event(log, block_number, tx_hash).await?;
            },
            // NonNFTAuctionStarted event: NonNFTAuctionStarted(uint256 indexed auctionId, address indexed seller, uint256 startTime, uint24 duration, uint256 price, string assetId, uint8 assetType)
            "0x98365f988d95d6ca2db9d1b7bfc5c24ed903f6966c1a9498655bc40c2ac90642" => {
                self.handle_non_nft_auction_started_event(log, block_number, tx_hash).await?;
            },
            // BidPlaced event: BidPlaced(uint256 indexed auctionId, uint256 indexed bidId, address indexed bidder, uint256 bidAmount, uint256 tokenId)
            "0x34a9aee5f476df7f218e672a92a2cb667ee9908bc59d1b2fa2b2a882f715775d" => {
                self.handle_bid_placed_event(log, block_number, tx_hash).await?;
            },
            // AuctionEnded event: AuctionEnded(uint256 indexed auctionId, address indexed seller, address indexed bidder, uint256 highestBid, uint256 tokenId)
            "0x596165d0521c3cb4157fad2621686f086daed4663acb3d03441a92b9277f5683" => {
                self.handle_auction_ended_event(log, block_number, tx_hash).await?;
            },
            // Initialized event: Initialized(uint8)
            "0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498" => {
                self.handle_initialized_event(log, block_number, tx_hash).await?;
            },
            // OwnershipTransferred event: OwnershipTransferred(address,address)
            "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0" => {
                self.handle_ownership_transferred_event(log, block_number, tx_hash).await?;
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
        // The first 3 offsets (0, 32, 64) are pointers to string data locations
        let name_offset = U256::from_big_endian(&data[0..32]).as_usize();
        let symbol_offset = U256::from_big_endian(&data[32..64]).as_usize();
        let image_offset = U256::from_big_endian(&data[64..96]).as_usize();
        let max_supply = U256::from_big_endian(&data[96..128]).as_u64();

        let name = self.extract_string_from_data(data, name_offset)?;
        let symbol = self.extract_string_from_data(data, symbol_offset)?;
        let image = self.extract_string_from_data(data, image_offset)?;

        // Store collection in database
        let creator_address_bytes: [u8; 20] = log.topics[2].as_bytes()[12..].try_into()
            .map_err(|_| ContractError::ContractCallError("Invalid creator address".to_string()))?;

        if let Err(e) = self.collections_repository.store_collection(
            collection_id,
            self.chain_config.chain_id,
            &name,
            &symbol,
            &image,
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

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 96 {
            return Ok(());
        }

        // Extract uri string offset and then the string
        let uri_offset = U256::from_big_endian(&data[0..32]).as_usize();
        let token_uri = self.extract_string_from_data(data, uri_offset)?;

        // metadataHash is bytes32, not string - extract as hex string
        let metadata_hash = if data.len() >= 64 {
            format!("0x{}", hex::encode(&data[32..64]))
        } else {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        };

        // Extract royaltyRecipient and royaltyBps
        let royalty_recipient = format!("0x{}", hex::encode(&data[76..96])); // 20 bytes for address (offset 76-96)
        let royalty_bps = U256::from_big_endian(&data[96..128]).as_u64(); // uint96 (offset 96-128)

        // Store NFT mint event in database
        if let Err(e) = self.nft_events_repository.store_nft_mint_event(
            self.chain_config.chain_id,
            &to_address,
            token_id,
            Some(collection_id),
            tx_hash,
            block_number,
            &token_uri,
            &metadata_hash,
            &royalty_recipient,
            royalty_bps,
        ).await {
            error!("Failed to store NFT mint event on chain {}: {}",
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTMinted event: token_id={}, collection_id={}, to={}, uri={}, royalty_recipient={}, royalty_bps={}, chain_id={}", 
              token_id, collection_id, to_address, token_uri, royalty_recipient, royalty_bps, self.chain_config.chain_id);

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
        if data.len() < 96 {
            return Ok(());
        }

        // Extract string offsets and then the strings
        let social_media_id_offset = U256::from_big_endian(&data[0..32]).as_usize();
        let uri_offset = U256::from_big_endian(&data[32..64]).as_usize();

        let social_media_id = self.extract_string_from_data(data, social_media_id_offset)?;
        let _uri = self.extract_string_from_data(data, uri_offset)?;

        // metadataHash is bytes32, not string - extract as hex string
        let _metadata_hash = if data.len() >= 96 {
            format!("0x{}", hex::encode(&data[64..96]))
        } else {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        };

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

    /// Handle NFTListed event
    async fn handle_nft_listed_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTListed(uint256 indexed listingId, address indexed seller, address nftContract, uint256 tokenId, uint256 price)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 96 {
            return Ok(());
        }

        let nft_contract = format!("0x{}", hex::encode(&data[12..32]));
        let token_id = U256::from_big_endian(&data[32..64]).as_u64();
        let price = U256::from_big_endian(&data[64..96]).as_u128();

        // Store NFT listing event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            listing_id,
            &nft_contract,
            token_id,
            &seller_address,
            price,
            false, // is_auction
            None, // auction_end_time
            None, // reserve_price_wei
            tx_hash,
            block_number,
            "LISTED",
        ).await {
            error!("Failed to store NFT listing event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTListed event: listing_id={}, nft_contract={}, token_id={}, chain_id={}", 
              listing_id, nft_contract, token_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTBought event
    async fn handle_nft_bought_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 royaltyAmount, address royaltyRecipient, uint256 platformFee, address feeRecipient)
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

        let price = U256::from_big_endian(&data[0..32]).as_u128();

        // Store NFT sold event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            listing_id,
            "", // nft_contract - we'll need to get this from the original listing
            0, // token_id - we'll need to get this from the original listing
            &buyer_address, // seller_address - actually the buyer in this case
            price,
            false, // is_auction
            None, // auction_end_time
            None, // reserve_price_wei
            tx_hash,
            block_number,
            "SOLD",
        ).await {
            error!("Failed to store NFT bought event on chain {}: {}",
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTBought event: listing_id={}, buyer={}, price={}, chain_id={}",
              listing_id, buyer_address, price, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTListingCancelled event
    async fn handle_nft_listing_cancelled_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTListingCancelled(uint256 indexed listingId, address indexed seller, bool isNft)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 32 {
            return Ok(());
        }

        let is_nft = U256::from_big_endian(&data[0..32]).as_u64() != 0;

        // Store NFT listing cancelled event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            listing_id,
            "", // nft_contract - we'll need to get this from the original listing
            0, // token_id - we'll need to get this from the original listing
            &seller_address,
            0, // price - not relevant for cancellation
            false, // is_auction
            None, // auction_end_time
            None, // reserve_price_wei
            tx_hash,
            block_number,
            "UNLISTED",
        ).await {
            error!("Failed to store NFT listing cancelled event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTListingCancelled event: listing_id={}, seller={}, is_nft={}, chain_id={}", 
              listing_id, seller_address, is_nft, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle ListedForAuction event
    async fn handle_listed_for_auction_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: ListedForAuction(uint256 indexed listingId, bool isNft, bool isListedForAuction)
        if log.topics.len() < 2 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 64 {
            return Ok(());
        }

        let is_nft = U256::from_big_endian(&data[0..32]).as_u64() != 0;
        let is_listed_for_auction = U256::from_big_endian(&data[32..64]).as_u64() != 0;

        // Store auction listing event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            listing_id,
            "", // nft_contract - we'll need to get this from the original listing
            0, // token_id - we'll need to get this from the original listing
            "", // seller_address - we'll need to get this from the original listing
            0, // price - not relevant for auction listing
            is_listed_for_auction, // is_auction
            None, // auction_end_time - will be set when auction starts
            None, // reserve_price_wei - will be set when auction starts
            tx_hash,
            block_number,
            if is_listed_for_auction { "AUCTION_LISTED" } else { "AUCTION_UNLISTED" },
        ).await {
            error!("Failed to store ListedForAuction event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored ListedForAuction event: listing_id={}, is_nft={}, is_listed_for_auction={}, chain_id={}", 
              listing_id, is_nft, is_listed_for_auction, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NFTAuctionStarted event
    async fn handle_nft_auction_started_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NFTAuctionStarted(uint256 indexed auctionId, address indexed seller, uint256 startTime, uint24 duration, uint256 price)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let auction_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 128 {
            return Ok(());
        }

        let start_time = U256::from_big_endian(&data[0..32]).as_u64();
        let duration = U256::from_big_endian(&data[32..64]).as_u64();
        let price = U256::from_big_endian(&data[64..96]).as_u128();

        // Calculate auction end time
        let auction_end_time = chrono::DateTime::from_timestamp(start_time as i64 + duration as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now());

        // Store auction started event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            auction_id,
            "", // nft_contract - we'll need to get this from the original listing
            0, // token_id - we'll need to get this from the original listing
            &seller_address,
            price,
            true, // is_auction
            Some(auction_end_time), // auction_end_time
            Some(price), // reserve_price_wei - using price as reserve for now
            tx_hash,
            block_number,
            "AUCTION_STARTED",
        ).await {
            error!("Failed to store NFTAuctionStarted event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored NFTAuctionStarted event: auction_id={}, seller={}, start_time={}, duration={}, price={}, chain_id={}", 
              auction_id, seller_address, start_time, duration, price, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle AuctionEnded event
    async fn handle_auction_ended_event(&self, log: &Log, block_number: u64, tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: AuctionEnded(uint256 indexed auctionId, address indexed seller, address indexed bidder, uint256 highestBid, uint256 tokenId)
        if log.topics.len() < 4 {
            return Ok(());
        }

        let auction_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));
        let bidder_address = format!("0x{}", hex::encode(&log.topics[3].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 64 {
            return Ok(());
        }

        let highest_bid = U256::from_big_endian(&data[0..32]).as_u128();
        let token_id = U256::from_big_endian(&data[32..64]).as_u64();

        // Store auction ended event in database
        if let Err(e) = self.listing_events_repository.store_nft_listing_event(
            self.chain_config.chain_id,
            auction_id,
            "", // nft_contract - we'll need to get this from the original listing
            token_id,
            &bidder_address, // seller_address - actually the winning bidder
            highest_bid,
            true, // is_auction
            Some(chrono::Utc::now()), // auction_end_time - now
            None, // reserve_price_wei - not relevant for ended auction
            tx_hash,
            block_number,
            "AUCTION_ENDED",
        ).await {
            error!("Failed to store AuctionEnded event on chain {}: {}", 
                   self.chain_config.chain_id, e);
        }

        info!("Stored AuctionEnded event: auction_id={}, seller={}, bidder={}, highest_bid={}, token_id={}, chain_id={}", 
              auction_id, seller_address, bidder_address, highest_bid, token_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NonNFTListed event
    async fn handle_non_nft_listed_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NonNFTListed(uint256 indexed listingId, address indexed seller, uint8 assetType, string assetId, uint256 price)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 96 {
            return Ok(());
        }

        // Extract assetType (uint8 in the last byte of the first 32-byte word)
        let asset_type = data[31] as u8;

        // Extract assetId string offset and then the string
        let asset_id_offset = U256::from_big_endian(&data[32..64]).as_usize();
        let asset_id = self.extract_string_from_data(data, asset_id_offset)?;

        // Extract price
        let price = U256::from_big_endian(&data[64..96]).as_u128();

        info!("Stored NonNFTListed event: listing_id={}, seller={}, asset_type={}, asset_id='{}', price={}, chain_id={}", 
              listing_id, seller_address, asset_type, asset_id, price, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NonNFTBought event
    async fn handle_non_nft_bought_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NonNFTBought(uint256 indexed listingId, address indexed buyer, uint256 price, uint256 sellerAmount, uint256 platformFee, address feeRecipient)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let buyer_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 128 {
            return Ok(());
        }

        let price = U256::from_big_endian(&data[0..32]).as_u128();
        let seller_amount = U256::from_big_endian(&data[32..64]).as_u128();
        let platform_fee = U256::from_big_endian(&data[64..96]).as_u128();
        let fee_recipient = format!("0x{}", hex::encode(&data[96..128]));

        info!("Stored NonNFTBought event: listing_id={}, buyer={}, price={}, seller_amount={}, platform_fee={}, fee_recipient={}, chain_id={}", 
              listing_id, buyer_address, price, seller_amount, platform_fee, fee_recipient, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NonNFTListingCancelled event
    async fn handle_non_nft_listing_cancelled_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NonNFTListingCancelled(uint256 indexed listingId, address indexed seller, bool isNft)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let listing_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 32 {
            return Ok(());
        }

        let is_nft = U256::from_big_endian(&data[0..32]).as_u64() != 0;

        info!("Stored NonNFTListingCancelled event: listing_id={}, seller={}, is_nft={}, chain_id={}", 
              listing_id, seller_address, is_nft, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle NonNFTAuctionStarted event
    async fn handle_non_nft_auction_started_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: NonNFTAuctionStarted(uint256 indexed auctionId, address indexed seller, uint256 startTime, uint24 duration, uint256 price, string assetId, uint8 assetType)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let auction_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let seller_address = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 160 {
            return Ok(());
        }

        let start_time = U256::from_big_endian(&data[0..32]).as_u64();
        let duration = U256::from_big_endian(&data[32..64]).as_u64();
        let price = U256::from_big_endian(&data[64..96]).as_u128();

        // Extract assetId string offset and then the string
        let asset_id_offset = U256::from_big_endian(&data[96..128]).as_usize();
        let asset_id = self.extract_string_from_data(data, asset_id_offset)?;

        // Extract assetType (uint8 in the last byte of the 32-byte word at offset 128-160)
        let asset_type = data[159] as u8;

        info!("Stored NonNFTAuctionStarted event: auction_id={}, seller={}, start_time={}, duration={}, price={}, asset_id='{}', asset_type={}, chain_id={}", 
              auction_id, seller_address, start_time, duration, price, asset_id, asset_type, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle BidPlaced event
    async fn handle_bid_placed_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: BidPlaced(uint256 indexed auctionId, uint256 indexed bidId, address indexed bidder, uint256 bidAmount, uint256 tokenId)
        if log.topics.len() < 4 {
            return Ok(());
        }

        let auction_id = U256::from_big_endian(&log.topics[1].as_bytes()).as_u64();
        let bid_id = U256::from_big_endian(&log.topics[2].as_bytes()).as_u64();
        let bidder_address = format!("0x{}", hex::encode(&log.topics[3].as_bytes()[12..]));

        // Parse non-indexed parameters from data
        let data = &log.data;
        if data.len() < 64 {
            return Ok(());
        }

        let bid_amount = U256::from_big_endian(&data[0..32]).as_u128();
        let token_id = U256::from_big_endian(&data[32..64]).as_u64();

        info!("Stored BidPlaced event: auction_id={}, bid_id={}, bidder={}, bid_amount={}, token_id={}, chain_id={}", 
              auction_id, bid_id, bidder_address, bid_amount, token_id, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle Initialized event
    async fn handle_initialized_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        info!("DEBUG: Initialized event handler called!");
        // Parse event data: Initialized(uint8)
        let data = &log.data;
        if data.len() < 32 {
            return Ok(());
        }

        let version = data[31]; // uint8 is in the last byte of the 32-byte word
        info!("Stored Initialized event: version={}, chain_id={}", version, self.chain_config.chain_id);

        Ok(())
    }

    /// Handle OwnershipTransferred event
    async fn handle_ownership_transferred_event(&self, log: &Log, _block_number: u64, _tx_hash: &[u8; 32]) -> Result<(), ContractError> {
        // Parse event data: OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
        if log.topics.len() < 3 {
            return Ok(());
        }

        let previous_owner = format!("0x{}", hex::encode(&log.topics[1].as_bytes()[12..]));
        let new_owner = format!("0x{}", hex::encode(&log.topics[2].as_bytes()[12..]));

        info!("Stored OwnershipTransferred event: previous_owner={}, new_owner={}, chain_id={}", 
              previous_owner, new_owner, self.chain_config.chain_id);

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
