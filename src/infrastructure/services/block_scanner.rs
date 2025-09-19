use ethers::{
    providers::{Http, Provider, Middleware},
    types::{BlockNumber, Address, U64},
};
use std::sync::Arc;
use sqlx::{PgPool, Row};
use tracing::{info, warn};
use serde_json::json;

use crate::infrastructure::contracts::config::get_supported_chains;
use crate::infrastructure::contracts::types::ChainConfig;
use crate::domain::services::ContractError;

/// Service to scan blockchain and find the first deployment block for contracts
pub struct BlockScanner {
    pool: PgPool,
}

impl BlockScanner {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Scan all supported chains to find starting blocks
    pub async fn scan_all_chains(&self) -> Result<(), ContractError> {
        let supported_chains = get_supported_chains()?;
        
        for chain_config in supported_chains {
            info!("Scanning chain {} ({}) for starting block", chain_config.chain_id, chain_config.name);
            
            match self.scan_chain(&chain_config).await {
                Ok(starting_block) => {
                    info!("Found starting block {} for chain {}", starting_block, chain_config.chain_id);
                    self.store_starting_block(&chain_config, starting_block).await?;
                }
                Err(e) => {
                    warn!("Failed to scan chain {}: {}", chain_config.chain_id, e);
                }
            }
        }
        
        Ok(())
    }

    /// Scan a specific chain to find the first deployment block
    async fn scan_chain(&self, chain_config: &ChainConfig) -> Result<u64, ContractError> {
        let provider = Arc::new(Provider::<Http>::try_from(&chain_config.rpc_url)
            .map_err(|e| ContractError::RpcError(format!("Failed to create provider: {}", e)))?);

        // Get current block number
        let current_block = provider.get_block_number().await
            .map_err(|e| ContractError::RpcError(format!("Failed to get current block: {}", e)))?;

        info!("Current block on chain {}: {}", chain_config.chain_id, current_block);

        // Start scanning from a reasonable point (e.g., 1000 blocks ago or block 0)
        let start_block = if current_block > U64::from(1000) {
            current_block - U64::from(1000)
        } else {
            U64::from(0)
        };

        // Scan backwards from current block to find first contract deployment
        let mut earliest_block = current_block;
        
        let start_block_u64 = start_block.as_u64();
        let current_block_u64 = current_block.as_u64();
        
        for block_num in (start_block_u64..=current_block_u64).rev() {
            if let Ok(block) = provider.get_block_with_txs(BlockNumber::Number(block_num.into())).await {
                if let Some(block) = block {
                    // Check if any transaction in this block deployed our contracts
                    for tx in block.transactions {
                        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx.hash).await {
                            if let Some(contract_address) = receipt.contract_address {
                                // Check if this contract address matches any of our known contracts
                                if self.is_our_contract(&contract_address, chain_config) {
                                    info!("Found contract deployment at block {}: {}", block_num, contract_address);
                                    earliest_block = U64::from(block_num);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(earliest_block.as_u64())
    }

    /// Check if an address matches any of our known contract addresses
    fn is_our_contract(&self, address: &Address, chain_config: &ChainConfig) -> bool {
        let addresses = &chain_config.contract_addresses;

        // Check against all known contract addresses
        address == &addresses.vertix_nft ||
        address == &addresses.marketplace_core ||
        address == &addresses.marketplace_auctions ||
        address == &addresses.marketplace_fees ||
        address == &addresses.marketplace_storage ||
        address == &addresses.marketplace_proxy ||
        address == &addresses.vertix_escrow ||
        address == &addresses.vertix_governance ||
        address == &addresses.cross_chain_bridge ||
        address == &addresses.cross_chain_registry
    }

    /// Store the starting block for a chain in the database
    async fn store_starting_block(&self, chain_config: &ChainConfig, starting_block: u64) -> Result<(), ContractError> {
        let contract_addresses = json!({
            "vertix_nft": format!("{:?}", chain_config.contract_addresses.vertix_nft),
            "marketplace_core": format!("{:?}", chain_config.contract_addresses.marketplace_core),
            "marketplace_auctions": format!("{:?}", chain_config.contract_addresses.marketplace_auctions),
            "marketplace_fees": format!("{:?}", chain_config.contract_addresses.marketplace_fees),
            "marketplace_storage": format!("{:?}", chain_config.contract_addresses.marketplace_storage),
            "marketplace_proxy": format!("{:?}", chain_config.contract_addresses.marketplace_proxy),
            "vertix_escrow": format!("{:?}", chain_config.contract_addresses.vertix_escrow),
            "vertix_governance": format!("{:?}", chain_config.contract_addresses.vertix_governance),
            "cross_chain_bridge": format!("{:?}", chain_config.contract_addresses.cross_chain_bridge),
            "cross_chain_registry": format!("{:?}", chain_config.contract_addresses.cross_chain_registry),
        });

        sqlx::query(
            r#"
            INSERT INTO chain_starting_blocks (chain_id, chain_name, starting_block_number, contract_addresses)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (chain_id) DO UPDATE SET
                starting_block_number = EXCLUDED.starting_block_number,
                contract_addresses = EXCLUDED.contract_addresses,
                updated_at = NOW()
            "#
        )
        .bind(chain_config.chain_id as i64)
        .bind(&chain_config.name)
        .bind(starting_block as i64)
        .bind(contract_addresses)
        .execute(&self.pool)
        .await
        .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        info!("Stored starting block {} for chain {}", starting_block, chain_config.chain_id);
        Ok(())
    }

    /// Get the starting block for a specific chain
    pub async fn get_starting_block(&self, chain_id: u64) -> Result<Option<u64>, ContractError> {
        let row = sqlx::query(
            "SELECT starting_block_number FROM chain_starting_blocks WHERE chain_id = $1"
        )
        .bind(chain_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        Ok(row.map(|r| r.get::<i64, _>("starting_block_number") as u64))
    }

    /// Get all stored starting blocks
    pub async fn get_all_starting_blocks(&self) -> Result<Vec<(u64, u64, String)>, ContractError> {
        let rows = sqlx::query(
            "SELECT chain_id, starting_block_number, chain_name FROM chain_starting_blocks ORDER BY chain_id"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ContractError::DatabaseError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| {
            let chain_id: i64 = r.get("chain_id");
            let starting_block: i64 = r.get("starting_block_number");
            let chain_name: String = r.get("chain_name");
            (chain_id as u64, starting_block as u64, chain_name)
        }).collect())
    }
}
