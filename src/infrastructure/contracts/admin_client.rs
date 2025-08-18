use ethers::{
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    contract::{Contract},
    types::{Address},
};
use std::sync::Arc;

use crate::domain::models::{
    AddSupportedNftContractRequest, AddSupportedNftContractResponse,
    RemoveSupportedNftContractRequest, RemoveSupportedNftContractResponse,
    SetPlatformFeeRequest, SetPlatformFeeResponse,
    SetFeeRecipientRequest, SetFeeRecipientResponse,
    ResolveDisputeRequest, ResolveDisputeResponse,
    SetEscrowDurationRequest, SetEscrowDurationResponse,
    PauseContractRequest, PauseContractResponse,
    UnpauseContractRequest, UnpauseContractResponse,
};
use crate::domain::services::ContractError;
use crate::infrastructure::contracts::types::*;
use crate::infrastructure::contracts::abis;

// Admin contract client for owner-only operations
#[derive(Clone)]
pub struct AdminContractClient {
    #[allow(dead_code)]
    provider: Arc<Provider<Http>>,
    wallet: LocalWallet,
    chain_config: ChainConfig,
    vertix_governance: Contract<Provider<Http>>,
    vertix_escrow: Contract<Provider<Http>>,
    marketplace_storage: Contract<Provider<Http>>,
    cross_chain_bridge: Contract<Provider<Http>>,
    #[allow(dead_code)]
    cross_chain_registry: Contract<Provider<Http>>,
}

impl AdminContractClient {
    pub async fn new(
        rpc_url: String,
        private_key: String,
        chain_config: ChainConfig,
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
        let governance_abi = abis::load_vertix_governance_abi()?;
        let escrow_abi = abis::load_vertix_escrow_abi()?;
        let marketplace_storage_abi = abis::load_marketplace_storage_abi()?;
        let cross_chain_bridge_abi = abis::load_cross_chain_bridge_abi()?;
        let cross_chain_registry_abi = abis::load_cross_chain_registry_abi()?;

        // Create contract instances
        let vertix_governance = Contract::new(chain_config.contract_addresses.vertix_governance, governance_abi, provider.clone());
        let vertix_escrow = Contract::new(chain_config.contract_addresses.vertix_escrow, escrow_abi, provider.clone());
        let marketplace_storage = Contract::new(chain_config.contract_addresses.marketplace_storage, marketplace_storage_abi, provider.clone());
        let cross_chain_bridge = Contract::new(chain_config.contract_addresses.cross_chain_bridge, cross_chain_bridge_abi, provider.clone());
        let cross_chain_registry = Contract::new(chain_config.contract_addresses.cross_chain_registry, cross_chain_registry_abi, provider.clone());

        Ok(Self {
            provider,
            wallet,
            chain_config,
            vertix_governance,
            vertix_escrow,
            marketplace_storage,
            cross_chain_bridge,
            cross_chain_registry,
        })
    }

    // ============ GOVERNANCE ADMIN FUNCTIONS ============

    /// Add an NFT contract as supported in governance
    pub async fn add_supported_nft_contract(&self, request: AddSupportedNftContractRequest) -> Result<AddSupportedNftContractResponse, ContractError> {
        println!("   Adding NFT contract {} as supported...", request.nft_contract);

        let nft_contract = request.nft_contract.parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Call the addSupportedNftContract function
        let call = self.vertix_governance
            .method::<_, ()>("addSupportedNftContract", nft_contract)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Add supported NFT contract transaction reverted".to_string()));
            }
        }

        println!("   NFT contract added as supported successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(AddSupportedNftContractResponse {
            nft_contract: request.nft_contract,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Remove an NFT contract from supported list
    pub async fn remove_supported_nft_contract(&self, request: RemoveSupportedNftContractRequest) -> Result<RemoveSupportedNftContractResponse, ContractError> {
        println!("   Removing NFT contract {} from supported list...", request.nft_contract);

        let nft_contract = request.nft_contract.parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Call the removeSupportedNftContract function
        let call = self.vertix_governance
            .method::<_, ()>("removeSupportedNftContract", nft_contract)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Remove supported NFT contract transaction reverted".to_string()));
            }
        }

        println!("   NFT contract removed from supported list successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(RemoveSupportedNftContractResponse {
            nft_contract: request.nft_contract,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Set platform fee
    pub async fn set_platform_fee(&self, request: SetPlatformFeeRequest) -> Result<SetPlatformFeeResponse, ContractError> {
        println!("   Setting platform fee to {} basis points...", request.new_fee);

        // Call the setPlatformFee function
        let call = self.vertix_governance
            .method::<_, ()>("setPlatformFee", request.new_fee)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Set platform fee transaction reverted".to_string()));
            }
        }

        println!("   Platform fee set successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(SetPlatformFeeResponse {
            new_fee: request.new_fee,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Set fee recipient
    pub async fn set_fee_recipient(&self, request: SetFeeRecipientRequest) -> Result<SetFeeRecipientResponse, ContractError> {
        println!("   Setting fee recipient to {}...", request.new_recipient);

        let recipient = request.new_recipient.parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Call the setFeeRecipient function
        let call = self.vertix_governance
            .method::<_, ()>("setFeeRecipient", recipient)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Set fee recipient transaction reverted".to_string()));
            }
        }

        println!("   Fee recipient set successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(SetFeeRecipientResponse {
            new_recipient: request.new_recipient,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    // ============ ESCROW ADMIN FUNCTIONS ============

    /// Resolve a dispute in escrow
    pub async fn resolve_dispute(&self, request: ResolveDisputeRequest) -> Result<ResolveDisputeResponse, ContractError> {
        println!("   Resolving dispute for listing {}...", request.listing_id);

        let winner = request.winner.parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?;

        // Call the resolveDispute function
        let call = self.vertix_escrow
            .method::<_, ()>("resolveDispute", (request.listing_id, winner))
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Resolve dispute transaction reverted".to_string()));
            }
        }

        println!("   Dispute resolved successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(ResolveDisputeResponse {
            listing_id: request.listing_id,
            winner: request.winner,
            amount: 0, // TODO: Extract from events
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Set escrow duration
    pub async fn set_escrow_duration(&self, request: SetEscrowDurationRequest) -> Result<SetEscrowDurationResponse, ContractError> {
        println!("   Setting escrow duration to {} seconds...", request.new_duration);

        // Call the setEscrowDuration function
        let call = self.vertix_escrow
            .method::<_, ()>("setEscrowDuration", request.new_duration)
            .map_err(|e| ContractError::ContractCallError(e.to_string()))?;

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Set escrow duration transaction reverted".to_string()));
            }
        }

        println!("   Escrow duration set successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(SetEscrowDurationResponse {
            new_duration: request.new_duration,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    // ============ PAUSE/UNPAUSE FUNCTIONS ============

    /// Pause a contract
    pub async fn pause_contract(&self, request: PauseContractRequest) -> Result<PauseContractResponse, ContractError> {
        println!("   Pausing {} contract...", request.contract_type);

        let call = match request.contract_type.as_ref() {
            "escrow" => self.vertix_escrow.method::<_, ()>("pause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            "marketplace" => self.marketplace_storage.method::<_, ()>("pause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            "bridge" => self.cross_chain_bridge.method::<_, ()>("pause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            _ => return Err(ContractError::ContractCallError(format!("Unknown contract type: {}", request.contract_type))),
        };

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Pause contract transaction reverted".to_string()));
            }
        }

        println!("   Contract paused successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(PauseContractResponse {
            contract_type: request.contract_type,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    /// Unpause a contract
    pub async fn unpause_contract(&self, request: UnpauseContractRequest) -> Result<UnpauseContractResponse, ContractError> {
        println!("   Unpausing {} contract...", request.contract_type);

        let call = match request.contract_type.as_ref() {
            "escrow" => self.vertix_escrow.method::<_, ()>("unpause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            "marketplace" => self.marketplace_storage.method::<_, ()>("unpause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            "bridge" => self.cross_chain_bridge.method::<_, ()>("unpause", ())
                .map_err(|e| ContractError::ContractCallError(e.to_string()))?,
            _ => return Err(ContractError::ContractCallError(format!("Unknown contract type: {}", request.contract_type))),
        };

        // Send transaction
        let call_with_sender = call.from(self.wallet.address());
        let pending_tx = call_with_sender
            .send()
            .await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?;

        // Wait for transaction receipt
        let receipt = pending_tx.await
            .map_err(|e| ContractError::TransactionError(e.to_string()))?
            .ok_or_else(|| ContractError::TransactionError("No transaction receipt".to_string()))?;

        // Check if transaction was successful
        if let Some(status) = receipt.status {
            if status == 0.into() {
                return Err(ContractError::TransactionError("Unpause contract transaction reverted".to_string()));
            }
        }

        println!("   Contract unpaused successfully!");
        println!("     Transaction: 0x{:x}", receipt.transaction_hash);

        Ok(UnpauseContractResponse {
            contract_type: request.contract_type,
            transaction_hash: format!("0x{:x}", receipt.transaction_hash).into(),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
        })
    }

    // ============ UTILITY FUNCTIONS ============

    /// Get the admin wallet address
    pub fn get_admin_address(&self) -> Address {
        self.wallet.address()
    }

    /// Get the network configuration
    pub fn get_network_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    /// Get contract addresses
    pub fn get_contract_addresses(&self) -> &ContractAddresses {
        &self.chain_config.contract_addresses
    }
}
