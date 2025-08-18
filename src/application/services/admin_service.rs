use std::sync::Arc;
use tokio::sync::RwLock;
use crate::infrastructure::contracts::admin_client::AdminContractClient;
use crate::infrastructure::contracts::config::{get_current_chain_config, get_private_key};
use crate::infrastructure::contracts::types::ChainConfig;
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

/// Service layer for admin operations
pub struct AdminService {
    client: Arc<RwLock<AdminContractClient>>,
}

impl AdminService {
    /// Create a new admin service
    pub async fn new() -> Result<Self, ContractError> {
        let chain_config = get_current_chain_config()?;

        let client = AdminContractClient::new(
            chain_config.rpc_url.clone(),
            get_private_key()?,
            chain_config,
        ).await?;

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
        })
    }

    /// Add an NFT contract as supported
    pub async fn add_supported_nft_contract(&self, request: AddSupportedNftContractRequest) -> Result<AddSupportedNftContractResponse, ContractError> {
        let client = self.client.read().await;
        client.add_supported_nft_contract(request).await
    }

    /// Remove an NFT contract from supported list
    pub async fn remove_supported_nft_contract(&self, request: RemoveSupportedNftContractRequest) -> Result<RemoveSupportedNftContractResponse, ContractError> {
        let client = self.client.read().await;
        client.remove_supported_nft_contract(request).await
    }

    /// Set platform fee
    pub async fn set_platform_fee(&self, request: SetPlatformFeeRequest) -> Result<SetPlatformFeeResponse, ContractError> {
        let client = self.client.read().await;
        client.set_platform_fee(request).await
    }

    /// Set fee recipient
    pub async fn set_fee_recipient(&self, request: SetFeeRecipientRequest) -> Result<SetFeeRecipientResponse, ContractError> {
        let client = self.client.read().await;
        client.set_fee_recipient(request).await
    }

    /// Resolve dispute
    pub async fn resolve_dispute(&self, request: ResolveDisputeRequest) -> Result<ResolveDisputeResponse, ContractError> {
        let client = self.client.read().await;
        client.resolve_dispute(request).await
    }

    /// Set escrow duration
    pub async fn set_escrow_duration(&self, request: SetEscrowDurationRequest) -> Result<SetEscrowDurationResponse, ContractError> {
        let client = self.client.read().await;
        client.set_escrow_duration(request).await
    }

    /// Pause contract
    pub async fn pause_contract(&self, request: PauseContractRequest) -> Result<PauseContractResponse, ContractError> {
        let client = self.client.read().await;
        client.pause_contract(request).await
    }

    /// Unpause contract
    pub async fn unpause_contract(&self, request: UnpauseContractRequest) -> Result<UnpauseContractResponse, ContractError> {
        let client = self.client.read().await;
        client.unpause_contract(request).await
    }

    /// Get admin address
    pub fn get_admin_address(&self) -> String {
        // This would need to be implemented based on the contract's owner
        "0x0000000000000000000000000000000000000000".to_string()
    }

    /// Get network configuration
    pub async fn get_network_config(&self) -> ChainConfig {
        let client = self.client.read().await;
        client.get_network_config().clone()
    }
}
