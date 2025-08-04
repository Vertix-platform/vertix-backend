use std::fs;
use ethers::abi::Abi;
use crate::domain::services::ContractError;

pub fn load_vertix_nft_abi() -> Result<Abi, ContractError> {
    load_abi("vertixnft_abi.json")
}

pub fn load_vertix_governance_abi() -> Result<Abi, ContractError> {
    load_abi("vertixgovernance_abi.json")
}

pub fn load_vertix_escrow_abi() -> Result<Abi, ContractError> {
    load_abi("vertixescrow_abi.json")
}

pub fn load_marketplace_core_abi() -> Result<Abi, ContractError> {
    load_abi("marketplacecore_abi.json")
}

pub fn load_marketplace_auctions_abi() -> Result<Abi, ContractError> {
    load_abi("marketplaceauctions_abi.json")
}

pub fn load_cross_chain_bridge_abi() -> Result<Abi, ContractError> {
    load_abi("crosschainbridge_abi.json")
}

pub fn load_cross_chain_registry_abi() -> Result<Abi, ContractError> {
    load_abi("crosschainregistry_abi.json")
}

fn load_abi(filename: &str) -> Result<Abi, ContractError> {
    let abi_path = format!("abis/{}", filename);
    let abi_content = fs::read_to_string(&abi_path)
        .map_err(|e| ContractError::ContractCallError(format!("Failed to read ABI file {}: {}", filename, e)))?;

    serde_json::from_str(&abi_content)
        .map_err(|e| ContractError::ContractCallError(format!("Failed to parse ABI file {}: {}", filename, e)))
}