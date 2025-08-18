use ethers::types::Address;
use std::fs;
use std::collections::HashMap;
use crate::domain::services::ContractError;
use crate::infrastructure::contracts::types::{ContractAddresses, NetworkConfig};

// ============ HARDCODED ADDRESSES FOR LOCAL DEVELOPMENT ============
// These will be replaced by the extraction script

// Load contract addresses for local development (Anvil)
pub fn load_local_addresses() -> Result<ContractAddresses, ContractError> {
    // Try to load from generated file first
    if let Ok(addresses) = load_addresses_from_file("src/infrastructure/contracts/addresses/deployed_addresses_anvil.json") {
        return convert_json_to_addresses(addresses);
    }

    // Fallback to hardcoded addresses for development (Updated from latest deployment)
    Ok(ContractAddresses {
        vertix_nft: "0xF6a8aD553b265405526030c2102fda2bDcdDC177"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        vertix_governance: "0x666432Ccb747B2220875cE185f487Ed53677faC9"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        vertix_escrow: "0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        marketplace_core: "0x18E317A7D70d8fBf8e6E893616b52390EbBdb629"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        marketplace_auctions: "0x51A1ceB83B83F1985a81C295d1fF28Afef186E02"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        marketplace_fees: "0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        marketplace_storage: "0xB0D4afd8879eD9F52b28595d31B441D079B2Ca07"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        marketplace_proxy: "0xD1760AA0FCD9e64bA4ea43399Ad789CFd63C7809"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        cross_chain_bridge: "0x2E2Ed0Cfd3AD2f1d34481277b3204d807Ca2F8c2"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
        cross_chain_registry: "0x162A433068F51e18b7d13932F27e66a3f99E6890"
            .parse::<Address>()
            .map_err(|e| ContractError::InvalidAddress(e.to_string()))?,
    })
}

// Load contract addresses for Polygon network
pub fn load_polygon_addresses() -> Result<ContractAddresses, ContractError> {
    // Try to load from generated file first
    if let Ok(addresses) = load_addresses_from_file("src/infrastructure/contracts/addresses/deployed_addresses_polygon_mumbai.json") {
        return convert_json_to_addresses(addresses);
    }

    // Fallback to error if no deployment found
    Err(ContractError::ContractCallError("Polygon Mumbai addresses not found. Run deployment first.".to_string()))
}

// Load contract addresses for Base network
pub fn load_base_addresses() -> Result<ContractAddresses, ContractError> {
    // Try to load from generated file first
    if let Ok(addresses) = load_addresses_from_file("src/infrastructure/contracts/addresses/deployed_addresses_base_sepolia.json") {
        return convert_json_to_addresses(addresses);
    }

    // Fallback to error if no deployment found
    Err(ContractError::ContractCallError("Base Sepolia addresses not found. Run deployment first.".to_string()))
}

// Load contract addresses for Polygon zkEVM network
pub fn load_polygon_zkevm_addresses() -> Result<ContractAddresses, ContractError> {
    // Try to load from generated file first
    if let Ok(addresses) = load_addresses_from_file("src/infrastructure/contracts/addresses/deployed_addresses_polygon_zkevm.json") {
        return convert_json_to_addresses(addresses);
    }

    // Fallback to error if no deployment found
    Err(ContractError::ContractCallError("Polygon zkEVM addresses not found. Run deployment first.".to_string()))
}

// Load addresses from JSON file
fn load_addresses_from_file(file_path: &str) -> Result<HashMap<String, String>, ContractError> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| ContractError::ContractCallError(format!("Failed to read addresses file {}: {}", file_path, e)))?;

    let addresses: HashMap<String, String> = serde_json::from_str(&content)
        .map_err(|e| ContractError::ContractCallError(format!("Failed to parse addresses JSON from {}: {}", file_path, e)))?;

    Ok(addresses)
}

// Convert JSON addresses to ContractAddresses struct
fn convert_json_to_addresses(addresses: HashMap<String, String>) -> Result<ContractAddresses, ContractError> {
    let get_address = |key: &str| -> Result<Address, ContractError> {
        addresses.get(key)
            .ok_or_else(|| ContractError::ContractCallError(format!("Address not found for contract: {}", key)))
            .and_then(|addr_str| addr_str.parse::<Address>()
                .map_err(|e| ContractError::InvalidAddress(format!("Invalid address for {}: {}", key, e))))
    };

    Ok(ContractAddresses {
        vertix_nft: get_address("VertixNFT")?,
        vertix_governance: get_address("VertixGovernance")?,
        vertix_escrow: get_address("VertixEscrow")?,
        marketplace_core: get_address("MarketplaceCore")?,
        marketplace_auctions: get_address("MarketplaceAuctions")?,
        marketplace_fees: get_address("MarketplaceFees")?,
        marketplace_storage: get_address("MarketplaceStorage")?,
        marketplace_proxy: get_address("MarketplaceProxy")?,
        cross_chain_bridge: get_address("CrossChainBridge")?,
        cross_chain_registry: get_address("CrossChainRegistry")?,
    })
}

// Get network configuration for local development
pub fn get_local_network_config() -> NetworkConfig {
    NetworkConfig {
        chain_id: 31337, // Anvil default
        rpc_url: "http://localhost:8545".to_string(),
        ws_url: Some("ws://localhost:8545".to_string()),
        explorer_url: "http://localhost:8545".to_string(),
        native_currency: crate::infrastructure::contracts::types::NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
    }
}

// Get network configuration for Polygon Mumbai testnet
pub fn get_polygon_mumbai_network_config() -> NetworkConfig {
    NetworkConfig {
        chain_id: 80001,
        rpc_url: "https://polygon-mumbai-bor.publicnode.com".to_string(),
        ws_url: None,
        explorer_url: "https://mumbai.polygonscan.com".to_string(),
        native_currency: crate::infrastructure::contracts::types::NativeCurrency {
            name: "Matic".to_string(),
            symbol: "MATIC".to_string(),
            decimals: 18,
        },
    }
}

// Get network configuration for Polygon mainnet
pub fn get_polygon_network_config() -> NetworkConfig {
    NetworkConfig {
        chain_id: 137,
        rpc_url: "https://polygon-rpc.com".to_string(),
        ws_url: None,
        explorer_url: "https://polygonscan.com".to_string(),
        native_currency: crate::infrastructure::contracts::types::NativeCurrency {
            name: "Matic".to_string(),
            symbol: "MATIC".to_string(),
            decimals: 18,
        },
    }
}

// Get network configuration for Base Sepolia testnet
pub fn get_base_sepolia_network_config() -> NetworkConfig {
    NetworkConfig {
        chain_id: 84532,
        rpc_url: "https://sepolia.base.org".to_string(),
        ws_url: None,
        explorer_url: "https://sepolia.basescan.org".to_string(),
        native_currency: crate::infrastructure::contracts::types::NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
    }
}

// Get network configuration for Base mainnet
pub fn get_base_network_config() -> NetworkConfig {
    NetworkConfig {
        chain_id: 8453,
        rpc_url: "https://mainnet.base.org".to_string(),
        ws_url: None,
        explorer_url: "https://basescan.org".to_string(),
        native_currency: crate::infrastructure::contracts::types::NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
    }
}

// Get network configuration by chain ID
pub fn get_network_config_by_chain_id(chain_id: u64) -> Result<NetworkConfig, ContractError> {
    match chain_id {
        31337 => Ok(get_local_network_config()),
        80001 => Ok(get_polygon_mumbai_network_config()), // Polygon Mumbai testnet
        137 => Ok(get_polygon_network_config()), // Polygon mainnet
        84532 => Ok(get_base_sepolia_network_config()), // Base Sepolia testnet
        8453 => Ok(get_base_network_config()), // Base mainnet
        _ => Err(ContractError::ContractCallError(format!("Unsupported chain ID: {}", chain_id))),
    }
}

// Get contract addresses by chain ID
pub fn get_contract_addresses_by_chain_id(chain_id: u64) -> Result<ContractAddresses, ContractError> {
    match chain_id {
        31337 => load_local_addresses(),
        80001 => load_polygon_addresses(), // Polygon Mumbai testnet
        137 => load_polygon_addresses(), // Polygon mainnet (same addresses for now)
        84532 => load_base_addresses(), // Base Sepolia testnet
        8453 => load_base_addresses(), // Base mainnet (same addresses for now)
        1101 => load_polygon_zkevm_addresses(), // Polygon zkEVM mainnet
        1442 => load_polygon_zkevm_addresses(), // Polygon zkEVM testnet
        _ => Err(ContractError::ContractCallError(format!("Unsupported chain ID: {}", chain_id))),
    }
}