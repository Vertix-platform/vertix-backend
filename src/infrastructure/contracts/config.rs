use crate::infrastructure::contracts::types::{
    ChainConfig, ChainType, GasSettings, GasPriceStrategy, MultiChainConfig,
    NativeCurrency, ContractAddresses
};
use crate::infrastructure::contracts::addresses;
use crate::domain::services::ContractError;

/// Get the current chain configuration from environment variables
pub fn get_current_chain_config() -> Result<ChainConfig, ContractError> {
    let chain_id = std::env::var("CHAIN_ID")
        .unwrap_or_else(|_| "31337".to_string())
        .parse::<u64>()
        .unwrap_or(31337);

    match chain_id {
        137 => get_polygon_mainnet_config(),
        8453 => get_base_mainnet_config(),
        84532 => get_base_sepolia_config(),
        1101 => get_polygon_zkevm_mainnet_config(),
        2442 => get_polygon_zkevm_testnet_config(),
        31337 => get_anvil_config(),
        _ => get_anvil_config(), // Default to Anvil for unknown chains
    }
}

/// Get all supported chain configurations
pub fn get_supported_chains() -> Result<Vec<ChainConfig>, ContractError> {
    let mut chains = Vec::new();

    chains.push(get_anvil_config()?);
    chains.push(get_base_sepolia_config()?);
    chains.push(get_polygon_zkevm_testnet_config()?);
    chains.push(get_polygon_mainnet_config()?);
    chains.push(get_base_mainnet_config()?);
    chains.push(get_polygon_zkevm_mainnet_config()?);

    Ok(chains)
}

/// Get multi-chain configuration
pub fn get_multi_chain_config() -> Result<MultiChainConfig, ContractError> {
    let current_chain = get_current_chain_config()?;
    let supported_chains = get_supported_chains()?;

    Ok(MultiChainConfig {
        current_chain,
        supported_chains,
    })
}

/// Anvil local development configuration
fn get_anvil_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 31337,
        chain_type: ChainType::Polygon, // Using Polygon type for compatibility
        name: "Anvil Local".to_string(),
        rpc_url: std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string()),
        ws_url: None,
        explorer_url: "".to_string(),
        native_currency: NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 200000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Fixed(20000000000), // 20 gwei
            block_time_seconds: 1,
        },
        contract_addresses: get_anvil_contract_addresses()?,
    })
}

/// Base Sepolia testnet configuration
fn get_base_sepolia_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 84532,
        chain_type: ChainType::Base,
        name: "Base Sepolia".to_string(),
        rpc_url: std::env::var("BASE_SEPOLIA_RPC_URL").unwrap_or_else(|_| "https://sepolia.base.org".to_string()),
        ws_url: None,
        explorer_url: "https://sepolia.basescan.org".to_string(),
        native_currency: NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 300000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Eip1559,
            block_time_seconds: 2,
        },
        contract_addresses: get_base_contract_addresses()?,
    })
}

/// Polygon mainnet configuration
fn get_polygon_mainnet_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 137,
        chain_type: ChainType::Polygon,
        name: "Polygon Mainnet".to_string(),
        rpc_url: std::env::var("POLYGON_MAINNET_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_string()),
        ws_url: None,
        explorer_url: "https://polygonscan.com".to_string(),
        native_currency: NativeCurrency {
            name: "MATIC".to_string(),
            symbol: "MATIC".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 500000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Dynamic,
            block_time_seconds: 2,
        },
        contract_addresses: get_polygon_contract_addresses()?,
    })
}

/// Base mainnet configuration
fn get_base_mainnet_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 8453,
        chain_type: ChainType::Base,
        name: "Base Mainnet".to_string(),
        rpc_url: std::env::var("BASE_MAINNET_RPC_URL").unwrap_or_else(|_| "https://mainnet.base.org".to_string()),
        ws_url: None,
        explorer_url: "https://basescan.org".to_string(),
        native_currency: NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 300000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Eip1559,
            block_time_seconds: 2,
        },
        contract_addresses: get_base_contract_addresses()?,
    })
}

/// Polygon zkEVM mainnet configuration
fn get_polygon_zkevm_mainnet_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 1101,
        chain_type: ChainType::Polygon,
        name: "Polygon zkEVM Mainnet".to_string(),
        rpc_url: std::env::var("POLYGON_ZKEVM_MAINNET_RPC_URL").unwrap_or_else(|_| "https://zkevm-rpc.com".to_string()),
        ws_url: None,
        explorer_url: "https://zkevm.polygonscan.com".to_string(),
        native_currency: NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 500000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Dynamic,
            block_time_seconds: 2,
        },
        contract_addresses: get_polygon_zkevm_contract_addresses()?,
    })
}

/// Polygon zkEVM testnet configuration
fn get_polygon_zkevm_testnet_config() -> Result<ChainConfig, ContractError> {
    Ok(ChainConfig {
        chain_id: 2442,
        chain_type: ChainType::Polygon,
        name: "Polygon zkEVM Testnet".to_string(),
        rpc_url: std::env::var("POLYGON_ZKEVM_TESTNET_RPC_URL").unwrap_or_else(|_| "https://rpc.public.zkevm-test.net".to_string()),
        ws_url: None,
        explorer_url: "https://testnet-zkevm.polygonscan.com".to_string(),
        native_currency: NativeCurrency {
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        },
        gas_settings: GasSettings {
            default_gas_limit: 500000,
            max_gas_limit: 30000000,
            gas_price_strategy: GasPriceStrategy::Dynamic,
            block_time_seconds: 2,
        },
        contract_addresses: get_polygon_zkevm_contract_addresses()?,
    })
}

/// Get contract addresses for Anvil using the addresses module
fn get_anvil_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_local_addresses()
}

/// Get contract addresses for Polygon using the addresses module
fn get_polygon_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_polygon_addresses()
}

/// Get contract addresses for Base using the addresses module
fn get_base_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_base_addresses()
}

/// Get contract addresses for Polygon zkEVM using the addresses module
fn get_polygon_zkevm_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_polygon_zkevm_addresses()
}

/// Get chain configuration by chain ID
pub fn get_chain_config_by_id(chain_id: u64) -> Result<Option<ChainConfig>, ContractError> {
    let supported_chains = get_supported_chains()?;
    Ok(supported_chains.into_iter().find(|config| config.chain_id == chain_id))
}

/// Validate if a chain ID is supported
pub fn is_chain_supported(chain_id: u64) -> Result<bool, ContractError> {
    let supported_chains = get_supported_chains()?;
    Ok(supported_chains.iter().any(|config| config.chain_id == chain_id))
}

/// Get gas limit for a specific operation on the current chain
pub fn get_gas_limit_for_operation(operation: &str) -> Result<u64, ContractError> {
    let config = get_current_chain_config()?;
    Ok(match operation {
        "mint_nft" => config.gas_settings.default_gas_limit,
        "list_nft" => config.gas_settings.default_gas_limit,
        "buy_nft" => config.gas_settings.default_gas_limit,
        "list_non_nft" => config.gas_settings.default_gas_limit,
        "buy_non_nft" => config.gas_settings.default_gas_limit,
        "confirm_transfer" => 100000,
        "raise_dispute" => 100000,
        "refund" => 100000,
        _ => config.gas_settings.default_gas_limit,
    })
}

/// Get private key with fallback for Anvil
pub fn get_private_key() -> Result<String, ContractError> {
    match std::env::var("PRIVATE_KEY") {
        Ok(key) => Ok(key),
        Err(_) => {
            // Check if we're on Anvil (local development)
            let chain_id = std::env::var("CHAIN_ID")
                .unwrap_or_else(|_| "31337".to_string())
                .parse::<u64>()
                .unwrap_or(31337);

            if chain_id == 31337 {
                // Use default Anvil private key for local development
                Ok("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string())
            } else {
                // For other chains, require explicit private key
                Err(ContractError::InvalidSignature { 
                    reason: "PRIVATE_KEY environment variable not set. Required for non-local chains.".to_string() 
                })
            }
        }
    }
}
