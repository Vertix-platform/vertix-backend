use crate::infrastructure::contracts::types::{
    ChainConfig, ChainType, GasSettings, GasPriceStrategy, MultiChainConfig,
    NativeCurrency, ContractAddresses
};
use crate::infrastructure::contracts::addresses;
use crate::domain::services::ContractError;

/// Get all available chains from environment variables
pub fn get_available_chains_from_env() -> Result<Vec<ChainConfig>, ContractError> {
    let mut available_chains = Vec::new();

    // Check for Anvil (local development)
    if let Ok(chain_id) = std::env::var("ANVIL_CHAIN_ID") {
        if chain_id == "31337" {
            available_chains.push(get_anvil_config()?);
        }
    }

    // Check for Polygon Mainnet (COMMENTED OUT - Mainnet not supported)
    // if let Ok(chain_id) = std::env::var("POLYGON_CHAIN_ID") {
    //     if chain_id == "137" {
    //         available_chains.push(get_polygon_mainnet_config()?);
    //     }
    // }

    // Check for Base Mainnet (COMMENTED OUT - Mainnet not supported)
    // if let Ok(chain_id) = std::env::var("BASE_CHAIN_ID") {
    //     if chain_id == "8453" {
    //         available_chains.push(get_base_mainnet_config()?);
    //     }
    // }

    // Check for Base Sepolia
    if let Ok(chain_id) = std::env::var("BASE_SEPOLIA_CHAIN_ID") {
        if chain_id == "84532" {
            available_chains.push(get_base_sepolia_config()?);
        }
    }

    // Check for Polygon zkEVM Mainnet (COMMENTED OUT - Mainnet not supported)
    // if let Ok(chain_id) = std::env::var("POLYGON_ZKEVM_CHAIN_ID") {
    //     if chain_id == "1101" {
    //         available_chains.push(get_polygon_zkevm_mainnet_config()?);
    //     }
    // }

    // Check for Polygon zkEVM Testnet (COMMENTED OUT - No addresses available yet)
    // if let Ok(chain_id) = std::env::var("POLYGON_ZKEVM_TESTNET_CHAIN_ID") {
    //     if chain_id == "2442" {
    //         available_chains.push(get_polygon_zkevm_testnet_config()?);
    //     }
    // }

    // If no chains are configured, add default
    if available_chains.is_empty() {
        available_chains.push(get_anvil_config()?);
    }

    Ok(available_chains)
}

/// Get the current chain configuration from environment variables
pub fn get_current_chain_config() -> Result<ChainConfig, ContractError> {
    let chain_id = std::env::var("DEFAULT_CHAIN_ID")
        .unwrap_or_else(|_| "31337".to_string())
        .parse::<u64>()
        .unwrap_or(31337);

    // First try to get from available chains
    let available_chains = get_available_chains_from_env()?;
    if let Some(config) = available_chains.iter().find(|c| c.chain_id == chain_id) {
        return Ok(config.clone());
    }

    // Fallback to hardcoded configs (Mainnet chains commented out)
    match chain_id {
        // 137 => get_polygon_mainnet_config(), // Mainnet not supported
        // 8453 => get_base_mainnet_config(), // Mainnet not supported
        84532 => get_base_sepolia_config(),
        // 1101 => get_polygon_zkevm_mainnet_config(), // Mainnet not supported
        // 2442 => get_polygon_zkevm_testnet_config(), // No addresses available yet
        31337 => get_anvil_config(),
        _ => get_anvil_config(), // Default to Anvil for unknown chains
    }
}

/// Get all supported chain configurations
pub fn get_supported_chains() -> Result<Vec<ChainConfig>, ContractError> {
    // First try to get chains from environment variables
    let env_chains = get_available_chains_from_env()?;
    if !env_chains.is_empty() {
        return Ok(env_chains);
    }

    // Fallback to only working testnet chains (with available addresses)
    let mut chains = Vec::new();

    chains.push(get_anvil_config()?);
    chains.push(get_base_sepolia_config()?);
    // chains.push(get_polygon_zkevm_testnet_config()?); // No addresses available yet
    // chains.push(get_polygon_mainnet_config()?); // Mainnet not supported
    // chains.push(get_base_mainnet_config()?); // Mainnet not supported
    // chains.push(get_polygon_zkevm_mainnet_config()?); // Mainnet not supported

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

/// Polygon mainnet configuration (COMMENTED OUT - Mainnet not supported)
// fn get_polygon_mainnet_config() -> Result<ChainConfig, ContractError> {
//     Ok(ChainConfig {
//         chain_id: 137,
//         chain_type: ChainType::Polygon,
//         name: "Polygon Mainnet".to_string(),
//         rpc_url: std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_string()),
//         ws_url: None,
//         explorer_url: "https://polygonscan.com".to_string(),
//         native_currency: NativeCurrency {
//             name: "MATIC".to_string(),
//             symbol: "MATIC".to_string(),
//             decimals: 18,
//         },
//         gas_settings: GasSettings {
//             default_gas_limit: 500000,
//             max_gas_limit: 30000000,
//             gas_price_strategy: GasPriceStrategy::Dynamic,
//             block_time_seconds: 2,
//         },
//         contract_addresses: get_polygon_contract_addresses()?,
//     })
// }

/// Base mainnet configuration (COMMENTED OUT - Mainnet not supported)
// fn get_base_mainnet_config() -> Result<ChainConfig, ContractError> {
//     Ok(ChainConfig {
//         chain_id: 8453,
//         chain_type: ChainType::Base,
//         name: "Base Mainnet".to_string(),
//         rpc_url: std::env::var("BASE_RPC_URL").unwrap_or_else(|_| "https://mainnet.base.org".to_string()),
//         ws_url: None,
//         explorer_url: "https://basescan.org".to_string(),
//         native_currency: NativeCurrency {
//             name: "Ether".to_string(),
//             symbol: "ETH".to_string(),
//             decimals: 18,
//         },
//         gas_settings: GasSettings {
//             default_gas_limit: 300000,
//             max_gas_limit: 30000000,
//             gas_price_strategy: GasPriceStrategy::Eip1559,
//             block_time_seconds: 2,
//         },
//         contract_addresses: get_base_contract_addresses()?,
//     })
// }

/// Polygon zkEVM mainnet configuration (COMMENTED OUT - Mainnet not supported)
// fn get_polygon_zkevm_mainnet_config() -> Result<ChainConfig, ContractError> {
//     Ok(ChainConfig {
//         chain_id: 1101,
//         chain_type: ChainType::Polygon,
//         name: "Polygon zkEVM Mainnet".to_string(),
//         rpc_url: std::env::var("POLYGON_ZKEVM_MAINNET_RPC_URL").unwrap_or_else(|_| "https://zkevm-rpc.com".to_string()),
//         ws_url: None,
//         explorer_url: "https://zkevm.polygonscan.com".to_string(),
//         native_currency: NativeCurrency {
//             name: "Ether".to_string(),
//             symbol: "ETH".to_string(),
//             decimals: 18,
//         },
//         gas_settings: GasSettings {
//             default_gas_limit: 500000,
//             max_gas_limit: 30000000,
//             gas_price_strategy: GasPriceStrategy::Dynamic,
//             block_time_seconds: 2,
//         },
//         contract_addresses: get_polygon_zkevm_contract_addresses()?,
//     })
// }

/// Polygon zkEVM testnet configuration (COMMENTED OUT - No addresses available yet)
// fn get_polygon_zkevm_testnet_config() -> Result<ChainConfig, ContractError> {
//     Ok(ChainConfig {
//         chain_id: 2442,
//         chain_type: ChainType::Polygon,
//         name: "Polygon zkEVM Testnet".to_string(),
//         rpc_url: std::env::var("POLYGON_ZKEVM_TESTNET_RPC_URL").unwrap_or_else(|_| "https://rpc.public.zkevm-test.net".to_string()),
//         ws_url: None,
//         explorer_url: "https://testnet-zkevm.polygonscan.com".to_string(),
//         native_currency: NativeCurrency {
//             name: "Ether".to_string(),
//             symbol: "ETH".to_string(),
//             decimals: 18,
//         },
//         gas_settings: GasSettings {
//             default_gas_limit: 500000,
//             max_gas_limit: 30000000,
//             gas_price_strategy: GasPriceStrategy::Dynamic,
//             block_time_seconds: 2,
//         },
//         contract_addresses: get_polygon_zkevm_contract_addresses()?,
//     })
// }

/// Get contract addresses for Anvil using the addresses module
fn get_anvil_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_local_addresses()
}

/// Get contract addresses for Polygon using the addresses module (COMMENTED OUT - Mainnet not supported)
// fn get_polygon_contract_addresses() -> Result<ContractAddresses, ContractError> {
//     addresses::load_polygon_addresses()
// }

/// Get contract addresses for Base using the addresses module
fn get_base_contract_addresses() -> Result<ContractAddresses, ContractError> {
    addresses::load_base_addresses()
}

/// Get contract addresses for Polygon zkEVM using the addresses module (COMMENTED OUT - No addresses available yet)
// fn get_polygon_zkevm_contract_addresses() -> Result<ContractAddresses, ContractError> {
//     addresses::load_polygon_zkevm_addresses()
// }

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
    // First try to get the main PRIVATE_KEY
    match std::env::var("PRIVATE_KEY") {
        Ok(key) => Ok(key),
        Err(_) => {
            // Check available chains to determine which private key to use
            let available_chains = get_available_chains_from_env()?;

            // If we have multiple chains, we need a specific private key
            if available_chains.len() > 1 {
                return Err(ContractError::InvalidSignature { 
                    reason: "Multiple chains detected. PRIVATE_KEY environment variable must be set for multi-chain operations.".to_string() 
                });
            }

            // If only one chain, check if it's Anvil
            if let Some(chain_config) = available_chains.first() {
                if chain_config.chain_id == 31337 {
                    // Use default Anvil private key for local development
                    Ok("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string())
                } else {
                    // For other chains, require explicit private key
                    Err(ContractError::InvalidSignature { 
                        reason: format!("PRIVATE_KEY environment variable not set. Required for chain ID: {}", chain_config.chain_id)
                    })
                }
            } else {
                // Fallback to checking DEFAULT_CHAIN_ID
                let chain_id = std::env::var("DEFAULT_CHAIN_ID")
                    .unwrap_or_else(|_| "31337".to_string())
                    .parse::<u64>()
                    .unwrap_or(31337);

                if chain_id == 31337 {
                    // Use default Anvil private key for local development
                    Ok("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string())
                } else {
                    // For other chains, require explicit private key
                    Err(ContractError::InvalidSignature { 
                        reason: format!("PRIVATE_KEY environment variable not set. Required for chain ID: {}", chain_id)
                    })
                }
            }
        }
    }
}

/// Get private key for a specific chain
pub fn get_private_key_for_chain(chain_id: u64) -> Result<String, ContractError> {
    // Try chain-specific private key first
    let chain_specific_key = match chain_id {
        31337 => std::env::var("ANVIL_PRIVATE_KEY"),
        137 => std::env::var("POLYGON_PRIVATE_KEY"),
        8453 => std::env::var("BASE_PRIVATE_KEY"),
        84532 => std::env::var("BASE_SEPOLIA_PRIVATE_KEY"),
        1101 => std::env::var("POLYGON_ZKEVM_PRIVATE_KEY"),
        2442 => std::env::var("POLYGON_ZKEVM_TESTNET_PRIVATE_KEY"),
        _ => Err(std::env::VarError::NotPresent),
    };

    match chain_specific_key {
        Ok(key) => Ok(key),
        Err(_) => {
            // Fallback to main PRIVATE_KEY
            match std::env::var("PRIVATE_KEY") {
                Ok(key) => Ok(key),
                Err(_) => {
                    if chain_id == 31337 {
                        // Use default Anvil private key for local development
                        Ok("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string())
                    } else {
                        // For other chains, require explicit private key
                        Err(ContractError::InvalidSignature { 
                            reason: format!("No private key found for chain ID: {}. Set PRIVATE_KEY or chain-specific key.", chain_id)
                        })
                    }
                }
            }
        }
    }
}
