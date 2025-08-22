use std::fs;
use std::path::Path;
use std::collections::HashMap;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Extracting contract ABIs and addresses...");

    // Extract ABIs to the correct location
    extract_abis("../abis", "contracts/out")?;

    // Extract addresses for each network
    let networks = vec!["anvil", "base_sepolia", "polygon_zkevm_testnet"];

    for network in networks {
        let broadcast_dir = format!("contracts/broadcast/DeployVertix.s.sol/{}",
            match network {
                "anvil" => "31337",
                "base_sepolia" => "84532",
                "polygon_zkevm_testnet" => "2442",
                _ => "31337"
            }
        );

        extract_addresses(&broadcast_dir, "../src/infrastructure/contracts/addresses", network)?;
    }

    println!("Contract extraction complete!");
    println!("ABIs saved to: ../abis");
    println!("Addresses saved to: ../src/infrastructure/contracts/addresses");

    Ok(())
}

fn extract_abis(out_dir: &str, abi_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory
    fs::create_dir_all(out_dir)?;

    // List of contracts to extract
    let contracts = vec![
        "VertixNFT",
        "VertixGovernance",
        "VertixEscrow",
        "MarketplaceCore",
        "MarketplaceAuctions",
        "MarketplaceFees",
        "MarketplaceStorage",
        "MarketplaceProxy",
        "CrossChainBridge",
        "CrossChainRegistry"
    ];

    for contract in contracts {
        let abi_path = format!("{}/{}.sol/{}.json", abi_dir, contract, contract);
        let out_path = format!("{}/{}.json", out_dir, contract);

        if Path::new(&abi_path).exists() {
            let abi_content = fs::read_to_string(&abi_path)?;
            let abi_json: Value = serde_json::from_str(&abi_content)?;

            if let Some(abi) = abi_json.get("abi") {
                fs::write(&out_path, serde_json::to_string_pretty(abi)?)?;
                println!("Extracted ABI: {}", contract);
            }
        }
    }

    Ok(())
}

fn extract_addresses(broadcast_dir: &str, addresses_dir: &str, network_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create addresses directory
    fs::create_dir_all(addresses_dir)?;

    // Check if broadcast directory exists for this network
    if !Path::new(broadcast_dir).exists() {
        println!("No deployment found for {} - attempting deployment...", network_name);

        let network_arg = match network_name {
            "anvil" => "--network anvil",
            "base_sepolia" => "--network base-testnet",
            "polygon_zkevm_testnet" => "--network polygon-zkevm-testnet",
            _ => "--network anvil"
        };

        let output = std::process::Command::new("make")
            .arg("deploy")
            .env("ARGS", network_arg)
            .current_dir("../../contracts")
            .output()?;

        if !output.status.success() {
            println!("Deployment failed for {}: {}", network_name, String::from_utf8_lossy(&output.stderr));
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        println!("Deployment completed successfully for {}", network_name);

        // Parse the deployment output to extract addresses
        parse_deployment_output(&output_str, addresses_dir, network_name)?;
    } else {
        println!("Found existing deployment artifacts for {}", network_name);

        // Try to parse from existing deployment files
        if let Ok(addresses) = parse_from_broadcast_files(broadcast_dir) {
            if !addresses.is_empty() {
                save_addresses(&addresses, addresses_dir, network_name)?;
            } else {
                println!("No addresses found in broadcast files for {}", network_name);
            }
        } else {
            println!("Failed to parse addresses from broadcast files for {}", network_name);
        }
    }

    Ok(())
}

fn parse_deployment_output(output: &str, addresses_dir: &str, network_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut addresses = HashMap::new();

    // Parse proxy addresses from "proxy deployed at:" lines
    for line in output.lines() {
        if line.contains("proxy deployed at:") {
            if let Some(colon_pos) = line.find("proxy deployed at:") {
                let contract_part = &line[..colon_pos].trim();
                let address_part = &line[colon_pos + "proxy deployed at:".len()..].trim();

                if let Some(space_pos) = contract_part.rfind(' ') {
                    let contract_name = &contract_part[space_pos + 1..].trim();
                    addresses.insert(contract_name.to_string(), address_part.to_string());
                    println!("Extracted proxy address for {}: {}", contract_name, address_part);
                }
            }
        }
    }

    // Parse deployment summary section
    let mut in_summary = false;
    for line in output.lines() {
        if line.contains("=== Deployment Summary") {
            in_summary = true;
            continue;
        }
        if line.contains("==========================================") {
            in_summary = false;
            continue;
        }

        if in_summary && line.contains(":") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let contract_name = parts[0].trim();
                let address = parts[1].trim();

                let mapped_name = match contract_name {
                    "NFT Contract" => Some("VertixNFT"),
                    "Governance" => Some("VertixGovernance"),
                    "Escrow" => Some("VertixEscrow"),
                    "Marketplace Proxy" => Some("MarketplaceProxy"),
                    "CrossChain Bridge" => Some("CrossChainBridge"),
                    "Marketplace Core" => Some("MarketplaceCore"),
                    "Marketplace Auctions" => Some("MarketplaceAuctions"),
                    "Marketplace Fees" => Some("MarketplaceFees"),
                    "Marketplace Storage" => Some("MarketplaceStorage"),
                    "CrossChain Registry" => Some("CrossChainRegistry"),
                    "Verification Server" => Some("VerificationServer"),
                    "Fee Recipient" => Some("FeeRecipient"),
                    _ => {
                        println!("Warning: Unknown contract in summary: {}", contract_name);
                        None
                    }
                };

                if let Some(mapped_name) = mapped_name {
                    addresses.insert(mapped_name.to_string(), address.to_string());
                    println!("Extracted address for {}: {}", mapped_name, address);
                }
            }
        }
    }

    if addresses.is_empty() {
        println!("No addresses found in deployment output for {}", network_name);
        return Ok(());
    }

    save_addresses(&addresses, addresses_dir, network_name)?;
    Ok(())
}

fn parse_from_broadcast_files(broadcast_dir: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut addresses = HashMap::new();

    // Try to read the latest deployment file
    let run_latest_path = format!("{}/run-latest.json", broadcast_dir);
    if Path::new(&run_latest_path).exists() {
        let content = fs::read_to_string(&run_latest_path)?;
        let json: Value = serde_json::from_str(&content)?;

        if let Some(transactions) = json.get("transactions").and_then(|t| t.as_array()) {
            for transaction in transactions {
                if let (Some(contract_name), Some(contract_address)) = (
                    transaction.get("contractName").and_then(|c| c.as_str()),
                    transaction.get("contractAddress").and_then(|a| a.as_str())
                ) {
                    addresses.insert(contract_name.to_string(), contract_address.to_string());
                }
            }
        }
    }

    Ok(addresses)
}

fn save_addresses(addresses: &HashMap<String, String>, addresses_dir: &str, network_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Found {} addresses for {}", addresses.len(), network_name);

    // Save addresses to network-specific file
    let addresses_file = format!("{}/deployed_addresses_{}.json", addresses_dir, network_name);
    fs::write(&addresses_file, serde_json::to_string_pretty(&addresses)?)?;

    // Create network-specific Rust constants file
    let mut rust_constants = format!("// Auto-generated contract addresses for {}\n", network_name);
    rust_constants.push_str("// DO NOT EDIT - Generated from deployment artifacts\n");
    rust_constants.push_str("// These are PROXY addresses (where applicable) and other contract addresses\n\n");

    for (name, address) in addresses {
        let constant_name = name.to_uppercase()
            .replace("Vertix", "VERTIX_")
            .replace(" ", "_")
            .replace("-", "_");
        rust_constants.push_str(&format!("pub const {}: &str = \"{}\";\n", constant_name, address));
    }

    let constants_file = format!("{}/addresses_{}.rs", addresses_dir, network_name);
    fs::write(&constants_file, rust_constants)?;
    println!("Generated Rust constants: addresses_{}.rs", network_name);

    Ok(())
}