use crate::application::services::contract_service::ContractService;
use crate::domain::models::{MintNftRequest, CreateCollectionRequest, MintNftToCollectionRequest};
use std::sync::Arc;

/// Test configuration and setup
pub struct TestConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub chain_id: u64,
}

impl TestConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());
        let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
        let chain_id = std::env::var("CHAIN_ID").unwrap_or_else(|_| "31337".to_string()).parse::<u64>()?;

        Ok(Self {
            rpc_url,
            private_key,
            chain_id,
        })
    }
}

/// Create NFT metadata and hash it
pub fn create_nft_metadata(
    name: &str,
    description: &str,
    image_uri: &str,
    attributes: Option<Vec<serde_json::Value>>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Create metadata JSON
    let mut metadata = serde_json::json!({
        "name": name,
        "description": description,
        "image": image_uri,
        "external_url": "https://vertix.market",
        "created_at": chrono::Utc::now().timestamp()
    });

    // Add attributes if provided
    if let Some(attrs) = attributes {
        metadata["attributes"] = serde_json::Value::Array(attrs);
    }

    // Convert metadata to string and hash it using Keccak256
    let metadata_string = serde_json::to_string(&metadata)?;
    let metadata_hash = ethers::core::utils::keccak256(metadata_string.as_bytes());
    let metadata_hash_hex = format!("0x{}", hex::encode(metadata_hash));

    Ok((metadata_string, metadata_hash_hex))
}

/// Test NFT minting functionality
pub async fn test_nft_minting() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎨 Testing NFT minting...");

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Create attributes for the NFT
    let attributes = vec![
        serde_json::json!({
            "trait_type": "Creator",
            "value": "Vertix Backend"
        }),
        serde_json::json!({
            "trait_type": "Test",
            "value": "true"
        }),
        serde_json::json!({
            "trait_type": "Rarity",
            "value": "Common"
        })
    ];

    // Create metadata and hash it
    let (metadata_string, metadata_hash) = create_nft_metadata(
        "Vertix Test NFT",
        "A test NFT created by the Vertix backend",
        "ipfs://QmTest123",
        Some(attributes)
    )?;

    println!("   Metadata JSON: {}", metadata_string);
    println!("   Metadata Hash: {}", metadata_hash);

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Debug: Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from("ipfs://QmTest123"),
        metadata_hash: Arc::from(metadata_hash.to_string()),
        collection_id: Some(0),
        royalty_bps: Some(0), // Try with 0% royalty
    };

    match contract_service.mint_nft(wallet_address.clone(), mint_request).await {
        Ok(response) => {
            println!("    NFT minted successfully!");
            println!("      Token ID: {}", response.token_id);
            println!("      Transaction Hash: {}", response.transaction_hash);
            println!("      Block Number: {}", response.block_number);
            Ok(())
        }
        Err(e) => {
            println!("   Failed to mint NFT: {}", e);
            Err(e.into())
        }
    }
}

pub async fn test_create_collection() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎨 Testing create collection...");

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);


    // Debug: Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    let create_collection_request = CreateCollectionRequest {
        name: Arc::from("Vertix Test Collection"),
        symbol: Arc::from("VTX"),
        image: Arc::from("ipfs://QmTest123"),
        max_supply: Some(1000),
    };

    match contract_service.create_collection(wallet_address.clone(), create_collection_request).await {
        Ok(response) => {
            println!("   Collection created successfully!");
            println!("      Collection ID: {}", response.collection_id);
            println!("      Transaction Hash: {}", response.transaction_hash);
            println!("      Block Number: {}", response.block_number);
            Ok(())
        }
        Err(e) => {
            println!("   Failed to create collection: {}", e);
            Err(e.into())
        }
    }
}

pub async fn test_mint_nft_to_collection() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎨 Testing mint NFT to collection...");

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;

    let wallet_address = contract_service.get_wallet_address().await;

    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // Step 3: Create attributes for the NFT
    let attributes = vec![
        serde_json::json!({
            "trait_type": "Creator",
            "value": "Vertix Backend"
        }),
        serde_json::json!({
            "trait_type": "Test",
            "value": "true"
        }),
        serde_json::json!({
            "trait_type": "Rarity",
            "value": "Common"
        })
    ];

    // Create metadata and hash it
    let (metadata_string, metadata_hash) = create_nft_metadata(
        "Vertix Test NFT",
        "A test NFT created by the Vertix backend",
        "ipfs://QmTest123",
        Some(attributes)
    )?;

    println!("   Metadata JSON: {}", metadata_string);
    println!("   Metadata Hash: {}", metadata_hash);


    let mint_request = MintNftToCollectionRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from("ipfs://QmTest123"),
        metadata_hash: Arc::from(metadata_hash.to_string()),
        collection_id: 1, // Use the actual collection ID
        royalty_bps: Some(500), // 5% royalty
    };

    match contract_service.mint_nft_to_collection(wallet_address.clone(), mint_request).await {
        Ok(response) => {
            println!("    NFT minted to collection successfully!");
            println!("      Collection ID: {}", response.collection_id);
            println!("      Token ID: {}", response.token_id);
            println!("      Transaction Hash: {}", response.transaction_hash);
            println!("      Block Number: {}", response.block_number);
            Ok(())
        }
        Err(e) => {
            println!("  Failed to mint NFT to collection: {}", e);
            Err(e.into())
        }
    }
}

/// Test connection and basic functionality
pub async fn test_connection() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔗 Testing wallet and network connection...");

    // Load configuration
    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;

    // Test wallet connection
    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {:?}", wallet_address);

    // Test balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // Test network connection
    let is_connected = contract_service.is_connected().await;
    println!("   Network connected: {}", is_connected);

    let network_config = contract_service.get_network_config();
    println!("   Network config: {} (Chain ID: {})", network_config.native_currency.name, network_config.chain_id);

    println!("✅ Connection test completed successfully!");
    Ok(())
}