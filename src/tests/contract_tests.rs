use crate::application::services::contract_service::ContractService;
use crate::domain::models::{
    MintNftRequest, CreateCollectionRequest, MintNftToCollectionRequest,
    InitiateSocialMediaNftMintRequest, MintSocialMediaNftRequest
};
use crate::domain::SocialMediaPlatform;
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
    let metadata_hash = alloy::primitives::keccak256(metadata_string.as_bytes());
    let metadata_hash_hex = format!("0x{}", hex::encode(metadata_hash));

    Ok((metadata_string, metadata_hash_hex))
}

/// Test NFT minting functionality
pub async fn test_nft_minting() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing NFT minting...");

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
    println!("Testing create collection...");

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
    println!("Testing mint NFT to collection...");

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

pub async fn test_mint_social_media_nft() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing mint social media NFT...");

    // Set up test environment for Pinata
    if std::env::var("PINATA_JWT").is_err() {
        println!("   PINATA_JWT not set, using test mode");
        unsafe {
            std::env::set_var("PINATA_JWT", "test_jwt");
        }
    }

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // Test data for social media profile (use timestamp to ensure uniqueness)
    let timestamp = chrono::Utc::now().timestamp();
    let test_social_media_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from(format!("123456789_{}", timestamp)),
        username: Arc::from("testuser"),
        display_name: Arc::from("Test User"),
        profile_image_url: Some(Arc::from("https://example.com/image.jpg")),
        follower_count: Some(1000),
        verified: true,
        access_token: Arc::from("test_token"),
        custom_image_url: None,
        royalty_bps: Some(500), // 5% royalty
    };

    // Step 1: Initiate social media NFT minting
    println!("   Step 1: Initiating social media NFT minting...");

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), test_social_media_data).await {
        Ok(init_response) => {
            println!("   Initiation successful!");


            // Verify the token URI is in IPFS format
            if !init_response.token_uri.starts_with("ipfs://") {
                println!("   Warning: Token URI is not in IPFS format: {}", init_response.token_uri);
            } else {
                println!("   Token URI is in correct IPFS format");
            }

            // Step 2: Mint the social media NFT
            println!("    Step 2: Minting social media NFT...");

            let mint_request = MintSocialMediaNftRequest {
                to: Arc::from(wallet_address.to_string()),
                social_media_id: init_response.social_media_id,
                token_uri: init_response.token_uri,
                metadata_hash: init_response.metadata_hash,
                royalty_bps: Some(init_response.royalty_bps),
                signature: init_response.signature,
                // custom_image_url: None,
            };

            match contract_service.mint_social_media_nft(wallet_address.clone(), mint_request).await {
                Ok(mint_response) => {
                    println!("   Social media NFT minted successfully!");
                    println!("     Token ID: {}", mint_response.token_id);
                    println!("     Transaction Hash: {}", mint_response.transaction_hash);
                    println!("     Block Number: {}", mint_response.block_number);
                    Ok(())
                }
                Err(e) => {
                    println!("   Failed to mint social media NFT: {}", e);
                    Err(e.into())
                }
            }
        }
        Err(e) => {
            println!("   Failed to initiate social media NFT minting: {}", e);
            Err(e.into())
        }
    }
}

/// Test social media NFT minting with different platforms
pub async fn test_social_media_platforms() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing social media NFT minting with different platforms...");

    // Set up test environment for Pinata
    if std::env::var("PINATA_JWT").is_err() {
        println!("   PINATA_JWT not set, using test mode");
        unsafe {
            std::env::set_var("PINATA_JWT", "test_jwt");
        }
    }

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;
    let wallet_address = contract_service.get_wallet_address().await;

    // Test Instagram
    println!("   Testing Instagram platform...");
    let instagram_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Instagram,
        user_id: Arc::from("987654321"),
        username: Arc::from("instagramuser"),
        display_name: Arc::from("Instagram User"),
        profile_image_url: Some(Arc::from("https://example.com/instagram.jpg")),
        follower_count: Some(5000),
        verified: false,
        access_token: Arc::from("instagram_token"),
        custom_image_url: None,
        royalty_bps: Some(300), // 3% royalty
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), instagram_data).await {
        Ok(response) => {
            println!("   Instagram initiation successful!");
            println!("     Social Media ID: {}", response.social_media_id);
            assert!(response.social_media_id.contains("instagram_"));
        }
        Err(e) => {
            println!("   Instagram initiation failed: {}", e);
            return Err(e.into());
        }
    }

    // Test Facebook
    println!("   Testing Facebook platform...");
    let facebook_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Facebook,
        user_id: Arc::from("555666777"),
        username: Arc::from("facebookuser"),
        display_name: Arc::from("Facebook User"),
        profile_image_url: Some(Arc::from("https://example.com/facebook.jpg")),
        follower_count: Some(2500),
        verified: true,
        access_token: Arc::from("facebook_token"),
        custom_image_url: None,
        royalty_bps: Some(750), // 7.5% royalty
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), facebook_data).await {
        Ok(response) => {
            println!("   Facebook initiation successful!");
            println!("     Social Media ID: {}", response.social_media_id);
            assert!(response.social_media_id.contains("facebook_"));
        }
        Err(e) => {
            println!("   Facebook initiation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   All platform tests completed successfully!");
    Ok(())
}

/// Test social media NFT minting with custom images
pub async fn test_custom_image_minting() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing social media NFT minting with custom images...");

    // Set up test environment for Pinata
    if std::env::var("PINATA_JWT").is_err() {
        println!("   PINATA_JWT not set, using test mode");
        unsafe {
            std::env::set_var("PINATA_JWT", "test_jwt");
        }
    }

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;
    let wallet_address = contract_service.get_wallet_address().await;

    // Test with custom image URL
    println!("   Testing with custom image URL...");
    let custom_image_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from("111222333"),
        username: Arc::from("customimageuser"),
        display_name: Arc::from("Custom Image User"),
        profile_image_url: Some(Arc::from("https://example.com/profile.jpg")),
        follower_count: Some(1500),
        verified: true,
        access_token: Arc::from("custom_token"),
        custom_image_url: Some(Arc::from("https://example.com/custom-artwork.jpg")),
        royalty_bps: Some(1000), // 10% royalty (maximum)
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), custom_image_data).await {
        Ok(response) => {
            println!("   Custom image initiation successful!");
            println!("     Social Media ID: {}", response.social_media_id);
            println!("     Token URI: {}", response.token_uri);

            // Verify the metadata contains the custom image
            if response.metadata.contains("custom-artwork.jpg") {
                println!("   Custom image URL found in metadata");
            } else {
                println!("   Custom image URL not found in metadata");
            }
        }
        Err(e) => {
            println!("   Custom image initiation failed: {}", e);
            return Err(e.into());
        }
    }

    // Test with no profile image (should use fallback)
    println!("   Testing with no profile image (fallback)...");
    let no_image_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from("444555666"),
        username: Arc::from("noimageuser"),
        display_name: Arc::from("No Image User"),
        profile_image_url: None,
        follower_count: Some(500),
        verified: false,
        access_token: Arc::from("noimage_token"),
        custom_image_url: None,
        royalty_bps: Some(250), // 2.5% royalty
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), no_image_data).await {
        Ok(response) => {
            println!("   No image initiation successful!");
            println!("     Social Media ID: {}", response.social_media_id);
            println!("     Token URI: {}", response.token_uri);

            // Verify the metadata contains fallback image
            if response.metadata.contains("QmDefaultSocialMediaImage") {
                println!("   Fallback image found in metadata");
            } else {
                println!("   Fallback image not found in metadata");
            }
        }
        Err(e) => {
            println!("   No image initiation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   All custom image tests completed successfully!");
    Ok(())
}

/// Test error cases for social media NFT minting
pub async fn test_social_media_error_cases() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing social media NFT minting error cases...");

    // Set up test environment for Pinata
    if std::env::var("PINATA_JWT").is_err() {
        println!("   PINATA_JWT not set, using test mode");
        unsafe {
            std::env::set_var("PINATA_JWT", "test_jwt");
        }
    }

    let config = TestConfig::from_env()?;
    let contract_service = ContractService::new(config.rpc_url, config.private_key, config.chain_id).await?;
    let wallet_address = contract_service.get_wallet_address().await;

    // Test with empty user ID (should fail)
    println!("   Testing with empty user ID...");
    let empty_user_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from(""),
        username: Arc::from("testuser"),
        display_name: Arc::from("Test User"),
        profile_image_url: Some(Arc::from("https://example.com/image.jpg")),
        follower_count: Some(1000),
        verified: true,
        access_token: Arc::from("test_token"),
        custom_image_url: None,
        royalty_bps: Some(500),
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), empty_user_data).await {
        Ok(_) => {
            println!("   Empty user ID should have failed!");
            return Err("Empty user ID was accepted when it should have been rejected".into());
        }
        Err(e) => {
            println!("   Empty user ID correctly rejected: {}", e);
        }
    }

    // Test with empty username (should fail)
    println!("   Testing with empty username...");
    let empty_username_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from("123456789"),
        username: Arc::from(""),
        display_name: Arc::from("Test User"),
        profile_image_url: Some(Arc::from("https://example.com/image.jpg")),
        follower_count: Some(1000),
        verified: true,
        access_token: Arc::from("test_token"),
        custom_image_url: None,
        royalty_bps: Some(500),
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), empty_username_data).await {
        Ok(_) => {
            println!("   Empty username should have failed!");
            return Err("Empty username was accepted when it should have been rejected".into());
        }
        Err(e) => {
            println!("   Empty username correctly rejected: {}", e);
        }
    }

    // Test with excessive royalty (should fail)
    println!("   Testing with excessive royalty...");
    let excessive_royalty_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::Twitter,
        user_id: Arc::from("123456789"),
        username: Arc::from("testuser"),
        display_name: Arc::from("Test User"),
        profile_image_url: Some(Arc::from("https://example.com/image.jpg")),
        follower_count: Some(1000),
        verified: true,
        access_token: Arc::from("test_token"),
        custom_image_url: None,
        royalty_bps: Some(1500), // 15% royalty (exceeds 10% max)
    };

    match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), excessive_royalty_data).await {
        Ok(_) => {
            println!("   Excessive royalty should have failed!");
            return Err("Excessive royalty was accepted when it should have been rejected".into());
        }
        Err(e) => {
            println!("   Excessive royalty correctly rejected: {}", e);
        }
    }

    println!("   All error case tests completed successfully!");
    Ok(())
}

/// Test connection and basic functionality
pub async fn test_connection() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing wallet and network connection...");

    // Set up test environment for Pinata
    if std::env::var("PINATA_JWT").is_err() {
        println!("   PINATA_JWT not set, using test mode");
        unsafe {
            std::env::set_var("PINATA_JWT", "test_jwt");
        }
    }

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

    println!("Connection test completed successfully!");
    Ok(())
}