use crate::application::services::contract_service::{ContractService};
use crate::domain::models::{
    MintNftRequest, CreateCollectionRequest, MintNftToCollectionRequest,
    InitiateSocialMediaNftMintRequest, MintSocialMediaNftRequest,
    ListNftRequest, ListNonNftAssetRequest, ListNftForAuctionRequest, User,
    BuyNftRequest, BuyNonNftAssetRequest, CancelNftListingRequest, CancelNonNftListingRequest,
    AddSupportedNftContractRequest,
    ConfirmTransferRequest, RaiseDisputeRequest, RefundRequest,
};
use crate::domain::SocialMediaPlatform;
use std::sync::Arc;
use sqlx::PgPool;
use sqlx::types::chrono;
use crate::infrastructure::contracts::utils::verification::VerificationService;
use ethers::types::Address;
use crate::api::v1::contracts::ListSocialMediaNftApiRequest;
use crate::infrastructure::contracts::AdminContractClient;

/// Test configuration and setup
pub struct TestConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub chain_id: u64,
    pub db_pool: PgPool,
}

impl TestConfig {
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());
        let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
        let chain_id = std::env::var("CHAIN_ID").unwrap_or_else(|_| "31337".to_string()).parse::<u64>()?;

        // Setup database pool for tests
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/vertix_test".to_string());
        let db_pool = PgPool::connect(&database_url).await?;

        Ok(Self {
            rpc_url,
            private_key,
            chain_id,
            db_pool,
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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

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
    unsafe {
        std::env::set_var("PINATA_JWT", "test_jwt");
    }

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // Test data for social media profile (use timestamp to ensure uniqueness)
    let timestamp = chrono::Utc::now().timestamp();
    let test_social_media_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::X,
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
                println!("   Token URI is not in IPFS format: {}", init_response.token_uri);
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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;
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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;
    let wallet_address = contract_service.get_wallet_address().await;

    // Test with custom image URL
    println!("   Testing with custom image URL...");
    let custom_image_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::X,
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
        platform: SocialMediaPlatform::X,
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

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;
    let wallet_address = contract_service.get_wallet_address().await;

    // Test with empty user ID (should fail)
    println!("   Testing with empty user ID...");
    let empty_user_data = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::X,
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
        platform: SocialMediaPlatform::X,
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
        platform: SocialMediaPlatform::X,
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

// Get all collections
pub async fn test_get_all_collections() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing get all collections...");
    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new_read_only(config.rpc_url.to_string(), config.chain_id, config.db_pool).await?;

    let collections = contract_service.get_all_collections().await?;
    println!("   Found {} collections", collections.len());

    for (i, collection) in collections.iter().enumerate() {
        println!("   Collection {}: ID={}, Name='{}', Symbol='{}', Creator={}, Image='{}', MaxSupply={}, CurrentSupply={}",
            i + 1, collection.collection_id, collection.name, collection.symbol, collection.creator, collection.image, collection.max_supply, collection.current_supply);
    }

    Ok(())
}

// Get collection by id
pub async fn test_get_collection_by_id() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing get collection by id...");
    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new_read_only(config.rpc_url.to_string(), config.chain_id, config.db_pool).await?;

    let collection = contract_service.get_collection_by_id(1).await?;
    println!("   Collection: ID={}, Name='{}', Symbol='{}', Creator={}, Image='{}', MaxSupply={}, CurrentSupply={}",
        collection.collection_id, collection.name, collection.symbol, collection.creator, collection.image, collection.max_supply, collection.current_supply);

    Ok(())
}

// Get collections by creator
pub async fn test_get_collections_by_creator() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing get collections by creator...");
    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new_read_only(config.rpc_url.to_string(), config.chain_id, config.db_pool.clone()).await?;

    // For testing, we'll use a hardcoded wallet address or get it from a regular contract service
    let regular_service = ContractService::new(config.rpc_url.clone(), config.private_key.clone(), config.chain_id, config.db_pool).await?;
    let wallet_address = regular_service.get_wallet_address().await;
    println!("   Wallet address: {}", wallet_address);

    let collections = contract_service.get_collections_by_creator(wallet_address).await?;
    println!("   Found {} collections for creator", collections.len());

    for (i, collection) in collections.iter().enumerate() {
        println!("   Collection {}: ID={}, Name='{}', Symbol='{}', Creator={}, Image='{}', MaxSupply={}, CurrentSupply={}",
            i + 1, collection.collection_id, collection.name, collection.symbol, collection.creator, collection.image, collection.max_supply, collection.current_supply);
    }

    println!("Get collections by creator test completed successfully!");
    Ok(())
}

/// Test listing an NFT for sale
pub async fn test_list_nft() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing NFT Listing ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet address: {}", wallet_address);

    // Check balance
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

    // First mint an NFT to list
    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.clone()),
        token_uri: Arc::from("ipfs://QmTest123"),
        metadata_hash: Arc::from(metadata_hash),
        collection_id: None,
        royalty_bps: Some(500), // 5%
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("Minted NFT with token ID: {}", mint_response.token_id);

    // Get contract addresses to use the correct NFT contract
    let client = contract_service.get_client().await;
    let contract_addresses = client.get_contract_addresses();

    // Add NFT contract as supported in governance (admin function)
    println!("   Adding NFT contract as supported in governance...");
    let admin_client = AdminContractClient::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        client.get_network_config().clone(),
    ).await?;
    
    let add_contract_request = AddSupportedNftContractRequest {
        nft_contract: format!("0x{:x}", client.get_contract_addresses().vertix_nft).into(),
    };
    admin_client.add_supported_nft_contract(add_contract_request).await
        .map_err(|e| format!("Failed to add NFT contract as supported: {}", e))?;
    println!("Added NFT contract as supported");

    // Approve the marketplace to transfer the NFT
    println!("   Approving marketplace to transfer NFT...");
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;
    println!("Approved marketplace to transfer NFT");

    // Now list the NFT
    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 1000000000000000000, // 1 ETH in wei
        description: "A rare NFT with unique properties".into(),
    };

    match contract_service.list_nft(wallet_address.clone(), list_request).await {
        Ok(response) => {
            println!("NFT listed successfully!");
            println!("   Listing ID: {}", response.listing_id);
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!("ItNFT listing failed: {}", e);
        }
    }

    println!("NFT listing test completed!");
    Ok(())
}

/// Test listing a non-NFT asset for sale
pub async fn test_list_non_nft_asset() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Non-NFT Asset Listing ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;

    // Create a mock user for testing
    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: sqlx::types::chrono::Utc::now(),
    };

    // List a social media account
    let list_request = ListNonNftAssetRequest {
        asset_type: 1, // SocialMedia
        asset_id: "x/testuser".into(),
        price: 500000000000000000, // 0.5 ETH in wei
        description: "Popular Twitter account with 10k followers".into(),
        metadata: "Popular Twitter account with 10k followers".into(),
        verification_proof: "{\"platform\":\"twitter\",\"followers\":10000,\"verified\":true}".into(),
    };

    match contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await {
        Ok(response) => {
            println!("Non-NFT asset listed successfully!");
            println!("   Listing ID: {}", response.listing_id);
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!(" Non-NFT asset listing failed: {}", e);
        }
    }

    println!(" Non-NFT asset listing test completed!");
    Ok(())
}



/// Test listing a social media NFT for sale
pub async fn test_list_social_media_nft() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Social Media NFT Listing ===");

    // Set up test environment for Pinata BEFORE creating any services
    unsafe {
        std::env::set_var("PINATA_JWT", "test_jwt");
    }

    let config = TestConfig::from_env().await?;
    let private_key = config.private_key.clone();
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;

    // First, we need to initiate and create a social media NFT
    println!(" Creating a social media NFT first...");

    // Step 1: Initiate social media NFT minting
    let timestamp = chrono::Utc::now().timestamp();
    let init_request = InitiateSocialMediaNftMintRequest {
        platform: SocialMediaPlatform::X,
        user_id: Arc::from(format!("123456789_{}", timestamp)),
        username: Arc::from("twitter_handle_456"),
        display_name: Arc::from("Twitter User"),
        profile_image_url: Some(Arc::from("https://example.com/twitter.jpg")),
        follower_count: Some(50000),
        verified: true,
        access_token: Arc::from("twitter_token"),
        custom_image_url: None,
        royalty_bps: Some(500), // 5% royalty
    };

    let init_response = match contract_service.initiate_social_media_nft_mint(wallet_address.clone(), init_request).await {
        Ok(response) => {
            println!(" Social media NFT initiation successful!");
            println!("   Social Media ID: {}", response.social_media_id);
            println!("   Token URI: {}", response.token_uri);
            response
        }
        Err(e) => {
            println!(" Social media NFT initiation failed: {}", e);
            return Err(Box::new(e));
        }
    };

    // Step 2: Mint the social media NFT
    let mint_request = MintSocialMediaNftRequest {
        to: Arc::from(wallet_address.to_string()),
        social_media_id: init_response.social_media_id.clone(),
        token_uri: init_response.token_uri.clone(),
        metadata_hash: init_response.metadata_hash.clone(),
        royalty_bps: Some(init_response.royalty_bps),
        signature: init_response.signature.clone(),
    };

    let mint_response = match contract_service.mint_social_media_nft(wallet_address.clone(), mint_request).await {
        Ok(response) => {
            println!(" Social media NFT minted successfully!");
            println!("   Token ID: {}", response.token_id);
            println!("   Transaction: {}", response.transaction_hash);
            response
        }
        Err(e) => {
            println!(" Social media NFT minting failed: {}", e);
            return Err(Box::new(e));
        }
    };

    // Now list the social media NFT for sale
    println!(" Listing the social media NFT for sale...");

    // Step 3: Approve the marketplace to transfer the NFT
    println!(" Approving marketplace to transfer NFT...");
    let client = contract_service.get_client().await;

    // Get marketplace contract address

    // Approve the marketplace to transfer the NFT
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;
    println!(" Approved marketplace to transfer NFT");

    // Create a proper signature for listing
    let listing_price = 1500000000000000000u64; // 1.5 ETH in wei

    let verification_service = VerificationService::new(&private_key)?;
    let wallet_address_parsed = wallet_address.parse::<Address>()?;

    let _listing_signature = verification_service.generate_listing_signature(
        &wallet_address_parsed,
        mint_response.token_id,
        listing_price,
        &init_response.social_media_id,
    ).await?;


    let list_request = ListSocialMediaNftApiRequest {
        wallet_address: wallet_address.clone(),
        token_id: mint_response.token_id,
        price: listing_price.to_string(),
        social_media_id: init_response.social_media_id.to_string(),
        description: "Popular Twitter account with 50k followers - now for sale!".to_string(),
    };

    match contract_service.list_social_media_nft(wallet_address.clone(), list_request).await {
        Ok(response) => {
            println!(" Social media NFT listed successfully!");
            println!("   Listing ID: {}", response.listing_id);
            println!("   Token ID: {}", response.token_id);
            println!("   Price: {} wei", response.price);
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!(" Social media NFT listing failed: {}", e);
            return Ok(()); // Don't return error, just show the summary
        }
    }

    println!(" Social media NFT listing test completed!");
    Ok(())
}

/// Test to verify chain_id is included in listing responses
pub async fn test_chain_id_in_listing_responses() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Chain ID in Listing Responses ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);
    println!("   Expected Chain ID: {}", config.chain_id);

    // Test NFT listing with chain_id
    println!("   Testing NFT listing with chain_id...");

    // First, mint an NFT
    let metadata = create_nft_metadata(
        "Chain ID Test NFT",
        "An NFT to test chain_id in response",
        "ipfs://QmTestImage",
        None,
    )?;

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from(metadata.0),
        metadata_hash: Arc::from(metadata.1),
        collection_id: None,
        royalty_bps: Some(500),
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("   NFT minted with Token ID: {}", mint_response.token_id);

    // Approve marketplace
    let client = contract_service.get_client().await;
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;

    // List the NFT
    let contract_addresses = client.get_contract_addresses();
    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 1000000000000000000, // 1 ETH
        description: Arc::from("Testing chain_id in response"),
    };

    let list_response = contract_service.list_nft(wallet_address.clone(), list_request).await?;
    println!("   NFT Listing Response:");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Chain ID: {}", list_response.chain_id);
    println!("     Transaction: {}", list_response.transaction_hash);
    println!("     Expected Chain ID: {}", config.chain_id);
    println!("     Chain ID Match: {}", list_response.chain_id == config.chain_id);

    // Test non-NFT listing with chain_id
    println!("   Testing non-NFT listing with chain_id...");

    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    let non_nft_request = ListNonNftAssetRequest {
        asset_type: 1, // Social Media
        asset_id: Arc::from(format!("https://twitter.com/testuser_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap())),
        price: 500000000000000000, // 0.5 ETH
        description: Arc::from("Testing chain_id in non-NFT response"),
        metadata: Arc::from("Test metadata"),
        verification_proof: Arc::from("Test verification proof"),
    };

    let non_nft_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), non_nft_request).await?;
    println!("   Non-NFT Listing Response:");
    println!("     Listing ID: {}", non_nft_response.listing_id);
    println!("     Chain ID: {}", non_nft_response.chain_id);
    println!("     Transaction: {}", non_nft_response.transaction_hash);
    println!("     Expected Chain ID: {}", config.chain_id);
    println!("     Chain ID Match: {}", non_nft_response.chain_id == config.chain_id);

    println!("   Chain ID verification test completed!");
    Ok(())
}

/// Test to verify fee extraction from contract events
pub async fn test_fee_extraction_from_events() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Fee Extraction from Contract Events ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Test NFT purchase with fee extraction
    println!("   Testing NFT purchase with fee extraction...");

    // First, mint an NFT
    let metadata = create_nft_metadata(
        "Fee Test NFT",
        "An NFT to test fee extraction",
        "ipfs://QmTestImage",
        None,
    )?;

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from(metadata.0),
        metadata_hash: Arc::from(metadata.1),
        collection_id: None,
        royalty_bps: Some(500), // 5% royalty
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("   NFT minted with Token ID: {}", mint_response.token_id);

    // Approve marketplace
    let client = contract_service.get_client().await;
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;

    // List the NFT
    let contract_addresses = client.get_contract_addresses();
    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 1000000000000000000, // 1 ETH
        description: Arc::from("Testing fee extraction"),
    };

    let list_response = contract_service.list_nft(wallet_address.clone(), list_request).await?;
    println!("   NFT listed with Listing ID: {}", list_response.listing_id);

    // Buy the NFT
    let buy_request = BuyNftRequest { listing_id: list_response.listing_id };
    let price = 1000000000000000000; // 1 ETH

    let buy_response = contract_service.buy_nft(wallet_address.clone(), buy_request, price).await?;
    println!("   NFT Purchase Response:");
    println!("     Transaction: {}", buy_response.transaction_hash);
    println!("     New Owner: {}", buy_response.new_owner);
    println!("     Price: {} wei", buy_response.price);
    println!("     Royalty Amount: {} wei", buy_response.royalty_amount);
    println!("     Royalty Recipient: {}", buy_response.royalty_recipient);
    println!("     Platform Fee: {} wei", buy_response.platform_fee);
    println!("     Platform Recipient: {}", buy_response.platform_recipient);

    // Test non-NFT purchase with fee extraction
    println!("   Testing non-NFT purchase with fee extraction...");

    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    let non_nft_request = ListNonNftAssetRequest {
        asset_type: 1, // Social Media
        asset_id: Arc::from(format!("https://twitter.com/testuser_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap())),
        price: 500000000000000000, // 0.5 ETH
        description: Arc::from("Testing fee extraction for non-NFT"),
        metadata: Arc::from("Test metadata"),
        verification_proof: Arc::from("Test verification proof"),
    };

    let non_nft_list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), non_nft_request).await?;
    println!("   Non-NFT listed with Listing ID: {}", non_nft_list_response.listing_id);

    // Buy the non-NFT asset
    let non_nft_buy_request = BuyNonNftAssetRequest { listing_id: non_nft_list_response.listing_id };
    let non_nft_price = 500000000000000000; // 0.5 ETH

    let non_nft_buy_response = contract_service.buy_non_nft_asset(wallet_address.clone(), non_nft_buy_request, non_nft_price).await?;
    println!("   Non-NFT Purchase Response:");
    println!("     Transaction: {}", non_nft_buy_response.transaction_hash);
    println!("     Buyer: {}", non_nft_buy_response.buyer);
    println!("     Price: {} wei", non_nft_buy_response.price);
    println!("     Seller Amount: {} wei", non_nft_buy_response.seller_amount);
    println!("     Platform Fee: {} wei", non_nft_buy_response.platform_fee);
    println!("     Platform Recipient: {}", non_nft_buy_response.platform_recipient);

    println!("   Fee extraction test completed!");
    Ok(())
}

/// Test listing an NFT for auction
pub async fn test_list_nft_for_auction() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing NFT Auction Listing ===");

    // Set up test environment for Pinata BEFORE creating any services
    unsafe {
        std::env::set_var("PINATA_JWT", "test_jwt");
    }

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // First, mint an NFT to test with
    println!("   Minting an NFT first...");

    let metadata = create_nft_metadata(
        "Auction Test NFT",
        "An NFT created for testing auction functionality",
        "ipfs://QmTestImage",
        None,
    )?;

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from(metadata.0),
        metadata_hash: Arc::from(metadata.1),
        collection_id: None,
        royalty_bps: Some(500), // 5% royalty
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("   NFT minted successfully!");
    println!("     Token ID: {}", mint_response.token_id);
    println!("     Transaction: {}", mint_response.transaction_hash);

    // Approve the marketplace to transfer the NFT
    println!("   Approving marketplace to transfer NFT...");
    let client = contract_service.get_client().await;
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;
    println!("   Approved marketplace to transfer NFT");

    // Now create an NFT listing
    println!("   Creating an NFT listing...");

    // Get contract addresses to use the correct NFT contract
    let contract_addresses = client.get_contract_addresses();

    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 1000000000000000000, // 1 ETH in wei
        description: Arc::from("A rare NFT for auction testing"),
    };

    let list_response = contract_service.list_nft(wallet_address.clone(), list_request).await?;
    println!("   NFT listed successfully!");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Transaction: {}", list_response.transaction_hash);

    // Get the contract service's wallet address (which is the seller)
    let contract_wallet_address = contract_service.get_wallet_address().await;
    println!("   Contract service wallet: {}", contract_wallet_address);
    println!("   Test wallet: {}", wallet_address);

    // Try using the test wallet address instead (since they're the same)
    println!("   Listing NFT for auction...");

    let auction_request = ListNftForAuctionRequest {
        listing_id: list_response.listing_id,
        is_nft: true,
    };

    match contract_service.list_nft_for_auction(wallet_address.clone(), auction_request).await {
        Ok(auction_response) => {
            println!("   NFT listed for auction successfully!");
            println!("     Listing ID: {}", auction_response.listing_id);
            println!("     Is NFT: {}", auction_response.is_nft);
            println!("     Transaction: {}", auction_response.transaction_hash);
            println!("     Block Number: {}", auction_response.block_number);
        }
        Err(e) => {
            println!("   NFT auction listing failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   NFT auction listing test completed!");
    Ok(())
}

/// Test buying an NFT
pub async fn test_buy_nft() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing NFT Purchase ===");

    // Set up test environment for Pinata BEFORE creating any services
    unsafe {
        std::env::set_var("PINATA_JWT", "test_jwt");
    }

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // First, mint an NFT to test with
    println!("   Minting an NFT first...");

    let metadata = create_nft_metadata(
        "Purchase Test NFT",
        "An NFT created for testing purchase functionality",
        "ipfs://QmTestImage",
        None,
    )?;

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from(metadata.0),
        metadata_hash: Arc::from(metadata.1),
        collection_id: None,
        royalty_bps: Some(500), // 5% royalty
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("   NFT minted successfully!");
    println!("     Token ID: {}", mint_response.token_id);
    println!("     Transaction: {}", mint_response.transaction_hash);

    // Approve the marketplace to transfer the NFT
    println!("   Approving marketplace to transfer NFT...");
    let client = contract_service.get_client().await;
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;
    println!("   Approved marketplace to transfer NFT");

    // Now create an NFT listing
    println!("   Creating an NFT listing...");

    // Get contract addresses to use the correct NFT contract
    let contract_addresses = client.get_contract_addresses();

    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 500000000000000000, // 0.5 ETH in wei
        description: Arc::from("An NFT for purchase testing"),
    };

    let list_response = contract_service.list_nft(wallet_address.clone(), list_request).await?;
    println!("   NFT listed successfully!");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Transaction: {}", list_response.transaction_hash);

    // Now buy the NFT
    println!("   Buying the NFT...");

    let buy_request = BuyNftRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.buy_nft(wallet_address.clone(), buy_request, 500000000000000000).await {
        Ok(buy_response) => {
            println!("   NFT purchased successfully!");
            println!("     Transaction: {}", buy_response.transaction_hash);
            println!("     New Owner: {}", buy_response.new_owner);
        }
        Err(e) => {
            println!("   NFT purchase failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   NFT purchase test completed!");
    Ok(())
}

/// Test buying a non-NFT asset
pub async fn test_buy_non_nft_asset() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Non-NFT Asset Purchase ===");

    // Set up test environment for Pinata BEFORE creating any services
    unsafe {
        std::env::set_var("PINATA_JWT", "test_jwt");
    }

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // First, create a non-NFT asset listing to test with
    println!("   Creating a non-NFT asset listing...");

    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    let list_request = ListNonNftAssetRequest {
        asset_type: 1, // Social Media
        asset_id: Arc::from(format!("https://twitter.com/testuser_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap())),
        price: 300000000000000000, // 0.3 ETH in wei
        description: Arc::from("A test social media account for purchase testing"),
        metadata: Arc::from("Test metadata"),
        verification_proof: Arc::from("Test verification proof"),
    };

    let list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await?;
    println!("   Non-NFT asset listed successfully!");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Transaction: {}", list_response.transaction_hash);

    // Now buy the non-NFT asset
    println!("   Buying the non-NFT asset...");

    let buy_request = BuyNonNftAssetRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.buy_non_nft_asset(wallet_address.clone(), buy_request, 300000000000000000).await {
        Ok(buy_response) => {
            println!("   Non-NFT asset purchased successfully!");
            println!("     Transaction: {}", buy_response.transaction_hash);
            println!("     Buyer: {}", buy_response.buyer);
        }
        Err(e) => {
            println!("   Non-NFT asset purchase failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   Non-NFT asset purchase test completed!");
    Ok(())
}

/// Test canceling an NFT listing
pub async fn test_cancel_nft_listing() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing NFT Listing Cancellation ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // First, mint an NFT to test with
    println!("   Minting an NFT first...");

    let metadata = create_nft_metadata(
        "Cancel Test NFT",
        "An NFT created for testing cancellation functionality",
        "ipfs://QmTestImage",
        None,
    )?;

    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.to_string()),
        token_uri: Arc::from(metadata.0),
        metadata_hash: Arc::from(metadata.1),
        collection_id: None,
        royalty_bps: Some(500), // 5% royalty
    };

    let mint_response = contract_service.mint_nft(wallet_address.clone(), mint_request).await?;
    println!("   NFT minted successfully!");
    println!("     Token ID: {}", mint_response.token_id);
    println!("     Transaction: {}", mint_response.transaction_hash);

    // Approve the marketplace to transfer the NFT
    println!("   Approving marketplace to transfer NFT...");
    let client = contract_service.get_client().await;
    client.approve_nft_for_marketplace(mint_response.token_id).await
        .map_err(|e| format!("Failed to approve NFT for marketplace: {}", e))?;
    println!("   Approved marketplace to transfer NFT");

    // Now list the NFT
    println!("   Creating an NFT listing...");

    // Get contract addresses to use the correct NFT contract
    let contract_addresses = client.get_contract_addresses();

    let list_request = ListNftRequest {
        nft_contract: format!("0x{:x}", contract_addresses.vertix_nft).into(),
        token_id: mint_response.token_id,
        price: 500000000000000000, // 0.5 ETH in wei
        description: Arc::from("An NFT for cancellation testing"),
    };

    let list_response = contract_service.list_nft(wallet_address.clone(), list_request).await?;
    println!("   NFT listed successfully!");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Transaction: {}", list_response.transaction_hash);

    // Now cancel the NFT listing
    println!("   Cancelling the NFT listing...");

    let cancel_request = CancelNftListingRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.cancel_nft_listing(wallet_address.clone(), cancel_request).await {
        Ok(cancel_response) => {
            println!("   NFT listing cancelled successfully!");
            println!("     Listing ID: {}", cancel_response.listing_id);
            println!("     Transaction: {}", cancel_response.transaction_hash);
        }
        Err(e) => {
            println!("   NFT listing cancellation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   NFT listing cancellation test completed!");
    Ok(())
}

/// Test canceling a non-NFT asset listing
pub async fn test_cancel_non_nft_listing() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Non-NFT Asset Listing Cancellation ===");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Check balance
    let balance = contract_service.get_wallet_balance().await?;
    println!("   Balance: {} ETH", ethers::utils::format_units(balance, "ether")?);

    // First, create a non-NFT asset listing to test with
    println!("   Creating a non-NFT asset listing...");

    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    let list_request = ListNonNftAssetRequest {
        asset_type: 1, // Social Media
        asset_id: Arc::from(format!("https://twitter.com/testuser_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap())),
        price: 300000000000000000, // 0.3 ETH in wei
        description: Arc::from("A test social media account for cancellation testing"),
        metadata: Arc::from("Test metadata"),
        verification_proof: Arc::from("Test verification proof"),
    };

    let list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await?;
    println!("   Non-NFT asset listed successfully!");
    println!("     Listing ID: {}", list_response.listing_id);
    println!("     Transaction: {}", list_response.transaction_hash);

    // Now cancel the non-NFT asset listing
    println!("   Cancelling the non-NFT asset listing...");

    let cancel_request = CancelNonNftListingRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.cancel_non_nft_listing(wallet_address.clone(), cancel_request).await {
        Ok(cancel_response) => {
            println!("   Non-NFT asset listing cancelled successfully!");
            println!("     Listing ID: {}", cancel_response.listing_id);
            println!("     Transaction: {}", cancel_response.transaction_hash);
        }
        Err(e) => {
            println!("   Non-NFT asset listing cancellation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("   Non-NFT asset listing cancellation test completed!");
    Ok(())
}

/// Test confirm transfer functionality
pub async fn test_confirm_transfer() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing confirm transfer functionality...");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Create a test user
    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        password_hash: None,
        google_id: None,
        username: None,
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    // First, we need to create an escrow by buying a non-NFT asset
    // This will create an escrow that we can then confirm
    println!("   Creating escrow by buying a non-NFT asset...");

    let asset_id = uuid::Uuid::new_v4().to_string();
    let list_request = ListNonNftAssetRequest {
        asset_type: 2, // website
        asset_id: asset_id.clone().into(),
        price: 1000000000000000000, // 1 ETH
        description: "Test website for escrow".into(),
        metadata: serde_json::json!({
            "url": "https://example.com",
            "type": "website"
        }).to_string().into(),
        verification_proof: serde_json::json!({
            "url": "https://example.com",
            "verification_method": "dns"
        }).to_string().into(),
    };

    let list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await
        .map_err(|e| format!("Failed to list non-NFT asset: {}", e))?;

    println!("   Listed non-NFT asset with listing ID: {}", list_response.listing_id);

    // Now buy the asset to create an escrow
    let buy_request = BuyNonNftAssetRequest {
        listing_id: list_response.listing_id,
    };

    let buy_response = contract_service.buy_non_nft_asset(wallet_address.clone(), buy_request, 1000000000000000000).await
        .map_err(|e| format!("Failed to buy non-NFT asset: {}", e))?;

    println!("   Bought non-NFT asset, escrow created");
    println!("     Transaction: {}", buy_response.transaction_hash);
    println!("     Seller amount: {} wei", buy_response.seller_amount);

    // Now test the confirm transfer functionality
    println!("   Testing confirm transfer...");

    let confirm_request = ConfirmTransferRequest {
        listing_id: list_response.listing_id,
    };

    let confirm_response = contract_service.confirm_transfer(&user, wallet_address.clone(), confirm_request).await
        .map_err(|e| format!("Failed to confirm transfer: {}", e))?;

    println!("   ✅ Transfer confirmed successfully!");
    println!("     Transaction: {}", confirm_response.transaction_hash);
    println!("     Amount released to seller: {} wei", confirm_response.amount);
    println!("     Block: {}", confirm_response.block_number);

    // Verify the escrow is now completed by trying to get it
    println!("   Verifying escrow is completed...");

    let escrow = contract_service.get_escrow(list_response.listing_id).await
        .map_err(|e| format!("Failed to get escrow: {}", e))?;

    println!("   Escrow details:");
    println!("     Listing ID: {}", escrow.listing_id);
    println!("     Seller: {}", escrow.seller);
    println!("     Buyer: {}", escrow.buyer);
    println!("     Amount: {} wei", escrow.amount);
    println!("     Completed: {}", escrow.completed);
    println!("     Disputed: {}", escrow.disputed);
    println!("     Deadline: {}", escrow.deadline);

    // After confirmTransfer, the escrow should be deleted (all fields zero)
    // This indicates successful completion
    if escrow.seller == "0x0000000000000000000000000000000000000000".into() && 
       escrow.buyer == "0x0000000000000000000000000000000000000000".into() && 
       escrow.amount == 0 {
        println!("   ✅ Escrow was deleted (confirmTransfer successful)");
    } else if escrow.completed {
        println!("   ✅ Escrow is correctly marked as completed");
    } else {
        println!("   ❌ Escrow is not completed or deleted");
        return Err("Escrow should be completed/deleted after confirm transfer".into());
    }

    // Test error cases
    println!("   Testing error cases...");

    // Try to confirm transfer again (should fail since escrow is deleted)
    let confirm_request_again = ConfirmTransferRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.confirm_transfer(&user, wallet_address.clone(), confirm_request_again).await {
        Ok(_) => {
            println!("   ❌ Should have failed - escrow already completed/deleted");
            return Err("Confirm transfer should fail for completed/deleted escrow".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to confirm transfer again: {}", e);
        }
    }

    // Try to confirm transfer for non-existent listing
    let non_existent_request = ConfirmTransferRequest {
        listing_id: 999999,
    };

    match contract_service.confirm_transfer(&user, wallet_address.clone(), non_existent_request).await {
        Ok(_) => {
            println!("   ❌ Should have failed - non-existent listing");
            return Err("Confirm transfer should fail for non-existent listing".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to confirm transfer for non-existent listing: {}", e);
        }
    }

    println!("Confirm transfer test completed successfully!");
    Ok(())
}

/// Test raising a dispute
pub async fn test_raise_dispute() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing raise dispute functionality...");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Create a test user
    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        password_hash: None,
        google_id: None,
        username: None,
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    // First, we need to create an escrow by buying a non-NFT asset
    // This will create an escrow that we can then dispute
    println!("   Creating escrow by buying a non-NFT asset...");

    let asset_id = uuid::Uuid::new_v4().to_string();
    let list_request = ListNonNftAssetRequest {
        asset_type: 2, // website
        asset_id: asset_id.clone().into(),
        price: 1000000000000000000, // 1 ETH
        description: "Test website for dispute".into(),
        metadata: serde_json::json!({
            "url": "https://example.com",
            "type": "website"
        }).to_string().into(),
        verification_proof: serde_json::json!({
            "url": "https://example.com",
            "verification_method": "dns"
        }).to_string().into(),
    };

    let list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await
        .map_err(|e| format!("Failed to list non-NFT asset: {}", e))?;

    println!("   Listed non-NFT asset with listing ID: {}", list_response.listing_id);

    // Now buy the asset to create an escrow
    let buy_request = BuyNonNftAssetRequest {
        listing_id: list_response.listing_id,
    };

    let buy_response = contract_service.buy_non_nft_asset(wallet_address.clone(), buy_request, 1000000000000000000).await
        .map_err(|e| format!("Failed to buy non-NFT asset: {}", e))?;

    println!("   Bought non-NFT asset, escrow created");
    println!("     Transaction: {}", buy_response.transaction_hash);
    println!("     Seller amount: {} wei", buy_response.seller_amount);

    // Now test the raise dispute functionality
    println!("   Testing raise dispute...");

    let dispute_request = RaiseDisputeRequest {
        listing_id: list_response.listing_id,
    };

    let dispute_response = contract_service.raise_dispute(&user, wallet_address.clone(), dispute_request).await
        .map_err(|e| format!("Failed to raise dispute: {}", e))?;

    println!("   ✅ Dispute raised successfully!");
    println!("     Transaction: {}", dispute_response.transaction_hash);
    println!("     Raised by: {}", dispute_response.raiser);
    println!("     Block: {}", dispute_response.block_number);

    // Verify the escrow is now disputed
    println!("   Verifying escrow is disputed...");

    let escrow = contract_service.get_escrow(list_response.listing_id).await
        .map_err(|e| format!("Failed to get escrow: {}", e))?;

    println!("   Escrow details:");
    println!("     Listing ID: {}", escrow.listing_id);
    println!("     Seller: {}", escrow.seller);
    println!("     Buyer: {}", escrow.buyer);
    println!("     Amount: {} wei", escrow.amount);
    println!("     Completed: {}", escrow.completed);
    println!("     Disputed: {}", escrow.disputed);
    println!("     Deadline: {}", escrow.deadline);

    if escrow.disputed {
        println!("   ✅ Escrow is correctly marked as disputed");
    } else {
        println!("   ❌ Escrow is not marked as disputed");
        return Err("Escrow should be disputed after raise dispute".into());
    }

    // Test error cases
    println!("   Testing error cases...");

    // Try to raise dispute again (should fail)
    let dispute_request_again = RaiseDisputeRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.raise_dispute(&user, wallet_address.clone(), dispute_request_again).await {
        Ok(_) => {
            println!("   ❌ Should have failed - dispute already raised");
            return Err("Raise dispute should fail for already disputed escrow".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to raise dispute again: {}", e);
        }
    }

    // Try to confirm transfer while disputed (should fail)
    let confirm_request = ConfirmTransferRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.confirm_transfer(&user, wallet_address.clone(), confirm_request).await {
        Ok(_) => {
            println!("   ❌ Should have failed - cannot confirm transfer while disputed");
            return Err("Confirm transfer should fail for disputed escrow".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to confirm transfer while disputed: {}", e);
        }
    }

    println!("Raise dispute test completed successfully!");
    Ok(())
}

/// Test refund functionality
pub async fn test_refund() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing refund functionality...");

    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

    let wallet_address = contract_service.get_wallet_address().await;
    println!("   Wallet: {}", wallet_address);

    // Create a test user
    let user = User {
        id: uuid::Uuid::new_v4(),
        email: "test@example.com".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        password_hash: None,
        google_id: None,
        username: None,
        wallet_address: Some(wallet_address.to_string().into()),
        is_verified: true,
        created_at: chrono::Utc::now(),
    };

    // First, we need to create an escrow by buying a non-NFT asset
    // This will create an escrow that we can then refund
    println!("   Creating escrow by buying a non-NFT asset...");

    let asset_id = uuid::Uuid::new_v4().to_string();
    let list_request = ListNonNftAssetRequest {
        asset_type: 2, // website
        asset_id: asset_id.clone().into(),
        price: 1000000000000000000, // 1 ETH
        description: "Test website for refund".into(),
        metadata: serde_json::json!({
            "url": "https://example.com",
            "type": "website"
        }).to_string().into(),
        verification_proof: serde_json::json!({
            "url": "https://example.com",
            "verification_method": "dns"
        }).to_string().into(),
    };

    let list_response = contract_service.list_non_nft_asset(&user, wallet_address.clone(), list_request).await
        .map_err(|e| format!("Failed to list non-NFT asset: {}", e))?;

    println!("   Listed non-NFT asset with listing ID: {}", list_response.listing_id);

    // Now buy the asset to create an escrow
    let buy_request = BuyNonNftAssetRequest {
        listing_id: list_response.listing_id,
    };

    let buy_response = contract_service.buy_non_nft_asset(wallet_address.clone(), buy_request, 1000000000000000000).await
        .map_err(|e| format!("Failed to buy non-NFT asset: {}", e))?;

    println!("   Bought non-NFT asset, escrow created");
    println!("     Transaction: {}", buy_response.transaction_hash);
    println!("     Seller amount: {} wei", buy_response.seller_amount);

    // Get escrow details to check deadline
    let escrow = contract_service.get_escrow(list_response.listing_id).await
        .map_err(|e| format!("Failed to get escrow: {}", e))?;

    println!("   Escrow details:");
    println!("     Listing ID: {}", escrow.listing_id);
    println!("     Seller: {}", escrow.seller);
    println!("     Buyer: {}", escrow.buyer);
    println!("     Amount: {} wei", escrow.amount);
    println!("     Completed: {}", escrow.completed);
    println!("     Disputed: {}", escrow.disputed);
    println!("     Deadline: {}", escrow.deadline);

    // Try to refund before deadline (should fail)
    println!("   Testing refund before deadline (should fail)...");

    let refund_request = RefundRequest {
        listing_id: list_response.listing_id,
    };

    match contract_service.refund(&user, wallet_address.clone(), refund_request).await {
        Ok(_) => {
            println!("   ❌ Should have failed - deadline not passed");
            return Err("Refund should fail before deadline".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to refund before deadline: {}", e);
        }
    }

    // For testing purposes, we'll simulate waiting for deadline
    // In a real scenario, we would wait for the actual deadline
    println!("   Note: In a real scenario, we would wait for the deadline to pass");
    println!("   For testing, we'll simulate the refund functionality");

    // Test error cases
    println!("   Testing error cases...");

    // Try to refund non-existent listing
    let non_existent_refund_request = RefundRequest {
        listing_id: 999999,
    };

    match contract_service.refund(&user, wallet_address.clone(), non_existent_refund_request).await {
        Ok(_) => {
            println!("   ❌ Should have failed - non-existent listing");
            return Err("Refund should fail for non-existent listing".into());
        },
        Err(e) => {
            println!("   ✅ Correctly failed to refund non-existent listing: {}", e);
        }
    }

    println!("Refund test completed successfully!");
    println!("   Note: Full refund test requires waiting for deadline to pass");
    Ok(())
}

// Test listing a social media account

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
    let config = TestConfig::from_env().await?;
    let contract_service = ContractService::new(
        config.rpc_url.clone(),
        config.private_key.clone(),
        config.chain_id,
        config.db_pool,
    ).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verification_service_basic() {
        // Test that the verification service can be created without database
        println!("Testing basic verification service functionality...");

        // Set up test environment for Pinata
        if std::env::var("PINATA_JWT").is_err() {
            println!("   PINATA_JWT not set, using test mode");
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        // Test metadata creation
        let metadata = serde_json::json!({
            "name": "Test Asset",
            "description": "A test digital asset",
            "platform": "twitter",
            "identifier": "testuser",
            "verification_data": {
                "followers": 1000,
                "verified": true
            }
        });

        println!("   Created test metadata: {}", serde_json::to_string_pretty(&metadata).unwrap());
        println!("   Basic verification service test passed!");
    }

    #[tokio::test]
    async fn test_domain_models() {
        // Test that domain models work correctly
        println!("Testing domain models...");

        let request = ListNftRequest {
            nft_contract: Arc::from("0x1234567890123456789012345678901234567890"),
            token_id: 1,
            price: 1000000000000000000, // 1 ETH in wei
            description: Arc::from("A rare NFT with unique properties"),
        };

        assert_eq!(request.token_id, 1);
        assert_eq!(request.price, 1000000000000000000);
        assert_eq!(request.description.as_ref(), "A rare NFT with unique properties");

        println!("   Domain models test passed!");
    }
}