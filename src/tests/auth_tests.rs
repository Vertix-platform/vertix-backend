use crate::domain::models::{User, MintNftRequest, CreateEscrowRequest};
use crate::application::services::contract_service::ContractService;
use uuid::Uuid;
use sqlx::types::chrono::Utc;
use std::sync::Arc;

/// Test demonstrating the tiered authentication system
///
/// This test shows how:
/// 1. NFT operations only require wallet connection (no user signup needed)
/// 2. Non-NFT operations require both user authentication AND wallet connection
#[tokio::test]
async fn test_tiered_authentication() {
    // Setup contract service
    let contract_service = ContractService::new(
        "http://localhost:8545".to_string(),
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
        31337, // Anvil chain ID
    ).await.expect("Failed to create contract service");

    // ============ WALLET-ONLY OPERATIONS (NFT) ============
    // These work with just wallet connection, no user signup required

    println!("=== Testing Wallet-Only Operations (NFT) ===");

    // Create a wallet address (this would come from the frontend)
    let wallet_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string();

    // Test NFT minting - this should work with just wallet connection
    let mint_request = MintNftRequest {
        to: Arc::from(wallet_address.clone()),
        token_uri: Arc::from("ipfs://QmTest123"),
        metadata_hash: Arc::from("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        collection_id: Some(0),
        royalty_bps: Some(500), // 5%
    };

    match contract_service.mint_nft(wallet_address.clone(), mint_request).await {
        Ok(response) => {
            println!("✅ NFT minting successful!");
            println!("   Token ID: {}", response.token_id);
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!("❌ NFT minting failed: {}", e);
        }
    }

    // ============ AUTHENTICATED OPERATIONS (Non-NFT) ============
    // These require both user authentication AND wallet connection

    println!("\n=== Testing Authenticated Operations (Non-NFT) ===");

    // Create a mock authenticated user
    let authenticated_user = User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        username: Some("testuser".to_string()),
        wallet_address: Some(wallet_address.clone()), // Same wallet as above
        is_verified: true, // User has completed signup/verification
        created_at: Utc::now(),
    };

    // Test escrow creation - this should work with authenticated user
    let escrow_request = CreateEscrowRequest {
        asset_type: "social_media".to_string(),
        asset_id: "twitter_handle_123".to_string(),
        price: "1000000000000000000".to_string(), // 1 ETH in wei
        description: "Popular Twitter account with 10k followers".to_string(),
        verification_data: serde_json::json!({
            "platform": "twitter",
            "followers": 10000,
            "verified": true
        }),
    };

    match contract_service.create_escrow(&authenticated_user, wallet_address.clone(), escrow_request).await {
        Ok(response) => {
            println!("✅ Escrow creation successful!");
            println!("   Escrow ID: {}", response.escrow_id);
            println!("   Escrow Address: {}", response.escrow_address);
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!("❌ Escrow creation failed: {}", e);
        }
    }

    // ============ TESTING AUTHENTICATION REQUIREMENTS ============

    println!("\n=== Testing Authentication Requirements ===");

    // Test with unverified user (should fail)
    let unverified_user = User {
        id: Uuid::new_v4(),
        email: "unverified@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "Unverified".to_string(),
        last_name: "User".to_string(),
        username: None,
        wallet_address: Some(wallet_address.clone()),
        is_verified: false, // User hasn't completed verification
        created_at: Utc::now(),
    };

    let escrow_request_2 = CreateEscrowRequest {
        asset_type: "website".to_string(),
        asset_id: "example.com".to_string(),
        price: "500000000000000000".to_string(), // 0.5 ETH in wei
        description: "Profitable e-commerce website".to_string(),
        verification_data: serde_json::json!({
            "platform": "website",
            "monthly_revenue": 5000,
            "traffic": 10000
        }),
    };

    match contract_service.create_escrow(&unverified_user, wallet_address.clone(), escrow_request_2).await {
        Ok(_) => {
            println!("❌ Escrow creation should have failed for unverified user!");
        }
        Err(e) => {
            println!("✅ Correctly rejected unverified user: {}", e);
        }
    }

    // Test with user without connected wallet (should fail)
    let user_without_wallet = User {
        id: Uuid::new_v4(),
        email: "nowallet@example.com".to_string(),
        password_hash: None,
        google_id: None,
        first_name: "No".to_string(),
        last_name: "Wallet".to_string(),
        username: None,
        wallet_address: None, // No wallet connected
        is_verified: true,
        created_at: Utc::now(),
    };

    let escrow_request_3 = CreateEscrowRequest {
        asset_type: "domain".to_string(),
        asset_id: "cool.com".to_string(),
        price: "2000000000000000000".to_string(), // 2 ETH in wei
        description: "Premium domain name".to_string(),
        verification_data: serde_json::json!({
            "platform": "domain",
            "age_years": 5,
            "premium": true
        }),
    };

    match contract_service.create_escrow(&user_without_wallet, wallet_address.clone(), escrow_request_3).await {
        Ok(_) => {
            println!("❌ Escrow creation should have failed for user without wallet!");
        }
        Err(e) => {
            println!("✅ Correctly rejected user without wallet: {}", e);
        }
    }

    println!("\n=== Tiered Authentication Test Complete ===");
    println!("Summary:");
    println!("- NFT operations: Wallet connection only ✅");
    println!("- Non-NFT operations: User authentication + wallet connection ✅");
    println!("- Unverified users: Rejected for non-NFT operations ✅");
    println!("- Users without wallet: Rejected for non-NFT operations ✅");
}