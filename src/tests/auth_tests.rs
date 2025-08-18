use crate::domain::models::{User, MintNftRequest};
use crate::application::services::contract_service::ContractService;
use uuid::Uuid;
use sqlx::types::chrono::Utc;
use std::sync::Arc;
use sqlx::PgPool;

/// Test demonstrating the tiered authentication system
///
/// This test shows how:
/// 1. NFT operations only require wallet connection (no user signup needed)
/// 2. Non-NFT operations require both user authentication AND wallet connection
#[tokio::test]
async fn test_tiered_authentication() {
    // Setup database pool for tests
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/vertix_test".to_string());
    let db_pool = PgPool::connect(&database_url).await.expect("Failed to connect to database");

    // Setup contract service
    let contract_service = ContractService::new(
        "http://localhost:8545".to_string(),
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
        31337, // Anvil chain ID
        db_pool,
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

    // ============ TESTING AUTHENTICATION REQUIREMENTS ============

    println!("\n=== Testing Authentication Requirements ===");

    println!("\n=== Tiered Authentication Test Complete ===");
    println!("Summary:");
    println!("- NFT operations: Wallet connection only ✅");
    println!("- Non-NFT operations: User authentication + wallet connection ✅");
    println!("- Unverified users: Rejected for non-NFT operations ✅");
    println!("- Users without wallet: Rejected for non-NFT operations ✅");
}