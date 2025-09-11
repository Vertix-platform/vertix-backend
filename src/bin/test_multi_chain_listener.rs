use dotenvy::dotenv;
use tracing::{info, error};
use tracing_subscriber;

use vertix_backend::infrastructure::db::postgres::init_pool;
use vertix_backend::infrastructure::workers::multi_chain_listener::MultiChainListener;
use vertix_backend::infrastructure::contracts::config::get_supported_chains;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Testing Multi-Chain Blockchain Listener");
    info!("==========================================");

    // Test 1: Check supported chains
    info!("Test 1: Checking supported chains...");
    match get_supported_chains() {
        Ok(chains) => {
            info!("Found {} supported chains:", chains.len());
            for chain in &chains {
                info!("   • {} (Chain ID: {})", chain.name, chain.chain_id);
                info!("     RPC: {}", chain.rpc_url);
                info!("     Type: {:?}", chain.chain_type);
                info!("     Contracts:");
                info!("       - VertixNFT: {:?}", chain.contract_addresses.vertix_nft);
                info!("       - VertixEscrow: {:?}", chain.contract_addresses.vertix_escrow);
                info!("       - VertixGovernance: {:?}", chain.contract_addresses.vertix_governance);
                info!("");
            }
        }
        Err(e) => {
            error!("Failed to get supported chains: {}", e);
            return Err(e.into());
        }
    }

    // Test 2: Initialize database connection
    info!("Test 2: Testing database connection...");
    let pool = match init_pool().await {
        Ok(pool) => {
            info!("Database connection successful");
            pool
        }
        Err(e) => {
            error!("Database connection failed: {}", e);
            return Err(e.into());
        }
    };

    // Test 3: Test database tables
    info!("Test 3: Testing database tables...");
    match sqlx::query("SELECT COUNT(*) FROM collections").fetch_one(&pool).await {
        Ok(_) => info!("Collections table accessible"),
        Err(e) => {
            error!("Collections table error: {}", e);
            return Err(e.into());
        }
    }

    match sqlx::query("SELECT COUNT(*) FROM nft_mint_events").fetch_one(&pool).await {
        Ok(_) => info!("NFT mint events table accessible"),
        Err(e) => {
            error!("NFT mint events table error: {}", e);
            return Err(e.into());
        }
    }

    match sqlx::query("SELECT COUNT(*) FROM collection_events").fetch_one(&pool).await {
        Ok(_) => info!("Collection events table accessible"),
        Err(e) => {
            error!("Collection events table error: {}", e);
            return Err(e.into());
        }
    }

    match sqlx::query("SELECT COUNT(*) FROM social_media_nft_events").fetch_one(&pool).await {
        Ok(_) => info!("Social media NFT events table accessible"),
        Err(e) => {
            error!("Social media NFT events table error: {}", e);
            return Err(e.into());
        }
    }

    // Test 4: Initialize multi-chain listener
    info!("Test 4: Testing multi-chain listener initialization...");
    match MultiChainListener::new(pool, tokio::time::Duration::from_secs(15)) {
        Ok(listener) => {
            info!("Multi-chain listener initialized successfully");
            info!("   Active chain IDs: {:?}", listener.get_active_chain_ids());
        }
        Err(e) => {
            error!("Multi-chain listener initialization failed: {}", e);
            return Err(e.into());
        }
    }

    info!("");
    info!("All tests passed! Multi-chain listener is ready to use.");
    info!("");
    info!("Next steps:");
    info!("   1. Start the backend: cargo run --bin main");
    info!("   2. Check logs for multi-chain connections");
    info!("   3. Test API endpoints for chain information");

    Ok(())
}
