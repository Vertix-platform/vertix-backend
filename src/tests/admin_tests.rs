use crate::infrastructure::contracts::admin_client::AdminContractClient;
use crate::infrastructure::contracts::config::{get_current_chain_config, get_private_key};
use crate::domain::models::AddSupportedNftContractRequest;

pub async fn test_admin_functionality() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing admin functionality...");

    // Get current chain configuration
    let chain_config = get_current_chain_config()?;

    // Initialize admin client
    let admin_client = AdminContractClient::new(
        chain_config.rpc_url.clone(),
        get_private_key()?,
        chain_config,
    ).await?;

    // Test adding supported NFT contract
    let add_contract_request = AddSupportedNftContractRequest {
        nft_contract: "0x1234567890123456789012345678901234567890".to_string().into(),
    };

    match admin_client.add_supported_nft_contract(add_contract_request).await {
        Ok(response) => {
            println!("✅ Admin functionality test passed!");
            println!("   NFT contract added successfully");
            println!("   Transaction: {}", response.transaction_hash);
        }
        Err(e) => {
            println!("❌ Admin functionality test failed: {}", e);
        }
    }

    Ok(())
}
