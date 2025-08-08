use vertix_backend::tests::contract_tests::{
    test_nft_minting, test_create_collection, test_mint_nft_to_collection, test_connection,
    test_mint_social_media_nft, test_social_media_platforms, test_custom_image_minting, test_social_media_error_cases
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Vertix Backend Contract Test Runner");
    println!("=====================================\n");

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();
    let test_name = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match test_name {
        "connection" => {
            println!("Running connection test...");
            test_connection().await?;
        }
        "mint" => {
            println!("Running NFT minting test...");
            test_nft_minting().await?;
        }
        "create_collection" => {
            println!("Running create collection test...");
            test_create_collection().await?;
        }
        "mint_to_collection" => {
            println!("Running mint NFT to collection test...");
            test_mint_nft_to_collection().await?;
        }
        "social_media" => {
            println!("Running social media NFT minting test...");
            test_mint_social_media_nft().await?;
        }
        "social_media_platforms" => {
            println!("Running social media platforms test...");
            test_social_media_platforms().await?;
        }
        "custom_images" => {
            println!("Running custom image minting test...");
            test_custom_image_minting().await?;
        }
        "social_media_errors" => {
            println!("Running social media error cases test...");
            test_social_media_error_cases().await?;
        }
        "social_media_all" => {
            println!("Running all social media NFT tests...\n");

            println!("1. Social media NFT minting test...");
            test_mint_social_media_nft().await?;

            println!("\n2. Social media platforms test...");
            test_social_media_platforms().await?;

            println!("\n3. Custom image minting test...");
            test_custom_image_minting().await?;

            println!("\n4. Social media error cases test...");
            test_social_media_error_cases().await?;

            println!("\n✅ All social media NFT tests completed successfully!");
        }
        "all" => {
            println!("Running all tests...\n");

            println!("1. Connection test...");
            test_connection().await?;

            println!("\n2. NFT minting test...");
            test_nft_minting().await?;

            println!("\n3. Create collection test...");
            test_create_collection().await?;

            println!("\n4. Mint NFT to collection test...");
            test_mint_nft_to_collection().await?;

            println!("\n5. Social media NFT minting test...");
            test_mint_social_media_nft().await?;

            println!("\n6. Social media platforms test...");
            test_social_media_platforms().await?;

            println!("\n7. Custom image minting test...");
            test_custom_image_minting().await?;

            println!("\n8. Social media error cases test...");
            test_social_media_error_cases().await?;

            println!("\n✅ All tests completed successfully!");
        }
        _ => {
            println!("Unknown test: {}", test_name);
            println!("Available tests:");
            println!("  connection - Test wallet and network connection");
            println!("  mint - Test basic NFT minting");
            println!("  create_collection - Test collection creation");
            println!("  mint_to_collection - Test minting to collection");
            println!("  social_media - Test social media NFT minting");
            println!("  social_media_platforms - Test different social media platforms");
            println!("  custom_images - Test custom image minting");
            println!("  social_media_errors - Test error cases");
            println!("  social_media_all - Run all social media tests");
            println!("  all - Run all tests");
        }
    }

    Ok(())
}