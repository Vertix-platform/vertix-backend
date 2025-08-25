use vertix_backend::tests::{
    contract_tests::{
        test_nft_minting, test_create_collection, test_mint_social_media_nft,
        test_list_nft, test_buy_nft, test_list_non_nft_asset, test_buy_non_nft_asset,
        test_cancel_nft_listing, test_cancel_non_nft_listing, test_chain_id_in_listing_responses,
        test_fee_extraction_from_events, test_confirm_transfer, test_raise_dispute, test_refund,
        test_mint_nft_to_collection, test_social_media_platforms, test_custom_image_minting, test_social_media_error_cases,
        test_get_all_collections, test_get_collection_by_id, test_get_collections_by_creator,
        test_list_social_media_nft, test_list_nft_for_auction,
        test_connection, test_multi_chain_config,
    },
    admin_tests::test_admin_functionality,
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
        "get_all_collections" => {
            println!("Running get all collections test...");
            test_get_all_collections().await?;
        }
        "get_collection_by_id" => {
            println!("Running get collection by id test...");
            test_get_collection_by_id().await?;
        }
        "get_collections_by_creator" => {
            println!("Running get collections by creator test...");
            test_get_collections_by_creator().await?;
        }
        "list_nft" => {
            println!("Running list NFT test...");
            test_list_nft().await?;
        }
        "list_non_nft_asset" => {
            println!("Running list non-NFT asset test...");
            test_list_non_nft_asset().await?;
        }
        "list_social_media_nft" => {
            println!("Running list social media NFT test...");
            test_list_social_media_nft().await?;
        }
        "list_nft_for_auction" => {
            println!("Running list NFT for auction test...");
            test_list_nft_for_auction().await?;
        }
        "buy_nft" => {
            println!("Running buy NFT test...");
            test_buy_nft().await?;
        }
        "buy_non_nft_asset" => {
            println!("Running buy non-NFT asset test...");
            test_buy_non_nft_asset().await?;
        }
        "cancel_nft_listing" => {
            println!("Running cancel NFT listing test...");
            test_cancel_nft_listing().await?;
        }
        "cancel_non_nft_listing" => {
            println!("Running cancel non-NFT listing test...");
            test_cancel_non_nft_listing().await?;
        }
        "chain_id_test" => {
            println!("Running chain ID in listing responses test...");
            test_chain_id_in_listing_responses().await?;
        }
        "fee_extraction_test" => {
            println!("Running fee extraction from events test...");
            test_fee_extraction_from_events().await?;
        }
        "confirm_transfer" => {
            println!("Running confirm transfer test...");
            test_confirm_transfer().await?;
        }
        "raise_dispute" => {
            println!("Running raise dispute test...");
            test_raise_dispute().await?;
        }
        "refund" => {
            println!("Running refund test...");
            test_refund().await?;
        }
        "admin" => {
            println!("Running admin functionality test...");
            test_admin_functionality().await?;
        }
        "multi_chain" => {
            println!("Running multi-chain configuration test...");
            test_multi_chain_config().await?;
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

            println!("\n9. Get all collections test...");
            test_get_all_collections().await?;

            println!("\n10. List NFT test...");
            test_list_nft().await?;

            println!("\n11. List non-NFT asset test...");
            test_list_non_nft_asset().await?;

            println!("\n12. List social media NFT test...");
            test_list_social_media_nft().await?;

            println!("\n13. Confirm transfer test...");
            test_confirm_transfer().await?;

            println!("\n14. Raise dispute test...");
            test_raise_dispute().await?;

            println!("\n15. Refund test...");
            test_refund().await?;

            println!("\n16. Admin functionality test...");
            test_admin_functionality().await?;

            println!("\n All tests completed successfully!");
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
            println!("  get_all_collections - Test getting all collections");
            println!("  get_collection_by_id - Test getting collection by ID");
            println!("  get_collections_by_creator - Test getting collections by creator");
            println!("  list_nft - Test listing an NFT for sale");
            println!("  list_non_nft_asset - Test listing a non-NFT asset for sale");
            println!("  list_social_media_nft - Test listing a social media NFT for sale");
            println!("  list_nft_for_auction - Test listing an NFT for auction");
            println!("  buy_nft - Test buying an NFT");
            println!("  buy_non_nft_asset - Test buying a non-NFT asset");
            println!("  cancel_nft_listing - Test canceling an NFT listing");
            println!("  cancel_non_nft_listing - Test canceling a non-NFT listing");
            println!("  chain_id_test - Test chain ID in listing responses");
            println!("  fee_extraction_test - Test fee extraction from contract events");
            println!("  confirm_transfer - Test confirm transfer functionality");
            println!("  raise_dispute - Test raise dispute functionality");
            println!("  refund - Test refund functionality");
            println!("  admin - Test admin functionality");
            println!("  multi_chain - Test multi-chain configuration");
            println!("  all - Run all tests");
        }
    }

    Ok(())
}