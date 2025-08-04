use vertix_backend::tests::contract_tests::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Vertix Backend Contract Test Runner");
    println!("=====================================\n");

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        let test_name = &args[1];
        match test_name.as_str() {
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
            "mint_nft_to_collection" => {
                println!("Running mint NFT to collection test...");
                test_mint_nft_to_collection().await?;
            }

            _ => {
                println!("Unknown test: {}", test_name);
                println!("Available tests:");
                println!("  connection - Test wallet and network connection");
                println!("  mint       - Test NFT minting");
                println!("  create_collection - Test create collection");
                println!("  mint_nft_to_collection - Test mint NFT to collection");
                println!("  all        - Run all tests");
                return Ok(());
            }
        }
    } else {
        // Default: run all tests
        // run_all_tests().await?;
    }

    Ok(())
}