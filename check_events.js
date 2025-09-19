const { ethers } = require('ethers');

/**
 * Main function to check for events on the VertixNFT contract.
 * @dev This function connects to the Base Sepolia testnet, calculates the
 * correct event signatures (topics), and queries the blockchain for past events.
 */
async function checkEvents() {
  try {
    // === Part 1: Event Signature Calculation ===
    console.log('=== Calculating Correct Event Signatures ===');

    // VertixNFT Events
    const collectionCreatedSignature = 'CollectionCreated(uint256 indexed collectionId, address indexed creator, string name, string symbol, string image, uint256 maxSupply)';
    const nftMintedSignature = 'NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)';
    const socialMediaNftMintedSignature = 'SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)';

    // MarketplaceCore Events
    const nftListedSignature = 'NFTListed(uint256,address,address,uint256,uint256)';
    const nonNftListedSignature = 'NonNFTListed(uint256,address,uint8,string,uint256)';
    const nftBoughtSignature = 'NFTBought(uint256,address,uint256,uint256,address,uint256,address)';
    const nonNftBoughtSignature = 'NonNFTBought(uint256,address,uint256,uint256,uint256,address)';
    const nftListingCancelledSignature = 'NFTListingCancelled(uint256,address,bool)';
    const nonNftListingCancelledSignature = 'NonNFTListingCancelled(uint256,address,bool)';
    const listedForAuctionSignature = 'ListedForAuction(uint256,bool,bool)';

    // MarketplaceAuctions Events
    const nftAuctionStartedSignature = 'NFTAuctionStarted(uint256,address,uint256,uint24,uint256,address,uint256)';
    const nonNftAuctionStartedSignature = 'NonNFTAuctionStarted(uint256,address,uint256,uint24,uint256,string,uint8)';
    const bidPlacedSignature = 'BidPlaced(uint256,uint256,address,uint256,uint256)';
    const auctionEndedSignature = 'AuctionEnded(uint256,address,address,uint256,uint256)';

    // Generate the Keccak-256 hash for each signature using ethers.id()
    const collectionCreatedTopic = ethers.id(collectionCreatedSignature);
    const nftMintedTopic = ethers.id(nftMintedSignature);
    const socialMediaNftMintedTopic = ethers.id(socialMediaNftMintedSignature);
    const nftListedTopic = ethers.id(nftListedSignature);
    const nonNftListedTopic = ethers.id(nonNftListedSignature);
    const nftBoughtTopic = ethers.id(nftBoughtSignature);
    const nonNftBoughtTopic = ethers.id(nonNftBoughtSignature);
    const nftListingCancelledTopic = ethers.id(nftListingCancelledSignature);
    const nonNftListingCancelledTopic = ethers.id(nonNftListingCancelledSignature);
    const listedForAuctionTopic = ethers.id(listedForAuctionSignature);
    const nftAuctionStartedTopic = ethers.id(nftAuctionStartedSignature);
    const nonNftAuctionStartedTopic = ethers.id(nonNftAuctionStartedSignature);
    const bidPlacedTopic = ethers.id(bidPlacedSignature);
    const auctionEndedTopic = ethers.id(auctionEndedSignature);

    console.log('=== VertixNFT Events ===');
    console.log(`CollectionCreated Topic: ${collectionCreatedTopic}`);
    console.log(`NFTMinted Topic: ${nftMintedTopic}`);
    console.log(`SocialMediaNFTMinted Topic: ${socialMediaNftMintedTopic}`);

    console.log('\n=== MarketplaceCore Events ===');
    console.log(`NFTListed Topic: ${nftListedTopic}`);
    console.log(`NonNFTListed Topic: ${nonNftListedTopic}`);
    console.log(`NFTBought Topic: ${nftBoughtTopic}`);
    console.log(`NonNFTBought Topic: ${nonNftBoughtTopic}`);
    console.log(`NFTListingCancelled Topic: ${nftListingCancelledTopic}`);
    console.log(`NonNFTListingCancelled Topic: ${nonNftListingCancelledTopic}`);
    console.log(`ListedForAuction Topic: ${listedForAuctionTopic}`);

    console.log('\n=== MarketplaceAuctions Events ===');
    console.log(`NFTAuctionStarted Topic: ${nftAuctionStartedTopic}`);
    console.log(`NonNFTAuctionStarted Topic: ${nonNftAuctionStartedTopic}`);
    console.log(`BidPlaced Topic: ${bidPlacedTopic}`);
    console.log(`AuctionEnded Topic: ${auctionEndedTopic}`);

    console.log('\n=== Backend Event Signatures (for multi_chain_listener.rs) ===');
    console.log('// VertixNFT Events');
    console.log(`"${collectionCreatedTopic}" => {`);
    console.log(`"${nftMintedTopic}" => {`);
    console.log(`"${socialMediaNftMintedTopic}" => {`);
    console.log('// MarketplaceCore Events');
    console.log(`"${nftListedTopic}" => {`);
    console.log(`"${nonNftListedTopic}" => {`);
    console.log(`"${nftBoughtTopic}" => {`);
    console.log(`"${nonNftBoughtTopic}" => {`);
    console.log(`"${nftListingCancelledTopic}" => {`);
    console.log(`"${nonNftListingCancelledTopic}" => {`);
    console.log(`"${listedForAuctionTopic}" => {`);
    console.log('// MarketplaceAuctions Events');
    console.log(`"${nftAuctionStartedTopic}" => {`);
    console.log(`"${nonNftAuctionStartedTopic}" => {`);
    console.log(`"${bidPlacedTopic}" => {`);
    console.log(`"${auctionEndedTopic}" => {`);

    // === Part 2: Blockchain Interaction ===
    console.log('\n=== Connecting to Base Sepolia and Checking Events ===');

    // Connect to Base Sepolia
    const provider = new ethers.JsonRpcProvider('https://base-sepolia.g.alchemy.com/v2/oQT2pYTSsOMFt1tRQsJRB0_wP4vSmRK8');
    
    // Contract address
    const contractAddress = '0xf99c6514473ba9ef1c930837e1ff4eac19d2537b';

    console.log('Contract Address:', contractAddress);

    // Get current block
    const currentBlock = await provider.getBlockNumber();
    console.log('Current Block:', currentBlock);

    // Check historical blocks from contract deployment for CollectionCreated events
    const contractDeploymentBlock = 30375550;
    const chunkSize = 10; // Alchemy free tier limit
    const maxBlocksToCheck = 100000; // Check up to 100k blocks after deployment
    
    console.log(`Searching for CollectionCreated events in chunks of ${chunkSize} blocks (Alchemy free tier limit)...`);
    
    let totalCollectionEvents = 0;
    let totalAllEvents = 0;
    let fromBlock = contractDeploymentBlock;
    
    while (fromBlock < currentBlock && (fromBlock - contractDeploymentBlock) < maxBlocksToCheck) {
      const toBlock = Math.min(fromBlock + chunkSize - 1, currentBlock);
      console.log(`Checking blocks ${fromBlock} to ${toBlock}...`);
      
      try {
        // Define the event filter for CollectionCreated
        const collectionCreatedFilter = {
          address: contractAddress,
          topics: [collectionCreatedTopic],
          fromBlock: fromBlock,
          toBlock: toBlock
        };

        // Query for CollectionCreated events
        const collectionCreatedLogs = await provider.getLogs(collectionCreatedFilter);
        
        if (collectionCreatedLogs.length > 0) {
          console.log(`🎉 Found ${collectionCreatedLogs.length} CollectionCreated events in this chunk!`);
          totalCollectionEvents += collectionCreatedLogs.length;
          
          // Process CollectionCreated events
          for (const log of collectionCreatedLogs) {
            console.log('CollectionCreated Event:');
            console.log('  Block:', log.blockNumber);
            console.log('  Transaction:', log.transactionHash);
            console.log('  Data:', log.data);
            console.log('  Topics:', log.topics);
            console.log('---');
          }
        }

        // Also check for all events in this chunk
        const allEventsFilter = {
          address: contractAddress,
          topics: [
            [
              collectionCreatedTopic, nftMintedTopic, socialMediaNftMintedTopic,
              nftListedTopic, nonNftListedTopic, nftBoughtTopic, nonNftBoughtTopic,
              nftListingCancelledTopic, nonNftListingCancelledTopic, listedForAuctionTopic,
              nftAuctionStartedTopic, nonNftAuctionStartedTopic, bidPlacedTopic, auctionEndedTopic
            ]
          ],
          fromBlock: fromBlock,
          toBlock: toBlock
        };

        const allEventLogs = await provider.getLogs(allEventsFilter);
        if (allEventLogs.length > 0) {
          console.log(`  Found ${allEventLogs.length} total events in this chunk`);
          totalAllEvents += allEventLogs.length;
        }
        
        fromBlock = toBlock + 1;
        
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
        
      } catch (error) {
        console.log(`Error in chunk ${fromBlock}-${toBlock}:`, error.message);
        fromBlock = toBlock + 1;
        continue;
      }
    }
    
    console.log(`\n=== FINAL RESULTS ===`);
    console.log(`Total CollectionCreated events found: ${totalCollectionEvents}`);
    console.log(`Total events found: ${totalAllEvents}`);

    // Process and display the logs
    for (const log of allEventLogs) {
      console.log(`\nEvent Found:`);
      console.log('  Block Number:', log.blockNumber);
      console.log('  Transaction Hash:', log.transactionHash);

      // Determine which event it is based on the first topic
      switch (log.topics[0]) {
        // VertixNFT Events
        case collectionCreatedTopic:
          console.log('  Event Name: CollectionCreated');
          break;
        case nftMintedTopic:
          console.log('  Event Name: NFTMinted');
          break;
        case socialMediaNftMintedTopic:
          console.log('  Event Name: SocialMediaNFTMinted');
          break;
        // MarketplaceCore Events
        case nftListedTopic:
          console.log('  Event Name: NFTListed');
          break;
        case nonNftListedTopic:
          console.log('  Event Name: NonNFTListed');
          break;
        case nftBoughtTopic:
          console.log('  Event Name: NFTBought');
          break;
        case nonNftBoughtTopic:
          console.log('  Event Name: NonNFTBought');
          break;
        case nftListingCancelledTopic:
          console.log('  Event Name: NFTListingCancelled');
          break;
        case nonNftListingCancelledTopic:
          console.log('  Event Name: NonNFTListingCancelled');
          break;
        case listedForAuctionTopic:
          console.log('  Event Name: ListedForAuction');
          break;
        // MarketplaceAuctions Events
        case nftAuctionStartedTopic:
          console.log('  Event Name: NFTAuctionStarted');
          break;
        case nonNftAuctionStartedTopic:
          console.log('  Event Name: NonNFTAuctionStarted');
          break;
        case bidPlacedTopic:
          console.log('  Event Name: BidPlaced');
          break;
        case auctionEndedTopic:
          console.log('  Event Name: AuctionEnded');
          break;
        default:
          console.log('  Event Name: Unknown Event');
          console.log('  Topic:', log.topics[0]);
          break;
      }
    }

    if (allEventLogs.length === 0) {
        console.log('No events found in the specified block range.');
    }
    
  } catch (error) {
    console.error('Error:', error);
  }
}

// Execute the main function
checkEvents();