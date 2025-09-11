const { ethers } = require('ethers');

async function checkEvents() {
  try {
    // Connect to Base Sepolia
    const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
    
    // Contract address
    const contractAddress = '0xf99c6514473ba9ef1c930837e1ff4eac19d2537b';
    
    // Event signature for CollectionCreated
    const eventSignature = 'CollectionCreated(uint256,address,string,string,string,uint256)';
    const eventTopic = ethers.id(eventSignature);
    
    console.log('Contract Address:', contractAddress);
    console.log('Event Topic:', eventTopic);
    console.log('Expected Topic: 0xea90375fa9f17993ad151c9bbda49610fe7c5c7f3bac5e4777b89d97a85937e1');
    
    // Get current block
    const currentBlock = await provider.getBlockNumber();
    console.log('Current Block:', currentBlock);
    
    // Check last 2000 blocks for events
    const fromBlock = Math.max(0, currentBlock - 2000);
    console.log(`Checking blocks ${fromBlock} to ${currentBlock}...`);
    
    const filter = {
      address: contractAddress,
      topics: [eventTopic],
      fromBlock: fromBlock,
      toBlock: currentBlock
    };
    
    const logs = await provider.getLogs(filter);
    console.log(`Found ${logs.length} CollectionCreated events:`);
    
    for (let i = 0; i < logs.length; i++) {
      const log = logs[i];
      console.log(`\nEvent ${i + 1}:`);
      console.log('  Block:', log.blockNumber);
      console.log('  Transaction:', log.transactionHash);
      console.log('  Topics:', log.topics);
      console.log('  Data length:', log.data.length);
    }
    
    // Also check for any events from our contract (any topic)
    const allFilter = {
      address: contractAddress,
      fromBlock: fromBlock,
      toBlock: currentBlock
    };
    
    const allLogs = await provider.getLogs(allFilter);
    console.log(`\nFound ${allLogs.length} total events from contract in last 1000 blocks`);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

checkEvents();
