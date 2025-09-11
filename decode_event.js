const { ethers } = require('ethers');

async function decodeEvent() {
  try {
    // Connect to Base Sepolia
    const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
    
    // Contract address and ABI for the CollectionCreated event
    const contractAddress = '0xf99c6514473ba9ef1c930837e1ff4eac19d2537b';
    const abi = [
      "event CollectionCreated(uint256 indexed collectionId, address indexed creator, string name, string symbol, string image, uint256 maxSupply)"
    ];
    
    const contract = new ethers.Contract(contractAddress, abi, provider);
    
    // Get the specific transaction
    const txHash = '0x1d13daa437ee8a4c310107349ca4d57e0b0cfb176b8bdcf351577e1e699e7c39';
    const receipt = await provider.getTransactionReceipt(txHash);
    
    console.log('Transaction Receipt:');
    console.log('  Block:', receipt.blockNumber);
    console.log('  Gas Used:', receipt.gasUsed.toString());
    console.log('  Status:', receipt.status);
    console.log('  Logs:', receipt.logs.length);
    
    // Find and decode our event
    for (let i = 0; i < receipt.logs.length; i++) {
      const log = receipt.logs[i];
      
      if (log.address.toLowerCase() === contractAddress.toLowerCase()) {
        console.log(`\nContract Event ${i}:`);
        console.log('  Topics:', log.topics);
        console.log('  Data:', log.data);
        console.log('  Data length:', log.data.length);
        
        try {
          const decodedLog = contract.interface.parseLog({
            topics: log.topics,
            data: log.data
          });
          
          console.log('\nDecoded Event:');
          console.log('  Event Name:', decodedLog.name);
          console.log('  Collection ID:', decodedLog.args.collectionId.toString());
          console.log('  Creator:', decodedLog.args.creator);
          console.log('  Name:', decodedLog.args.name);
          console.log('  Symbol:', decodedLog.args.symbol);
          console.log('  Image:', decodedLog.args.image);
          console.log('  Max Supply:', decodedLog.args.maxSupply.toString());
          
        } catch (decodeError) {
          console.log('  Decode Error:', decodeError.message);
        }
      }
    }
    
  } catch (error) {
    console.error('Error:', error);
  }
}

decodeEvent();
