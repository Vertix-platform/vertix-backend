use sha3::{Digest, Keccak256};

fn main() {
    let event_signature = "CollectionCreated(uint256,address,string,string,string,uint256)";
    let mut hasher = Keccak256::new();
    hasher.update(event_signature.as_bytes());
    let result = hasher.finalize();
    let signature = format!("0x{}", hex::encode(result));
    println!("Event signature for '{}': {}", event_signature, signature);
}
