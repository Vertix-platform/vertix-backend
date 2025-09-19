use sha3::{Digest, Keccak256};

/// Calculate the keccak256 hash of an event signature
pub fn calculate_event_signature(event_signature: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(event_signature.as_bytes());
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result))
}

/// Common event signatures for Vertix contracts
pub mod event_signatures {
    use super::*;

    /// CollectionCreated event signature
    pub const COLLECTION_CREATED: &str = "CollectionCreated(uint256,address,string,string,string,uint256)";

    /// NFTMinted event signature
    pub const NFT_MINTED: &str = "NFTMinted(address,uint256,uint256,string,bytes32,address,uint96)";

    /// SocialMediaNFTMinted event signature
    pub const SOCIAL_MEDIA_NFT_MINTED: &str = "SocialMediaNFTMinted(address,uint256,string,string,bytes32,address,uint96)";

    /// NFTListed event signature
    pub const NFT_LISTED: &str = "NFTListed(address,uint256,uint256,string,bytes32,address,uint96)";


    /// Get the calculated signature for CollectionCreated
    pub fn collection_created() -> String {
        calculate_event_signature(COLLECTION_CREATED)
    }

    /// Get the calculated signature for NFTMinted
    pub fn nft_minted() -> String {
        calculate_event_signature(NFT_MINTED)
    }

    /// Get the calculated signature for SocialMediaNFTMinted
    pub fn social_media_nft_minted() -> String {
        calculate_event_signature(SOCIAL_MEDIA_NFT_MINTED)
    }

    /// Get the calculated signature for NFTListed
    pub fn nft_listed() -> String {
        calculate_event_signature(NFT_LISTED)
    }

    /// Get all known event signatures
    pub fn all_signatures() -> Vec<(String, &'static str)> {
        vec![
            (collection_created(), COLLECTION_CREATED),
            (nft_minted(), NFT_MINTED),
            (social_media_nft_minted(), SOCIAL_MEDIA_NFT_MINTED),
            (nft_listed(), NFT_LISTED),
        ]
    }
}

/// Event signature matcher that can handle different event structures
pub struct EventMatcher {
    known_signatures: Vec<(String, String)>, // (signature, event_name)
}

impl EventMatcher {
    /// Create a new event matcher with known signatures
    pub fn new() -> Self {
        let signatures = event_signatures::all_signatures();
        let known_signatures = signatures
            .into_iter()
            .map(|(sig, name)| (sig, name.to_string()))
            .collect();

        Self { known_signatures }
    }

    /// Add a custom event signature
    pub fn add_signature(&mut self, event_signature: &str) {
        let signature = calculate_event_signature(event_signature);
        self.known_signatures.push((signature, event_signature.to_string()));
    }

    /// Match an event signature to its name
    pub fn match_signature(&self, signature: &str) -> Option<&str> {
        self.known_signatures
            .iter()
            .find(|(sig, _)| sig == signature)
            .map(|(_, name)| name.as_str())
    }

    /// Get all known signatures
    pub fn get_signatures(&self) -> &Vec<(String, String)> {
        &self.known_signatures
    }

    /// Check if a signature is known
    pub fn is_known_signature(&self, signature: &str) -> bool {
        self.known_signatures.iter().any(|(sig, _)| sig == signature)
    }
}

impl Default for EventMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_signature_calculation() {
        let signature = calculate_event_signature("CollectionCreated(uint256,address,string,string,string,uint256)");
        assert_eq!(signature, "0xea90375fa9f17993ad151c9bbda49610fe7c5c7f3bac5e4777b89d97a85937e1");
    }

    #[test]
    fn test_event_matcher() {
        let mut matcher = EventMatcher::new();

        // Test known signatures
        assert!(matcher.is_known_signature("0xea90375fa9f17993ad151c9bbda49610fe7c5c7f3bac5e4777b89d97a85937e1"));
        assert!(matcher.is_known_signature("0xf223b61344ba5afacd4809990cbc46788d1166f1f02a8d9825ef806cfbe88a5c"));

        // Test signature matching
        let event_name = matcher.match_signature("0xea90375fa9f17993ad151c9bbda49610fe7c5c7f3bac5e4777b89d97a85937e1");
        assert_eq!(event_name, Some("CollectionCreated(uint256,address,string,string,string,uint256)"));

        // Test custom signature
        matcher.add_signature("CustomEvent(uint256,address)");
        let custom_sig = calculate_event_signature("CustomEvent(uint256,address)");
        assert!(matcher.is_known_signature(&custom_sig));
    }
}
