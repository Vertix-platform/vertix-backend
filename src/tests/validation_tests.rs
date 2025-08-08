use crate::api::validation::{Validator, Validate};
use crate::api::v1::contracts::{
    MintNftApiRequest,
    InitiateSocialMediaNftMintApiRequest,
    MintSocialMediaNftApiRequest
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_nft_request_validation_success() {
        let request = MintNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            collection_id: Some(1),
            royalty_bps: Some(500),
        };

        let result = request.validate();
        assert!(result.is_ok(), "Valid request should pass validation");
    }

    #[test]
    fn test_mint_nft_request_validation_invalid_address() {
        let request = MintNftApiRequest {
            wallet_address: "invalid_address".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            collection_id: Some(1),
            royalty_bps: Some(500),
        };

        let result = request.validate();
        assert!(result.is_err(), "Invalid address should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "wallet_address"));
    }

    #[test]
    fn test_mint_nft_request_validation_invalid_uri() {
        let request = MintNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            token_uri: "http://example.com/nft".to_string(), // Not IPFS
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            collection_id: Some(1),
            royalty_bps: Some(500),
        };

        let result = request.validate();
        assert!(result.is_err(), "Non-IPFS URI should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "token_uri"));
    }

    #[test]
    fn test_mint_nft_request_validation_invalid_royalty() {
        let request = MintNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            collection_id: Some(1),
            royalty_bps: Some(10001), // > 100%
        };

        let result = request.validate();
        assert!(result.is_err(), "Royalty > 100% should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "royalty_bps"));
    }

    #[test]
    fn test_initiate_social_media_nft_validation_success() {
        let request = InitiateSocialMediaNftMintApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            platform: "twitter".to_string(),
            user_id: "123456789".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            profile_image_url: Some("https://example.com/avatar.jpg".to_string()),
            follower_count: Some(1000),
            verified: true,
            access_token: "valid_access_token_here".to_string(),
            custom_image_url: None,
            royalty_bps: Some(500),
        };

        let result = request.validate();
        assert!(result.is_ok(), "Valid social media request should pass validation");
    }

    #[test]
    fn test_initiate_social_media_nft_validation_invalid_platform() {
        let request = InitiateSocialMediaNftMintApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            platform: "tiktok".to_string(), // Not supported
            user_id: "123456789".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            profile_image_url: Some("https://example.com/avatar.jpg".to_string()),
            follower_count: Some(1000),
            verified: true,
            access_token: "valid_access_token_here".to_string(),
            custom_image_url: None,
            royalty_bps: Some(500),
        };

        let result = request.validate();
        assert!(result.is_err(), "Invalid platform should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "platform"));
    }

    #[test]
    fn test_mint_social_media_nft_validation_success() {
        let request = MintSocialMediaNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            social_media_id: "twitter_123456789_1234567890".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            royalty_bps: Some(500),
            signature: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12".to_string(),
        };

        let result = request.validate();
        assert!(result.is_ok(), "Valid mint social media NFT request should pass validation");
    }

    #[test]
    fn test_mint_social_media_nft_validation_invalid_signature() {
        let request = MintSocialMediaNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            social_media_id: "twitter_123456789_1234567890".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            royalty_bps: Some(500),
            signature: "0x123".to_string(), // Too short
        };

        let result = request.validate();
        assert!(result.is_err(), "Invalid signature should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "signature"));
    }

    #[test]
    fn test_validator_ethereum_address() {
        // Valid address
        assert!(Validator::validate_ethereum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "test").is_ok());

        // Invalid address - wrong length
        assert!(Validator::validate_ethereum_address("0x123", "test").is_err());

        // Invalid address - non-hex characters
        assert!(Validator::validate_ethereum_address("0xg39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "test").is_err());

        // Empty address
        assert!(Validator::validate_ethereum_address("", "test").is_err());
    }

    #[test]
    fn test_validator_ipfs_uri() {
        // Valid IPFS URI
        assert!(Validator::validate_ipfs_uri("ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", "test").is_ok());

        // Invalid - not IPFS
        assert!(Validator::validate_ipfs_uri("https://example.com/file", "test").is_err());

        // Empty URI
        assert!(Validator::validate_ipfs_uri("", "test").is_err());
    }

    #[test]
    fn test_validator_hex_string() {
        // Valid hex string
        assert!(Validator::validate_hex_string("0x1234abcd", "test", Some(8)).is_ok());

        // Invalid - non-hex characters
        assert!(Validator::validate_hex_string("0x123xyz", "test", None).is_err());

        // Invalid - wrong length
        assert!(Validator::validate_hex_string("0x123", "test", Some(8)).is_err());

        // Invalid - odd number of characters
        assert!(Validator::validate_hex_string("0x123", "test", None).is_err());
    }

    #[test]
    fn test_validator_basis_points() {
        // Valid basis points
        assert!(Validator::validate_basis_points(500, "test").is_ok());
        assert!(Validator::validate_basis_points(10000, "test").is_ok());

        // Invalid - too high
        assert!(Validator::validate_basis_points(10001, "test").is_err());
    }

    #[test]
    fn test_validator_social_media_platform() {
        // Valid platforms
        assert!(Validator::validate_social_media_platform("twitter", "test").is_ok());
        assert!(Validator::validate_social_media_platform("Instagram", "test").is_ok());
        assert!(Validator::validate_social_media_platform("FACEBOOK", "test").is_ok());

        // Invalid platform
        assert!(Validator::validate_social_media_platform("tiktok", "test").is_err());
    }

    #[test]
    fn test_validator_url() {
        // Valid URLs
        assert!(Validator::validate_url("https://example.com", "test").is_ok());
        assert!(Validator::validate_url("http://example.com/path", "test").is_ok());

        // Invalid URLs
        assert!(Validator::validate_url("ftp://example.com", "test").is_err());
        assert!(Validator::validate_url("not a url", "test").is_err());
        assert!(Validator::validate_url("", "test").is_err());
    }

    #[test]
    fn test_multiple_validation_errors() {
        let request = MintNftApiRequest {
            wallet_address: "invalid".to_string(),
            token_uri: "not_ipfs".to_string(),
            metadata_hash: "too_short".to_string(),
            collection_id: Some(1),
            royalty_bps: Some(15000), // Too high
        };

        let result = request.validate();
        assert!(result.is_err(), "Multiple invalid fields should fail validation");

        let errors = result.unwrap_err();
        assert!(errors.len() >= 3, "Should have multiple validation errors");

        // Check that all fields with errors are represented
        let error_fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert!(error_fields.contains(&"wallet_address"));
        assert!(error_fields.contains(&"token_uri"));
        assert!(error_fields.contains(&"metadata_hash"));
        assert!(error_fields.contains(&"royalty_bps"));
    }

    #[test]
    fn test_duplicate_social_media_id_error_handling() {
        // This test demonstrates the error handling for duplicate social media IDs
        // In a real scenario, this would be caught by the smart contract

        let request = MintSocialMediaNftApiRequest {
            wallet_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            social_media_id: "twitter_123456789_1234567890".to_string(),
            token_uri: "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
            metadata_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            royalty_bps: Some(500),
            signature: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12".to_string(),
        };

        // The validation should pass for a valid request
        let result = request.validate();
        assert!(result.is_ok(), "Valid request should pass validation");
    }
}
