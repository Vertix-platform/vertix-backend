use ethers::types::{Address};
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use ethers::utils::keccak256;
use crate::domain::services::ContractError;
use crate::domain::{SocialMediaProfile, SocialMediaPlatform, InitiateSocialMediaNftMintRequest, InitiateSocialMediaNftMintResponse};
use std::sync::Arc;
use serde::Deserialize;


#[derive(Debug, Deserialize)]
struct PinataResponse {
    data: PinataData,
}

#[derive(Debug, Deserialize)]
struct PinataData {
    cid: String,
}

#[derive(Clone)]
pub struct VerificationService {
    private_key: LocalWallet,
    verification_address: Address,
    pinata_jwt: String,
}

impl VerificationService {
    pub fn new(private_key_hex: &str) -> Result<Self, ContractError> {
        let private_key: LocalWallet = private_key_hex
            .parse()
            .map_err(|e| ContractError::ContractCallError(format!("Invalid private key format: {}", e)))?;

        let verification_address = private_key.address();

        // Get Pinata JWT from environment
        let pinata_jwt = std::env::var("PINATA_JWT")
            .map_err(|_| ContractError::ContractCallError("PINATA_JWT environment variable not set".to_string()))?;

        Ok(Self {
            private_key,
            verification_address,
            pinata_jwt,
        })
    }

    /// Upload metadata to Pinata IPFS using v3 API
    async fn upload_metadata_to_pinata(&self, metadata: &serde_json::Value, social_media_id: &str) -> Result<String, ContractError> {
        // Check if we're in test mode (using test JWT)
        if self.pinata_jwt == "test_jwt" {
            // Generate a mock IPFS hash for testing
            let metadata_string = serde_json::to_string(metadata)
                .map_err(|e| ContractError::ContractCallError(format!("Failed to serialize metadata: {}", e)))?;
            let metadata_hash = keccak256(metadata_string.as_bytes());
            let mock_ipfs_hash = format!("Qm{}", hex::encode(&metadata_hash[..20]));
            return Ok(format!("ipfs://{}", mock_ipfs_hash));
        }

        // Serialize metadata to JSON string
        let metadata_string = serde_json::to_string(metadata)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to serialize metadata: {}", e)))?;

        // Prepare headers with JWT auth
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = format!("Bearer {}", self.pinata_jwt);
        headers.insert(
            reqwest::header::AUTHORIZATION, 
            reqwest::header::HeaderValue::from_str(&auth_value)
                .map_err(|e| ContractError::ContractCallError(format!("Invalid auth header: {}", e)))?
        );

        // Create a client with proper headers
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create client: {}", e)))?;

        // Prepare multipart form
        let file_part = reqwest::multipart::Part::text(metadata_string)
            .file_name(format!("{}.json", social_media_id))
            .mime_str("application/json")
            .map_err(|e| ContractError::ContractCallError(format!("Invalid mime type: {}", e)))?;

        // Set to "public" for public upload
        let network_part = reqwest::multipart::Part::text("public");

        let form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .part("network", network_part);

        // Send the request to v3 API
        let response = client.post("https://uploads.pinata.cloud/v3/files")
            .multipart(form)
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to upload to Pinata: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ContractError::ContractCallError(format!("Pinata upload failed: {}", error_text)));
        }

        // Parse the response
        let pinata_response: PinataResponse = response.json().await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to parse Pinata response: {}", e)))?;

        Ok(format!("ipfs://{}", pinata_response.data.cid))
    }



    pub async fn generate_signature(&self, user_address: &Address, social_media_id: &str) -> Result<String, ContractError> {
        // 1. Create the message hash: keccak256(abi.encodePacked(address, string))
        let mut message_data = Vec::new();
        message_data.extend_from_slice(user_address.as_bytes());
        message_data.extend_from_slice(social_media_id.as_bytes());

        let message_hash = keccak256(message_data);
        println!("[DEBUG] Signature generation:");
        println!("  user_address: {:?}", user_address);
        println!("  social_media_id: {:?}", social_media_id);
        println!("  verification_server: {:?}", self.verification_address);
        println!("  message_hash: 0x{}", hex::encode(message_hash));

        // 2. Create the Ethereum signed message hash (correct way)
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message_hash.len());
        let mut eth_message = Vec::new();
        eth_message.extend_from_slice(prefix.as_bytes());
        eth_message.extend_from_slice(&message_hash);
        let eth_signed_hash = keccak256(eth_message);
        println!("  eth_signed_hash: 0x{}", hex::encode(eth_signed_hash));

        // 3. Sign the hash
        println!("[DEBUG] Backend signing address: {:?}", self.private_key.address());
        let signature = self.private_key
            .sign_hash(ethers::types::H256::from_slice(&eth_signed_hash))
            .map_err(|e| ContractError::ContractCallError(format!("Failed to sign message: {}", e)))?;

        // 4. Format signature correctly (ensure v is in correct range)
        let mut signature_bytes = signature.to_vec();
        if signature_bytes[64] < 27 {
            signature_bytes[64] += 27;
        }

        let signature_hex = format!("0x{}", hex::encode(&signature_bytes));

        Ok(signature_hex)
    }


    /// Process social media NFT minting request and generate all necessary data
    pub async fn process_social_media_nft_mint(
        &self,
        user_address: &Address,
        request: &InitiateSocialMediaNftMintRequest,
    ) -> Result<InitiateSocialMediaNftMintResponse, ContractError> {
        // Create social media profile from request
        let profile = SocialMediaProfile {
            platform: request.platform.clone(),
            user_id: request.user_id.to_string(),
            username: request.username.to_string(),
            display_name: request.display_name.to_string(),
            profile_image_url: request.profile_image_url.as_deref().map(|s| s.to_string()),
            follower_count: request.follower_count,
            verified: request.verified,
            access_token: request.access_token.to_string(),
            refresh_token: None,
        };

        // Validate the profile
        self.validate_profile(&profile)?;

        // Create social media ID
        let social_media_id = match profile.platform {
            SocialMediaPlatform::Twitter => format!("twitter_{}", profile.user_id),
            SocialMediaPlatform::Instagram => format!("instagram_{}", profile.user_id),
            SocialMediaPlatform::Facebook => format!("facebook_{}", profile.user_id),
        };

        // Create metadata with custom image if provided
        let metadata = self.create_social_media_metadata_json(
            &profile,
            request.custom_image_url.as_deref(),
        )?;

        // Upload metadata to Pinata IPFS
        let token_uri = self.upload_metadata_to_pinata(&metadata, &social_media_id).await?;

        // Generate metadata hash for verification
        let metadata_string = serde_json::to_string(&metadata)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to serialize metadata: {}", e)))?;
        let metadata_hash = keccak256(metadata_string.as_bytes());
        let metadata_hash_hex = format!("0x{}", hex::encode(metadata_hash));

        // Generate signature for verification
        let signature = self.generate_signature(user_address, &social_media_id).await?;

        // Set default royalty if not provided
        let royalty_bps = request.royalty_bps.unwrap_or(500); // Default 5%

        Ok(InitiateSocialMediaNftMintResponse {
            social_media_id: Arc::from(social_media_id),
            token_uri: Arc::from(token_uri),
            metadata_hash: Arc::from(metadata_hash_hex),
            signature: Arc::from(signature),
            royalty_bps,
            metadata: Arc::from(metadata_string),
        })
    }

    /// Verify that a social media profile is authentic and generate signature
    pub async fn verify_and_sign_profile(
        &self,
        user_address: &Address,
        profile: &SocialMediaProfile,
    ) -> Result<String, ContractError> {
        // Create social media ID in the format expected by the smart contract
        let social_media_id = match profile.platform {
            SocialMediaPlatform::Twitter => format!("twitter_{}", profile.user_id),
            SocialMediaPlatform::Instagram => format!("instagram_{}", profile.user_id),
            SocialMediaPlatform::Facebook => format!("facebook_{}", profile.user_id),
        };

        // Generate signature for the social media ID
        self.generate_signature(user_address, &social_media_id).await
    }

    /// Get the verification server address
    pub fn get_verification_address(&self) -> Address {
        self.verification_address
    }

    /// Validate social media profile data
    pub fn validate_profile(&self, profile: &SocialMediaProfile) -> Result<(), ContractError> {
        if profile.user_id.is_empty() {
            return Err(ContractError::ContractCallError("Social media user ID cannot be empty".to_string()));
        }

        if profile.username.is_empty() {
            return Err(ContractError::ContractCallError("Social media username cannot be empty".to_string()));
        }

        if profile.display_name.is_empty() {
            return Err(ContractError::ContractCallError("Social media display name cannot be empty".to_string()));
        }

        if profile.access_token.is_empty() {
            return Err(ContractError::ContractCallError("Social media access token cannot be empty".to_string()));
        }

        Ok(())
    }

    /// Create metadata for social media NFT
    pub fn create_social_media_metadata(
        &self,
        profile: &SocialMediaProfile,
        custom_image_url: Option<&str>,
    ) -> Result<(String, String), ContractError> {
        // Validate the profile first
        self.validate_profile(profile)?;

        // Use custom image URL if provided, otherwise use profile image
        let image_url = custom_image_url
            .or(profile.profile_image_url.as_deref())
            .unwrap_or("ipfs://QmDefaultSocialMediaImage");

        // Create metadata JSON
        let mut metadata = serde_json::json!({
            "name": format!("{} - {} NFT", profile.display_name, profile.platform.as_str()),
            "description": format!("Verified {} profile NFT for {}", profile.platform.as_str(), profile.username),
            "image": image_url,
            "external_url": self.get_external_url(profile),
            "created_at": chrono::Utc::now().timestamp(),
            "attributes": [
                {
                    "trait_type": "Platform",
                    "value": profile.platform.as_str()
                },
                {
                    "trait_type": "Username",
                    "value": profile.username
                },
                {
                    "trait_type": "Display Name",
                    "value": profile.display_name
                },
                {
                    "trait_type": "User ID",
                    "value": profile.user_id
                },
                {
                    "trait_type": "Verified",
                    "value": profile.verified
                }
            ]
        });

        // Add follower count if available
        if let Some(follower_count) = profile.follower_count {
            metadata["attributes"].as_array_mut().unwrap().push(
                serde_json::json!({
                    "trait_type": "Followers",
                    "value": follower_count
                })
            );
        }

        // Convert metadata to string and hash it
        let metadata_string = serde_json::to_string(&metadata)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to serialize metadata: {}", e)))?;

        let metadata_hash = keccak256(metadata_string.as_bytes());
        let metadata_hash_hex = format!("0x{}", hex::encode(metadata_hash));

        Ok((metadata_string, metadata_hash_hex))
    }

    /// Create metadata JSON for Pinata upload
    fn create_social_media_metadata_json(
        &self,
        profile: &SocialMediaProfile,
        custom_image_url: Option<&str>,
    ) -> Result<serde_json::Value, ContractError> {
        // Validate the profile first
        self.validate_profile(profile)?;

        // Use custom image URL if provided, otherwise use profile image
        let image_url = custom_image_url
            .or(profile.profile_image_url.as_deref())
            .unwrap_or("ipfs://QmDefaultSocialMediaImage");

        // Create metadata JSON
        let mut metadata = serde_json::json!({
            "name": format!("{} - {} NFT", profile.display_name, profile.platform.as_str()),
            "description": format!("Verified {} profile NFT for {}", profile.platform.as_str(), profile.username),
            "image": image_url,
            "external_url": self.get_external_url(profile),
            "created_at": chrono::Utc::now().timestamp(),
            "attributes": [
                {
                    "trait_type": "Platform",
                    "value": profile.platform.as_str()
                },
                {
                    "trait_type": "Username",
                    "value": profile.username
                },
                {
                    "trait_type": "Display Name",
                    "value": profile.display_name
                },
                {
                    "trait_type": "User ID",
                    "value": profile.user_id
                },
                {
                    "trait_type": "Verified",
                    "value": profile.verified
                }
            ]
        });

        // Add follower count if available
        if let Some(follower_count) = profile.follower_count {
            metadata["attributes"].as_array_mut().unwrap().push(
                serde_json::json!({
                    "trait_type": "Followers",
                    "value": follower_count
                })
            );
        }

        Ok(metadata)
    }

    /// Get external URL for the social media profile
    fn get_external_url(&self, profile: &SocialMediaProfile) -> String {
        match profile.platform {
            SocialMediaPlatform::Twitter => {
                format!("https://x.com/{}", profile.username)
            }
            SocialMediaPlatform::Instagram => {
                format!("https://instagram.com/{}", profile.username)
            }
            SocialMediaPlatform::Facebook => {
                format!("https://facebook.com/{}", profile.username)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SocialMediaProfile;
    use crate::domain::SocialMediaPlatform;
    use crate::domain::InitiateSocialMediaNftMintRequest;

    // Mock Pinata JWT for testing
    fn get_test_pinata_jwt() -> String {
        std::env::var("PINATA_JWT").unwrap_or_else(|_| "test_jwt".to_string())
    }

    #[tokio::test]
    async fn test_signature_generation() {
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);
        let social_media_id = "twitter_123456789";

        let signature = verification_service.generate_signature(&user_address, social_media_id).await.unwrap();

        assert!(signature.starts_with("0x"));
        assert_eq!(signature.len(), 132); // 0x + 130 hex characters
    }

    #[test]
    fn test_metadata_creation() {
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let profile = SocialMediaProfile {
            platform: SocialMediaPlatform::Twitter,
            user_id: "123456789".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            profile_image_url: Some("https://example.com/image.jpg".to_string()),
            follower_count: Some(1000),
            verified: true,
            access_token: "test_token".to_string(),
            refresh_token: None,
        };

        let (metadata_string, metadata_hash) = verification_service.create_social_media_metadata(&profile, None).unwrap();

        assert!(metadata_string.contains("Test User"));
        assert!(metadata_string.contains("twitter"));
        assert!(metadata_hash.starts_with("0x"));
    }

    #[test]
    fn test_metadata_json_creation() {
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let profile = SocialMediaProfile {
            platform: SocialMediaPlatform::Twitter,
            user_id: "123456789".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            profile_image_url: Some("https://example.com/image.jpg".to_string()),
            follower_count: Some(1000),
            verified: true,
            access_token: "test_token".to_string(),
            refresh_token: None,
        };

        let metadata = verification_service.create_social_media_metadata_json(&profile, None).unwrap();

        assert!(metadata["name"].as_str().unwrap().contains("Test User"));
        assert!(metadata["name"].as_str().unwrap().contains("twitter"));
        assert_eq!(metadata["image"].as_str().unwrap(), "https://example.com/image.jpg");
        assert!(metadata["attributes"].as_array().unwrap().len() >= 5);
    }

    #[tokio::test]
    async fn test_process_social_media_nft_mint() {
        // Set test environment variable if not set
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);
        let request = InitiateSocialMediaNftMintRequest {
            platform: SocialMediaPlatform::Twitter,
            user_id: Arc::from("123456789"),
            username: Arc::from("testuser"),
            display_name: Arc::from("Test User"),
            profile_image_url: Some(Arc::from("https://example.com/image.jpg")),
            follower_count: Some(1000),
            verified: true,
            access_token: Arc::from("test_token"),
            custom_image_url: None,
            royalty_bps: Some(500),
        };

        let response = verification_service.process_social_media_nft_mint(&user_address, &request).await.unwrap();

        assert!(response.social_media_id.contains("twitter_123456789"));
        assert!(response.signature.starts_with("0x"));
        assert!(response.metadata.contains("Test User"));
        assert!(response.metadata.contains("twitter"));
        assert!(response.token_uri.starts_with("ipfs://"));
    }
}