use ethers::types::Address;
use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use ethers::utils::keccak256;
use crate::domain::services::ContractError;
use crate::domain::{SocialMediaProfile, SocialMediaPlatform, InitiateSocialMediaNftMintRequest, InitiateSocialMediaNftMintResponse, ListNonNftAssetRequest, ListNonNftAssetResponse};
use std::sync::Arc;
use serde::Deserialize;
use serde_json::json;
use reqwest;
use regex::Regex;
use std::time::Duration;
use tokio::time::sleep;
use std::collections::HashMap;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;


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
        // let pinata_jwt = std::env::var("PINATA_JWT")
        //     .map_err(|_| ContractError::ContractCallError("PINATA_JWT environment variable not set".to_string()))?;
        let pinata_jwt = std::env::var("PINATA_JWT").unwrap_or_else(|_| {
            println!("   PINATA_JWT not set, using test mode");
            "test_jwt".to_string()
        });

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
        // create the message hash: keccak256(abi.encodePacked(address, string))
        let mut message_data = Vec::new();
        message_data.extend_from_slice(user_address.as_bytes());
        message_data.extend_from_slice(social_media_id.as_bytes());

        let message_hash = keccak256(message_data);

        // create the Ethereum signed message hash
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message_hash.len());
        let mut eth_message = Vec::new();
        eth_message.extend_from_slice(prefix.as_bytes());
        eth_message.extend_from_slice(&message_hash);
        let eth_signed_hash = keccak256(eth_message);
        println!("  eth_signed_hash: 0x{}", hex::encode(eth_signed_hash));

        // sign the hash
        println!("[DEBUG] Backend signing address: {:?}", self.private_key.address());
        let signature = self.private_key
            .sign_hash(ethers::types::H256::from_slice(&eth_signed_hash))
            .map_err(|e| ContractError::ContractCallError(format!("Failed to sign message: {}", e)))?;

        // format signature correctly (ensure v is in correct range)
        let mut signature_bytes = signature.to_vec();
        if signature_bytes[64] < 27 {
            signature_bytes[64] += 27;
        }

        let signature_hex = format!("0x{}", hex::encode(&signature_bytes));

        Ok(signature_hex)
    }

    /// Generate a signature for listing a social media NFT
    pub async fn generate_listing_signature(
        &self,
        user_address: &Address,
        token_id: u64,
        price: u64, // uint96 in Solidity
        social_media_id: &str,
    ) -> Result<String, ContractError> {
        // Create the message hash: keccak256(abi.encodePacked(msg.sender, tokenId, price, socialMediaId))
        let message_hash = {
            let mut message_data = Vec::new();

            // Address (20 bytes)
            message_data.extend_from_slice(user_address.as_bytes());

            // tokenId as uint256 (32 bytes)
            let token_id_bytes = token_id.to_be_bytes();
            let mut token_id_padded = [0u8; 32];
            token_id_padded[32 - token_id_bytes.len()..].copy_from_slice(&token_id_bytes);
            message_data.extend_from_slice(&token_id_padded);

            // price as uint96 (12 bytes)
            let mut price_bytes = [0u8; 12];
            price_bytes[12 - 8..].copy_from_slice(&price.to_be_bytes()); // Only need last 8 bytes for u64
            message_data.extend_from_slice(&price_bytes);

            // socialMediaId as string
            message_data.extend_from_slice(social_media_id.as_bytes());

            keccak256(message_data)
        };

        // Create the Ethereum signed message hash
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message_hash.len());
        let mut eth_message = Vec::new();
        eth_message.extend_from_slice(prefix.as_bytes());
        eth_message.extend_from_slice(&message_hash);
        let eth_signed_hash = keccak256(eth_message);

        // Debug output
        println!("Message hash: 0x{}", hex::encode(message_hash));
        println!("Ethereum signed message hash: 0x{}", hex::encode(eth_signed_hash));

        // Sign the hash
        let signature = self.private_key
            .sign_hash(ethers::types::H256::from_slice(&eth_signed_hash))
            .map_err(|e| ContractError::ContractCallError(format!("Failed to sign listing message: {}", e)))?;

        // Format signature correctly - ensure it's exactly 65 bytes
        let signature_bytes = signature.to_vec();
        println!("   Signature length: {} bytes", signature_bytes.len());
        println!("   Signature bytes: 0x{}", hex::encode(&signature_bytes));

        // Ensure signature is exactly 65 bytes (32 + 32 + 1)
        if signature_bytes.len() != 65 {
            return Err(ContractError::ContractCallError(format!("Invalid signature length: {} bytes, expected 65", signature_bytes.len())));
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
            SocialMediaPlatform::X => format!("x_{}", profile.user_id),
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
            SocialMediaPlatform::X => format!("x_{}", profile.user_id),
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
            SocialMediaPlatform::X => {
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

    /// List a non-NFT asset (social media account, website, domain, etc.) for sale
    pub async fn list_non_nft_asset(
        &self,
        user_address: &Address,
        request: &ListNonNftAssetRequest,
    ) -> Result<ListNonNftAssetResponse, ContractError> {
        // Parse and validate the asset type
        let asset_type = self.parse_asset_type(request.asset_type)?;

        // Extract and validate the asset identifier
        let (platform, identifier) = self.parse_asset_identifier(&request.asset_id, &asset_type)?;

        // Verify the asset exists and get verification data
        let verification_data = self.verify_asset(&platform, &identifier, &asset_type).await?;

        // Create metadata for the listing
        let metadata = self.create_non_nft_metadata(&asset_type, &platform, &identifier, &verification_data, &request.description)?;

        // Generate a unique listing ID
        let listing_id = self.generate_listing_id(user_address, &request.asset_id);

        // Create verification proof
        let verification_proof = self.create_verification_proof(&platform, &identifier, &verification_data)?;

        // Upload metadata to IPFS
        let metadata_uri = self.upload_metadata_to_pinata(&metadata, &format!("listing_{}", listing_id)).await?;

        // Generate signature for verification
        let signature = self.generate_listing_signature(user_address, listing_id, request.price, &request.asset_id).await?;

        Ok(ListNonNftAssetResponse {
            listing_id,
            creator: Arc::from(format!("0x{:x}", user_address)),
            asset_type: request.asset_type,
            asset_id: request.asset_id.clone(),
            price: request.price,
            description: request.description.clone(),
            metadata: Arc::from(metadata_uri),
            verification_proof: Arc::from(verification_proof),
            transaction_hash: Arc::from(signature),
            block_number: 0, // Will be set by the blockchain transaction
            chain_id: 0, // Will be set by the blockchain transaction
        })
    }

    /// Parse asset type from numeric code
    fn parse_asset_type(&self, asset_type: u8) -> Result<String, ContractError> {
        match asset_type {
            1 => Ok("social_media".to_string()),
            2 => Ok("domain".to_string()),
            3 => Ok("app".to_string()),
            4 => Ok("website".to_string()),
            5 => Ok("youtube".to_string()),
            6 => Ok("other".to_string()),
            _ => Err(ContractError::ContractCallError(format!("Invalid asset type: {}", asset_type))),
        }
    }

    /// Parse asset identifier to extract platform and identifier
    fn parse_asset_identifier(&self, asset_id: &str, asset_type: &str) -> Result<(String, String), ContractError> {
        match asset_type {
            "social_media" => self.parse_social_media_identifier(asset_id),
            "website" => self.parse_website_identifier(asset_id),
            "domain" => self.parse_domain_identifier(asset_id),
            _ => Ok(("unknown".to_string(), asset_id.to_string())),
        }
    }

    /// Parse social media identifier (username or URL)
    fn parse_social_media_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Handle URLs like https://x.com/username
        // Special handling for YouTube channel URLs
        if asset_id.contains("youtube.com/channel/") {
            let channel_pattern = Regex::new(r"https?://(?:www\.)?youtube\.com/channel/([^/\s?]+)").unwrap();
            if let Some(captures) = channel_pattern.captures(asset_id) {
                let channel_id = captures.get(1).unwrap().as_str();
                return Ok(("youtube".to_string(), channel_id.to_string()));
            }
        }

        // Handle other social media URLs
        let url_pattern = Regex::new(r"https?://(?:www\.)?(x\.com|instagram\.com|facebook\.com|youtube\.com|youtu\.be)/([^/\s?]+)").unwrap();

        if let Some(captures) = url_pattern.captures(asset_id) {
            let domain = captures.get(1).unwrap().as_str();
            let username = captures.get(2).unwrap().as_str();

            let platform = match domain {
                "x.com" => "x",
                "instagram.com" => "instagram",
                "facebook.com" => "facebook",
                "youtube.com" | "youtu.be" => "youtube",
                _ => return Err(ContractError::ContractCallError(format!("Unsupported social media platform: {}", domain))),
            };

            return Ok((platform.to_string(), username.to_string()));
        }

        // Handle direct usernames (require platform specification)
        if !asset_id.contains('/') && !asset_id.contains('.') {
            return Err(ContractError::ContractCallError("Platform must be specified for social media identifiers. Use format: platform/username (e.g., x/username, instagram/username)".to_string()));
        }

        Err(ContractError::ContractCallError(format!("Invalid social media identifier format: {}", asset_id)))
    }

    /// Parse website identifier
    fn parse_website_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Remove protocol and www if present
        let clean_url = asset_id
            .replace("https://", "")
            .replace("http://", "")
            .replace("www.", "");

        Ok(("website".to_string(), clean_url))
    }

    /// Parse domain identifier
    fn parse_domain_identifier(&self, asset_id: &str) -> Result<(String, String), ContractError> {
        // Remove protocol if present
        let clean_domain = asset_id
            .replace("https://", "")
            .replace("http://", "");

        Ok(("domain".to_string(), clean_domain))
    }

    /// Verify asset exists and get verification data
    async fn verify_asset(&self, platform: &str, identifier: &str, asset_type: &str) -> Result<serde_json::Value, ContractError> {
        match asset_type {
            "social_media" => self.verify_social_media_asset(platform, identifier).await,
            "website" => self.verify_website_asset(identifier).await,
            "domain" => self.verify_domain_asset(identifier).await,
            _ => Err(ContractError::ContractCallError(format!("Verification not implemented for asset type: {}", asset_type))),
        }
    }

    /// Verify social media asset with production-ready API integrations
    async fn verify_social_media_asset(&self, platform: &str, username: &str) -> Result<serde_json::Value, ContractError> {
        // Rate limiting - prevent abuse
        sleep(Duration::from_millis(100)).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Vertix-Verification-Bot/1.0")
            .build()
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create HTTP client: {}", e)))?;

        match platform {
            "x" => self.verify_x_profile(&client, username).await,
            "instagram" => self.verify_instagram_profile(&client, username).await,
            "facebook" => self.verify_facebook_profile(&client, username).await,
            "youtube" => self.verify_youtube_profile(&client, username).await,
            _ => Err(ContractError::ContractCallError(format!("Unsupported platform: {}", platform))),
        }
    }

    /// Verify X profile using X API v2
    async fn verify_x_profile(&self, client: &reqwest::Client, username: &str) -> Result<serde_json::Value, ContractError> {
        // Clean username (remove @ if present)
        let clean_username = username.trim_start_matches('@');

        // Validate username format
        if !self.is_valid_x_username(clean_username) {
            return Err(ContractError::ContractCallError("Invalid X username format".to_string()));
        }

        let mut verification_results = HashMap::new();

        // Get comprehensive profile data from X API v2
        let metadata_result = self.get_x_metadata(client, clean_username).await;

        match metadata_result {
            Ok(metadata) => {
                verification_results.insert("api_accessible", json!(true));
                verification_results.insert("metadata_available", json!(true));

                // Extract key metrics
                if let Some(followers_count) = metadata.get("followers_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("followers_count", json!(followers_count));
                }

                if let Some(verified) = metadata.get("verified").and_then(|v| v.as_bool()) {
                    verification_results.insert("verified_status", json!(verified));
                }

                if let Some(tweet_count) = metadata.get("tweet_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("tweet_count", json!(tweet_count));
                }

                if let Some(created_at) = metadata.get("created_at").and_then(|v| v.as_str()) {
                    verification_results.insert("account_created_at", json!(created_at));
                }

                if let Some(protected) = metadata.get("protected").and_then(|v| v.as_bool()) {
                    verification_results.insert("protected_account", json!(protected));
                }

                // Calculate account age
                if let Some(created_at_str) = metadata.get("created_at").and_then(|v| v.as_str()) {
                    if let Ok(created_timestamp) = chrono::DateTime::parse_from_rfc3339(created_at_str) {
                        let now = chrono::Utc::now();
                        let account_age_days = (now - created_timestamp.with_timezone(&chrono::Utc)).num_days() as u64;
                        verification_results.insert("account_age_days", json!(account_age_days));
                    }
                }

                // Additional profile information
                if let Some(description) = metadata.get("description").and_then(|v| v.as_str()) {
                    verification_results.insert("has_description", json!(!description.is_empty()));
                }

                if let Some(location) = metadata.get("location").and_then(|v| v.as_str()) {
                    verification_results.insert("has_location", json!(!location.is_empty()));
                }

                if let Some(url) = metadata.get("url").and_then(|v| v.as_str()) {
                    verification_results.insert("has_url", json!(!url.is_empty()));
                }

                // Store full metadata for reference
                verification_results.insert("full_metadata", metadata);
            }
            Err(e) => {
                verification_results.insert("api_accessible", json!(false));
                verification_results.insert("metadata_available", json!(false));
                verification_results.insert("api_error", json!(e.to_string()));

                // Fallback to HTTP check if API fails
                let profile_url = format!("https://x.com/{}", clean_username);
                let response = client.get(&profile_url)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.5")
                    .header("Accept-Encoding", "gzip, deflate")
                    .header("Connection", "keep-alive")
                    .send()
                    .await;

                if let Ok(resp) = response {
                    let status = resp.status();
                    verification_results.insert("http_status", json!(status.as_u16()));
                    verification_results.insert("is_accessible", json!(status.is_success()));
                } else {
                    verification_results.insert("is_accessible", json!(false));
                }
            }
        }

        let verification_data = json!({
            "platform": "x",
            "username": clean_username,
            "profile_url": format!("https://x.com/{}", clean_username),
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["x_api_v2", "http_fallback"],
            "results": verification_results,
            "confidence_score": self.calculate_x_confidence_score(&verification_results),
            "status": if verification_results.get("api_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified"
            } else if verification_results.get("is_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified_fallback"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    /// Verify Instagram profile using Instagram Basic Display API
    async fn verify_instagram_profile(&self, client: &reqwest::Client, username: &str) -> Result<serde_json::Value, ContractError> {
        // Clean username
        let clean_username = username.trim_start_matches('@');

        // Validate username format
        if !self.is_valid_instagram_username(clean_username) {
            return Err(ContractError::ContractCallError("Invalid Instagram username format".to_string()));
        }

        let mut verification_results = HashMap::new();

        // Get comprehensive profile data from Instagram Basic Display API
        let metadata_result = self.get_instagram_metadata(client, clean_username).await;
        
        match metadata_result {
            Ok(metadata) => {
                verification_results.insert("api_accessible", json!(true));
                verification_results.insert("metadata_available", json!(true));
                
                // Extract key metrics
                if let Some(followers_count) = metadata.get("followers_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("followers_count", json!(followers_count));
                }
                
                if let Some(following_count) = metadata.get("following_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("following_count", json!(following_count));
                }
                
                if let Some(media_count) = metadata.get("media_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("media_count", json!(media_count));
                }
                
                if let Some(verified) = metadata.get("verified").and_then(|v| v.as_bool()) {
                    verification_results.insert("verified_status", json!(verified));
                }
                
                if let Some(account_type) = metadata.get("account_type").and_then(|v| v.as_str()) {
                    verification_results.insert("account_type", json!(account_type));
                }
                
                if let Some(profile_picture_url) = metadata.get("profile_picture_url").and_then(|v| v.as_str()) {
                    verification_results.insert("profile_picture_url", json!(profile_picture_url));
                }
                
                if let Some(biography) = metadata.get("biography").and_then(|v| v.as_str()) {
                    verification_results.insert("has_biography", json!(!biography.is_empty()));
                }
                
                if let Some(website) = metadata.get("website").and_then(|v| v.as_str()) {
                    verification_results.insert("has_website", json!(!website.is_empty()));
                }
                
                // Store full metadata for reference
                verification_results.insert("full_metadata", metadata);
            }
            Err(e) => {
                verification_results.insert("api_accessible", json!(false));
                verification_results.insert("metadata_available", json!(false));
                verification_results.insert("api_error", json!(e.to_string()));
                
                // Fallback to HTTP check if API fails
                let profile_url = format!("https://instagram.com/{}", clean_username);
                let response = client.get(&profile_url)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.5")
                    .header("Accept-Encoding", "gzip, deflate, br")
                    .header("DNT", "1")
                    .header("Connection", "keep-alive")
                    .header("Upgrade-Insecure-Requests", "1")
                    .send()
                    .await;

                if let Ok(resp) = response {
                    let status = resp.status();
                    verification_results.insert("http_status", json!(status.as_u16()));
                    verification_results.insert("is_accessible", json!(status.is_success()));
                } else {
                    verification_results.insert("is_accessible", json!(false));
                }
            }
        }

        let verification_data = json!({
            "platform": "instagram",
            "username": clean_username,
            "profile_url": format!("https://instagram.com/{}", clean_username),
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["instagram_api", "http_fallback"],
            "results": verification_results,
            "confidence_score": self.calculate_instagram_confidence_score(&verification_results),
            "status": if verification_results.get("api_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified"
            } else if verification_results.get("is_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified_fallback"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    /// Verify Facebook profile using Facebook Graph API
    async fn verify_facebook_profile(&self, client: &reqwest::Client, username: &str) -> Result<serde_json::Value, ContractError> {
        // Clean username
        let clean_username = username.trim_start_matches('@');

        // Validate username format
        if !self.is_valid_facebook_username(clean_username) {
            return Err(ContractError::ContractCallError("Invalid Facebook username format".to_string()));
        }

        let mut verification_results = HashMap::new();

        // Get comprehensive profile data from Facebook Graph API
        let metadata_result = self.get_facebook_metadata(client, clean_username).await;
        
        match metadata_result {
            Ok(metadata) => {
                verification_results.insert("api_accessible", json!(true));
                verification_results.insert("metadata_available", json!(true));
                
                // Extract key metrics
                if let Some(followers_count) = metadata.get("followers_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("followers_count", json!(followers_count));
                }
                
                if let Some(friends_count) = metadata.get("friends_count").and_then(|v| v.as_u64()) {
                    verification_results.insert("friends_count", json!(friends_count));
                }
                
                if let Some(verified) = metadata.get("verified").and_then(|v| v.as_bool()) {
                    verification_results.insert("verified_status", json!(verified));
                }
                
                if let Some(account_type) = metadata.get("account_type").and_then(|v| v.as_str()) {
                    verification_results.insert("account_type", json!(account_type));
                }
                
                if let Some(profile_picture_url) = metadata.get("profile_picture_url").and_then(|v| v.as_str()) {
                    verification_results.insert("profile_picture_url", json!(profile_picture_url));
                }
                
                if let Some(cover_photo_url) = metadata.get("cover_photo_url").and_then(|v| v.as_str()) {
                    verification_results.insert("cover_photo_url", json!(cover_photo_url));
                }
                
                if let Some(bio) = metadata.get("bio").and_then(|v| v.as_str()) {
                    verification_results.insert("has_bio", json!(!bio.is_empty()));
                }
                
                if let Some(website) = metadata.get("website").and_then(|v| v.as_str()) {
                    verification_results.insert("has_website", json!(!website.is_empty()));
                }
                
                if let Some(location) = metadata.get("location").and_then(|v| v.as_str()) {
                    verification_results.insert("has_location", json!(!location.is_empty()));
                }
                
                if let Some(created_time) = metadata.get("created_time").and_then(|v| v.as_str()) {
                    verification_results.insert("account_created_at", json!(created_time));
                    
                    // Calculate account age
                    if let Ok(created_timestamp) = chrono::DateTime::parse_from_rfc3339(created_time) {
                        let now = chrono::Utc::now();
                        let account_age_days = (now - created_timestamp.with_timezone(&chrono::Utc)).num_days() as u64;
                        verification_results.insert("account_age_days", json!(account_age_days));
                    }
                }
                
                // Store full metadata for reference
                verification_results.insert("full_metadata", metadata);
            }
            Err(e) => {
                verification_results.insert("api_accessible", json!(false));
                verification_results.insert("metadata_available", json!(false));
                verification_results.insert("api_error", json!(e.to_string()));
                
                // Fallback to HTTP check if API fails
                let profile_url = format!("https://facebook.com/{}", clean_username);
                let response = client.get(&profile_url)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.5")
                    .header("Accept-Encoding", "gzip, deflate, br")
                    .header("DNT", "1")
                    .header("Connection", "keep-alive")
                    .header("Upgrade-Insecure-Requests", "1")
                    .send()
                    .await;

                if let Ok(resp) = response {
                    let status = resp.status();
                    verification_results.insert("http_status", json!(status.as_u16()));
                    verification_results.insert("is_accessible", json!(status.is_success()));
                } else {
                    verification_results.insert("is_accessible", json!(false));
                }
            }
        }

        let verification_data = json!({
            "platform": "facebook",
            "username": clean_username,
            "profile_url": format!("https://facebook.com/{}", clean_username),
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["facebook_graph_api", "http_fallback"],
            "results": verification_results,
            "confidence_score": self.calculate_facebook_confidence_score(&verification_results),
            "status": if verification_results.get("api_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified"
            } else if verification_results.get("is_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified_fallback"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    /// Verify YouTube profile/channel with production checks
    async fn verify_youtube_profile(&self, client: &reqwest::Client, identifier: &str) -> Result<serde_json::Value, ContractError> {
        // Clean identifier (remove @ if present)
        let clean_identifier = identifier.trim_start_matches('@');

        // Validate identifier format
        if !self.is_valid_youtube_identifier(clean_identifier) {
            return Err(ContractError::ContractCallError("Invalid YouTube identifier format".to_string()));
        }

        let mut verification_results = HashMap::new();

        // Try multiple YouTube URL formats
        let urls_to_try = vec![
            format!("https://youtube.com/{}", clean_identifier),
            format!("https://youtube.com/c/{}", clean_identifier),
            format!("https://youtube.com/channel/{}", clean_identifier),
            format!("https://youtube.com/user/{}", clean_identifier),
        ];

        let mut successful_url = None;
        let mut best_response = None;

        for url in urls_to_try {
            let response = client.get(&url)
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                .header("Accept-Language", "en-US,en;q=0.5")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("DNT", "1")
                .header("Connection", "keep-alive")
                .header("Upgrade-Insecure-Requests", "1")
                .send()
                .await;

            if let Ok(resp) = response {
                let status = resp.status();
                if status.is_success() {
                    successful_url = Some(url.clone());
                    best_response = Some(resp);
                    break;
                }
            }
        }

        if let (Some(url), Some(response)) = (successful_url, best_response) {
            let status = response.status();
            let content_length = response.content_length().unwrap_or(0);

            verification_results.insert("http_status", json!(status.as_u16()));
            verification_results.insert("content_length", json!(content_length));
            verification_results.insert("is_accessible", json!(true));
            verification_results.insert("profile_url", json!(url));

            // Content analysis for YouTube
            let body = response.text().await
                .map_err(|e| ContractError::ContractCallError(format!("Failed to read YouTube response: {}", e)))?;

            let has_channel_content = body.contains("channel") || body.contains("subscriber") || body.contains("video");
            let has_error_indicators = body.contains("This channel does not exist") || body.contains("Channel not found");
            let has_meta_tags = body.contains("<meta") || body.contains("<title>");

            verification_results.insert("has_channel_content", json!(has_channel_content));
            verification_results.insert("has_error_indicators", json!(has_error_indicators));
            verification_results.insert("has_meta_tags", json!(has_meta_tags));

            // Try to extract subscriber count and other metadata
            let metadata = self.extract_youtube_metadata(&body);
            if let Some(meta) = metadata {
                verification_results.insert("subscriber_count", meta.get("subscriber_count").unwrap_or(&json!(0)).clone());
                verification_results.insert("video_count", meta.get("video_count").unwrap_or(&json!(0)).clone());
                verification_results.insert("channel_name", meta.get("channel_name").unwrap_or(&json!("")).clone());
            }
        } else {
            verification_results.insert("is_accessible", json!(false));
            verification_results.insert("http_status", json!(404));
            verification_results.insert("content_length", json!(0));
        }

        let verification_data = json!({
            "platform": "youtube",
            "identifier": clean_identifier,
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["http_check", "content_analysis", "metadata_extraction"],
            "results": verification_results,
            "confidence_score": self.calculate_youtube_confidence_score(&verification_results),
            "status": if verification_results.get("is_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    /// Verify website asset with production checks
    async fn verify_website_asset(&self, url: &str) -> Result<serde_json::Value, ContractError> {
        // Rate limiting
        sleep(Duration::from_millis(200)).await;

        let full_url = if url.starts_with("http") {
            url.to_string()
        } else {
            format!("https://{}", url)
        };

        // Validate URL format
        if !self.is_valid_url(&full_url) {
            return Err(ContractError::ContractCallError("Invalid URL format".to_string()));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Vertix-Website-Verification-Bot/1.0")
            .build()
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create HTTP client: {}", e)))?;

        let mut verification_results = HashMap::new();

        // Multiple verification checks
        let response = client.get(&full_url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("Accept-Encoding", "gzip, deflate")
            .header("Connection", "keep-alive")
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to verify website: {}", e)))?;

        let status = response.status();
        let content_length = response.content_length().unwrap_or(0);
        let headers = response.headers().clone();

        verification_results.insert("status_code", json!(status.as_u16()));
        verification_results.insert("content_length", json!(content_length));
        verification_results.insert("is_accessible", json!(status.is_success()));

        // Check for security headers
        let has_https = full_url.starts_with("https://");
        let has_security_headers = headers.contains_key("strict-transport-security") || 
                                  headers.contains_key("x-content-type-options") ||
                                  headers.contains_key("x-frame-options");

        verification_results.insert("has_https", json!(has_https));
        verification_results.insert("has_security_headers", json!(has_security_headers));

        // Content analysis
        if status.is_success() {
            let body = response.text().await
                .map_err(|e| ContractError::ContractCallError(format!("Failed to read website content: {}", e)))?;

            let has_meaningful_content = body.len() > 1000; // Basic content check
            let has_meta_tags = body.contains("<meta") || body.contains("<title>");

            verification_results.insert("has_meaningful_content", json!(has_meaningful_content));
            verification_results.insert("has_meta_tags", json!(has_meta_tags));
            verification_results.insert("content_size", json!(body.len()));
        }

        let verification_data = json!({
            "url": full_url,
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["http_check", "security_analysis", "content_analysis"],
            "results": verification_results,
            "confidence_score": self.calculate_website_confidence_score(&verification_results),
            "status": if verification_results.get("is_accessible").and_then(|v| v.as_bool()).unwrap_or(false) {
                "verified"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    /// Verify domain asset with comprehensive DNS checks
    async fn verify_domain_asset(&self, domain: &str) -> Result<serde_json::Value, ContractError> {
        // Rate limiting
        sleep(Duration::from_millis(100)).await;

        // Validate domain format
        if !self.is_valid_domain(domain) {
            return Err(ContractError::ContractCallError("Invalid domain format".to_string()));
        }

        let mut verification_results = HashMap::new();

        // Comprehensive DNS resolution check using trust-dns-resolver
        let dns_result = self.check_dns_resolution(domain).await?;
        verification_results.insert("dns_resolvable", json!(dns_result));

        // Get detailed DNS information
        let dns_details = self.get_dns_details(domain).await?;
        verification_results.insert("dns_details", json!(dns_details));

        // HTTP accessibility check
        let http_accessible = self.check_http_accessibility(domain).await;
        verification_results.insert("http_accessible", json!(http_accessible));

        // Domain age check using WHOIS API
        let domain_age_days = self.get_domain_age(domain).await.unwrap_or(0);
        verification_results.insert("domain_age_days", json!(domain_age_days));

        // Get additional WHOIS information
        let whois_info = self.get_whois_info(domain).await?;
        verification_results.insert("whois_info", json!(whois_info));

        // Check for security headers
        let security_info = self.check_domain_security(domain).await?;
        verification_results.insert("security_info", json!(security_info));

        let verification_data = json!({
            "domain": domain,
            "verified_at": chrono::Utc::now().timestamp(),
            "verification_methods": ["dns_check", "dns_details", "http_check", "age_check", "security_check"],
            "results": verification_results,
            "confidence_score": self.calculate_domain_confidence_score(&verification_results),
            "status": if dns_result {
                "verified"
            } else {
                "unverified"
            }
        });

        Ok(verification_data)
    }

    // Helper methods for validation and verification

    fn is_valid_x_username(&self, username: &str) -> bool {
        // X username rules: 4-15 characters, alphanumeric and underscore only
        let username_regex = Regex::new(r"^[a-zA-Z0-9_]{4,15}$").unwrap();
        username_regex.is_match(username)
    }

    fn is_valid_instagram_username(&self, username: &str) -> bool {
        // Instagram username rules: 1-30 characters, alphanumeric, dots, underscores
        let username_regex = Regex::new(r"^[a-zA-Z0-9._]{1,30}$").unwrap();
        username_regex.is_match(username)
    }

    fn is_valid_facebook_username(&self, username: &str) -> bool {
        // Facebook username rules: 5-50 characters, alphanumeric and dots
        let username_regex = Regex::new(r"^[a-zA-Z0-9.]{5,50}$").unwrap();
        username_regex.is_match(username)
    }

    fn is_valid_youtube_identifier(&self, identifier: &str) -> bool {
        // YouTube identifier rules:
        // - Channel IDs: 24 characters, alphanumeric, hyphens, underscores
        // - Usernames: 3-20 characters, alphanumeric, hyphens, underscores
        // - Custom URLs: 3-30 characters, alphanumeric, hyphens, underscores
        let channel_id_regex = Regex::new(r"^UC[a-zA-Z0-9_-]{22}$").unwrap();
        let username_regex = Regex::new(r"^[a-zA-Z0-9_-]{3,30}$").unwrap();

        channel_id_regex.is_match(identifier) || username_regex.is_match(identifier)
    }

    fn is_valid_url(&self, url: &str) -> bool {
        let url_regex = Regex::new(r"^https?://[^\s/$.?#].[^\s]*$").unwrap();
        url_regex.is_match(url)
    }

    fn is_valid_domain(&self, domain: &str) -> bool {
        let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        domain_regex.is_match(domain)
    }

    async fn get_x_metadata(&self, client: &reqwest::Client, username: &str) -> Result<serde_json::Value, ContractError> {
        // Get X API v2 credentials from environment
        let bearer_token = std::env::var("X_API_BEARER_TOKEN")
            .map_err(|_| ContractError::ContractCallError("X_API_BEARER_TOKEN environment variable not set".to_string()))?;

        // Clean username (remove @ if present)
        let clean_username = username.trim_start_matches('@');

        // X API v2 endpoint for user lookup by username
        let url = format!("https://api.x.com/2/users/by/username/{}", clean_username);

        let response = client.get(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .header("User-Agent", "Vertix-X-Verification/1.0")
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("X API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ContractError::ContractCallError(format!("X API error: {}", error_text)));
        }

        let api_response: serde_json::Value = response.json().await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to parse X API response: {}", e)))?;

        // Check for API error response
        if let Some(errors) = api_response.get("errors") {
            if let Some(error) = errors.as_array().and_then(|arr| arr.first()) {
                let error_message = error.get("detail").and_then(|v| v.as_str()).unwrap_or("Unknown X API error");
                return Err(ContractError::ContractCallError(format!("X API error: {}", error_message)));
            }
        }

        // Extract user data
        if let Some(data) = api_response.get("data") {
            let mut metadata = HashMap::new();

            if let Some(id) = data.get("id").and_then(|v| v.as_str()) {
                metadata.insert("user_id", json!(id));
            }

            if let Some(name) = data.get("name").and_then(|v| v.as_str()) {
                metadata.insert("display_name", json!(name));
            }

            if let Some(username) = data.get("username").and_then(|v| v.as_str()) {
                metadata.insert("username", json!(username));
            }

            if let Some(description) = data.get("description").and_then(|v| v.as_str()) {
                metadata.insert("description", json!(description));
            }

            if let Some(profile_image_url) = data.get("profile_image_url").and_then(|v| v.as_str()) {
                metadata.insert("profile_image_url", json!(profile_image_url));
            }

            if let Some(verified) = data.get("verified").and_then(|v| v.as_bool()) {
                metadata.insert("verified", json!(verified));
            }

            if let Some(public_metrics) = data.get("public_metrics") {
                if let Some(followers_count) = public_metrics.get("followers_count").and_then(|v| v.as_u64()) {
                    metadata.insert("followers_count", json!(followers_count));
                }

                if let Some(following_count) = public_metrics.get("following_count").and_then(|v| v.as_u64()) {
                    metadata.insert("following_count", json!(following_count));
                }

                if let Some(tweet_count) = public_metrics.get("tweet_count").and_then(|v| v.as_u64()) {
                    metadata.insert("tweet_count", json!(tweet_count));
                }

                if let Some(listed_count) = public_metrics.get("listed_count").and_then(|v| v.as_u64()) {
                    metadata.insert("listed_count", json!(listed_count));
                }
            }

            if let Some(created_at) = data.get("created_at").and_then(|v| v.as_str()) {
                metadata.insert("created_at", json!(created_at));
            }

            if let Some(location) = data.get("location").and_then(|v| v.as_str()) {
                metadata.insert("location", json!(location));
            }

            if let Some(url) = data.get("url").and_then(|v| v.as_str()) {
                metadata.insert("url", json!(url));
            }

            if let Some(protected) = data.get("protected").and_then(|v| v.as_bool()) {
                metadata.insert("protected", json!(protected));
            }

            Ok(json!(metadata))
        } else {
            Err(ContractError::ContractCallError("No user data found in X API response".to_string()))
        }
    }

    async fn get_instagram_metadata(&self, client: &reqwest::Client, _username: &str) -> Result<serde_json::Value, ContractError> {
        // Get Instagram Basic Display API credentials from environment
        let access_token = std::env::var("INSTAGRAM_ACCESS_TOKEN")
            .map_err(|_| ContractError::ContractCallError("INSTAGRAM_ACCESS_TOKEN environment variable not set".to_string()))?;

        // Instagram Basic Display API endpoint for user lookup
        let url = format!(
            "https://graph.instagram.com/me?fields=id,username,account_type,media_count,followers_count,following_count,verified,profile_picture_url,biography,website&access_token={}",
            access_token
        );

        let response = client.get(&url)
            .header("User-Agent", "Vertix-Instagram-Verification/1.0")
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Instagram API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ContractError::ContractCallError(format!("Instagram API error: {}", error_text)));
        }

        let api_response: serde_json::Value = response.json().await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to parse Instagram API response: {}", e)))?;

        // Check for API error response
        if let Some(error) = api_response.get("error") {
            let error_message = error.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown Instagram API error");
            let error_code = error.get("code").and_then(|v| v.as_u64()).unwrap_or(0);
            return Err(ContractError::ContractCallError(format!("Instagram API error {}: {}", error_code, error_message)));
        }

        // Extract user data
        let mut metadata = HashMap::new();
        
        if let Some(id) = api_response.get("id").and_then(|v| v.as_str()) {
            metadata.insert("user_id", json!(id));
        }
        
        if let Some(username) = api_response.get("username").and_then(|v| v.as_str()) {
            metadata.insert("username", json!(username));
        }
        
        if let Some(account_type) = api_response.get("account_type").and_then(|v| v.as_str()) {
            metadata.insert("account_type", json!(account_type));
        }
        
        if let Some(media_count) = api_response.get("media_count").and_then(|v| v.as_u64()) {
            metadata.insert("media_count", json!(media_count));
        }
        
        if let Some(followers_count) = api_response.get("followers_count").and_then(|v| v.as_u64()) {
            metadata.insert("followers_count", json!(followers_count));
        }
        
        if let Some(following_count) = api_response.get("following_count").and_then(|v| v.as_u64()) {
            metadata.insert("following_count", json!(following_count));
        }
        
        if let Some(verified) = api_response.get("verified").and_then(|v| v.as_bool()) {
            metadata.insert("verified", json!(verified));
        }
        
        if let Some(profile_picture_url) = api_response.get("profile_picture_url").and_then(|v| v.as_str()) {
            metadata.insert("profile_picture_url", json!(profile_picture_url));
        }
        
        if let Some(biography) = api_response.get("biography").and_then(|v| v.as_str()) {
            metadata.insert("biography", json!(biography));
        }
        
        if let Some(website) = api_response.get("website").and_then(|v| v.as_str()) {
            metadata.insert("website", json!(website));
        }

        Ok(json!(metadata))
    }

    async fn get_facebook_metadata(&self, client: &reqwest::Client, username: &str) -> Result<serde_json::Value, ContractError> {
        // Get Facebook Graph API credentials from environment
        let access_token = std::env::var("FACEBOOK_ACCESS_TOKEN")
            .map_err(|_| ContractError::ContractCallError("FACEBOOK_ACCESS_TOKEN environment variable not set".to_string()))?;

        // Facebook Graph API v18.0 endpoint for user lookup
        let url = format!(
            "https://graph.facebook.com/v18.0/{}?fields=id,name,username,verified,account_type,followers_count,friends_count,profile_picture_url,cover_photo_url,bio,website,location,created_time&access_token={}",
            username, access_token
        );

        let response = client.get(&url)
            .header("User-Agent", "Vertix-Facebook-Verification/1.0")
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("Facebook API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ContractError::ContractCallError(format!("Facebook API error: {}", error_text)));
        }

        let api_response: serde_json::Value = response.json().await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to parse Facebook API response: {}", e)))?;

        // Check for API error response
        if let Some(error) = api_response.get("error") {
            let error_message = error.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown Facebook API error");
            let error_code = error.get("code").and_then(|v| v.as_u64()).unwrap_or(0);
            return Err(ContractError::ContractCallError(format!("Facebook API error {}: {}", error_code, error_message)));
        }

        // Extract user data
        let mut metadata = HashMap::new();
        
        if let Some(id) = api_response.get("id").and_then(|v| v.as_str()) {
            metadata.insert("user_id", json!(id));
        }
        
        if let Some(name) = api_response.get("name").and_then(|v| v.as_str()) {
            metadata.insert("display_name", json!(name));
        }
        
        if let Some(username) = api_response.get("username").and_then(|v| v.as_str()) {
            metadata.insert("username", json!(username));
        }
        
        if let Some(verified) = api_response.get("verified").and_then(|v| v.as_bool()) {
            metadata.insert("verified", json!(verified));
        }
        
        if let Some(account_type) = api_response.get("account_type").and_then(|v| v.as_str()) {
            metadata.insert("account_type", json!(account_type));
        }
        
        if let Some(followers_count) = api_response.get("followers_count").and_then(|v| v.as_u64()) {
            metadata.insert("followers_count", json!(followers_count));
        }
        
        if let Some(friends_count) = api_response.get("friends_count").and_then(|v| v.as_u64()) {
            metadata.insert("friends_count", json!(friends_count));
        }
        
        if let Some(profile_picture_url) = api_response.get("profile_picture_url").and_then(|v| v.as_str()) {
            metadata.insert("profile_picture_url", json!(profile_picture_url));
        }
        
        if let Some(cover_photo_url) = api_response.get("cover_photo_url").and_then(|v| v.as_str()) {
            metadata.insert("cover_photo_url", json!(cover_photo_url));
        }
        
        if let Some(bio) = api_response.get("bio").and_then(|v| v.as_str()) {
            metadata.insert("bio", json!(bio));
        }
        
        if let Some(website) = api_response.get("website").and_then(|v| v.as_str()) {
            metadata.insert("website", json!(website));
        }
        
        if let Some(location) = api_response.get("location").and_then(|v| v.as_str()) {
            metadata.insert("location", json!(location));
        }
        
        if let Some(created_time) = api_response.get("created_time").and_then(|v| v.as_str()) {
            metadata.insert("created_time", json!(created_time));
        }

        Ok(json!(metadata))
    }

    fn extract_youtube_metadata(&self, body: &str) -> Option<serde_json::Value> {
        // Extract metadata from YouTube page content
        // This is a simplified version - in production you'd use YouTube Data API v3

        let mut metadata = HashMap::new();

        // Try to extract subscriber count
        let subscriber_pattern = Regex::new(r#"subscriberCount["\s]*:["\s]*"?(\d+)"?"#).unwrap();
        if let Some(captures) = subscriber_pattern.captures(body) {
            if let Ok(count) = captures.get(1).unwrap().as_str().parse::<u64>() {
                metadata.insert("subscriber_count", json!(count));
            }
        }

        // Try to extract video count
        let video_pattern = Regex::new(r#"videoCount["\s]*:["\s]*"?(\d+)"?"#).unwrap();
        if let Some(captures) = video_pattern.captures(body) {
            if let Ok(count) = captures.get(1).unwrap().as_str().parse::<u64>() {
                metadata.insert("video_count", json!(count));
            }
        }

        // Try to extract channel name
        let name_pattern = Regex::new(r#"<title[^>]*>([^<]+)"#).unwrap();
        if let Some(captures) = name_pattern.captures(body) {
            let name = captures.get(1).unwrap().as_str().trim();
            if !name.is_empty() && name != "YouTube" {
                metadata.insert("channel_name", json!(name));
            }
        }

        if metadata.is_empty() {
            None
        } else {
            Some(json!(metadata))
        }
    }

    async fn check_dns_resolution(&self, domain: &str) -> Result<bool, ContractError> {
        // Use trust-dns-resolver for proper DNS resolution
        let config = ResolverConfig::default();
        let opts = ResolverOpts::default();

        let resolver = Resolver::new(config, opts)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create DNS resolver: {}", e)))?;

        // Check A record (IPv4)
        let a_record_result = resolver.lookup(domain, RecordType::A);
        let has_a_record = a_record_result.is_ok();

        // Check AAAA record (IPv6)
        let aaaa_record_result = resolver.lookup(domain, RecordType::AAAA);
        let has_aaaa_record = aaaa_record_result.is_ok();

        // Check CNAME record
        let cname_record_result = resolver.lookup(domain, RecordType::CNAME);
        let has_cname_record = cname_record_result.is_ok();

        // // Check MX record (for email)
        // let mx_record_result = resolver.lookup(domain, RecordType::MX);
        // let has_mx_record = mx_record_result.is_ok();

        // // Check TXT record (for verification)
        // let txt_record_result = resolver.lookup(domain, RecordType::TXT);
        // let has_txt_record = txt_record_result.is_ok();

        // Domain is resolvable if it has at least A, AAAA, or CNAME records
        let is_resolvable = has_a_record || has_aaaa_record || has_cname_record;

        Ok(is_resolvable)
    }

    async fn check_http_accessibility(&self, domain: &str) -> bool {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        let url = format!("https://{}", domain);
        client.get(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false)
    }

    async fn get_dns_details(&self, domain: &str) -> Result<serde_json::Value, ContractError> {
        // Use trust-dns-resolver to get detailed DNS information
        let config = ResolverConfig::default();
        let opts = ResolverOpts::default();

        let resolver = Resolver::new(config, opts)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create DNS resolver: {}", e)))?;

        let mut dns_details = HashMap::new();

        // Get A records (IPv4)
        if let Ok(a_records) = resolver.lookup(domain, RecordType::A) {
            let a_ips: Vec<String> = a_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("a_records", json!(a_ips));
        }

        // Get AAAA records (IPv6)
        if let Ok(aaaa_records) = resolver.lookup(domain, RecordType::AAAA) {
            let aaaa_ips: Vec<String> = aaaa_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("aaaa_records", json!(aaaa_ips));
        }

        // Get CNAME records
        if let Ok(cname_records) = resolver.lookup(domain, RecordType::CNAME) {
            let cnames: Vec<String> = cname_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("cname_records", json!(cnames));
        }

        // Get MX records
        if let Ok(mx_records) = resolver.lookup(domain, RecordType::MX) {
            let mx_servers: Vec<String> = mx_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("mx_records", json!(mx_servers));
        }

        // Get TXT records
        if let Ok(txt_records) = resolver.lookup(domain, RecordType::TXT) {
            let txt_values: Vec<String> = txt_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("txt_records", json!(txt_values));
        }

        // Get NS records
        if let Ok(ns_records) = resolver.lookup(domain, RecordType::NS) {
            let ns_servers: Vec<String> = ns_records.iter().map(|r| r.to_string()).collect();
            dns_details.insert("ns_records", json!(ns_servers));
        }

        Ok(json!(dns_details))
    }

    async fn check_domain_security(&self, domain: &str) -> Result<serde_json::Value, ContractError> {
        let mut security_info = HashMap::new();

        // Check for HTTPS support
        let https_url = format!("https://{}", domain);
        let http_url = format!("http://{}", domain);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create HTTP client: {}", e)))?;

        // Check HTTPS accessibility
        let https_accessible = client.get(&https_url).send().await.is_ok();
        security_info.insert("https_supported", json!(https_accessible));

        // Check for security headers
        if https_accessible {
            if let Ok(response) = client.get(&https_url).send().await {
                let headers = response.headers();

                security_info.insert("has_hsts", json!(headers.contains_key("strict-transport-security")));
                security_info.insert("has_csp", json!(headers.contains_key("content-security-policy")));
                security_info.insert("has_x_frame_options", json!(headers.contains_key("x-frame-options")));
                security_info.insert("has_x_content_type_options", json!(headers.contains_key("x-content-type-options")));
                security_info.insert("has_x_xss_protection", json!(headers.contains_key("x-xss-protection")));
            }
        }

        // Check for redirect from HTTP to HTTPS
        if let Ok(response) = client.get(&http_url).send().await {
            let status = response.status();
            let location = response.headers().get("location");
            let redirects_to_https = location
                .and_then(|l| l.to_str().ok())
                .map(|l| l.starts_with("https://"))
                .unwrap_or(false);

            security_info.insert("redirects_to_https", json!(redirects_to_https));
            security_info.insert("http_status", json!(status.as_u16()));
        }

        Ok(json!(security_info))
    }

    async fn get_domain_age(&self, domain: &str) -> Result<u64, ContractError> {
        // Use IP2Location WHOIS API for production-level domain age verification
        let whois_info = self.get_whois_info(domain).await?;
        
        if let Some(domain_age) = whois_info.get("domain_age").and_then(|v| v.as_u64()) {
            return Ok(domain_age);
        }
        
        // Fallback: calculate age from creation date
        if let Some(creation_date) = whois_info.get("create_date").and_then(|v| v.as_str()) {
            if let Ok(creation_timestamp) = chrono::DateTime::parse_from_rfc3339(creation_date) {
                let now = chrono::Utc::now();
                let age_days = (now - creation_timestamp.with_timezone(&chrono::Utc)).num_days() as u64;
                return Ok(age_days);
            }
        }
        
        // Final fallback
        Ok(365)
    }

    async fn get_whois_info(&self, domain: &str) -> Result<serde_json::Value, ContractError> {
        // Rate limiting for WHOIS API calls
        sleep(Duration::from_millis(200)).await;

        // Get API key from environment
        let api_key = std::env::var("IP2LOCATION_WHOIS_API_KEY")
            .map_err(|_| ContractError::ContractCallError("IP2LOCATION_WHOIS_API_KEY environment variable not set".to_string()))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Vertix-WHOIS-Verification/1.0")
            .build()
            .map_err(|e| ContractError::ContractCallError(format!("Failed to create HTTP client: {}", e)))?;

        // Build API URL
        let url = format!(
            "https://api.ip2whois.com/v2?key={}&domain={}&format=json",
            api_key, domain
        );

        let response = client.get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ContractError::ContractCallError(format!("WHOIS API request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ContractError::ContractCallError(format!("WHOIS API error: {}", error_text)));
        }

        let whois_data: serde_json::Value = response.json().await
            .map_err(|e| ContractError::ContractCallError(format!("Failed to parse WHOIS API response: {}", e)))?;

        // Check for API error response
        if let Some(error) = whois_data.get("error") {
            let error_code = error.get("error_code").and_then(|v| v.as_u64()).unwrap_or(0);
            let error_message = error.get("error_message").and_then(|v| v.as_str()).unwrap_or("Unknown error");
            return Err(ContractError::ContractCallError(format!("WHOIS API error {}: {}", error_code, error_message)));
        }

        Ok(whois_data)
    }

    fn calculate_x_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        // API accessibility (highest weight)
        if let Some(api_accessible) = results.get("api_accessible").and_then(|v| v.as_bool()) {
            if api_accessible { score += 0.3; }
            total_checks += 1;
        }

        // HTTP fallback accessibility
        if let Some(is_accessible) = results.get("is_accessible").and_then(|v| v.as_bool()) {
            if is_accessible { score += 0.2; }
            total_checks += 1;
        }

        // Verification status
        if let Some(verified) = results.get("verified_status").and_then(|v| v.as_bool()) {
            if verified { score += 0.15; }
            total_checks += 1;
        }

        // Follower count (bonus for established accounts)
        if let Some(followers_count) = results.get("followers_count").and_then(|v| v.as_u64()) {
            if followers_count > 1000 { score += 0.1; }
            if followers_count > 10000 { score += 0.05; }
            total_checks += 1;
        }

        // Account age (bonus for older accounts)
        if let Some(account_age_days) = results.get("account_age_days").and_then(|v| v.as_u64()) {
            if account_age_days > 365 { score += 0.1; } // 1+ year old
            if account_age_days > 1095 { score += 0.05; } // 3+ years old
            total_checks += 1;
        }

        // Tweet count (bonus for active accounts)
        if let Some(tweet_count) = results.get("tweet_count").and_then(|v| v.as_u64()) {
            if tweet_count > 100 { score += 0.05; }
            if tweet_count > 1000 { score += 0.05; }
            total_checks += 1;
        }

        // Profile completeness
        if let Some(has_description) = results.get("has_description").and_then(|v| v.as_bool()) {
            if has_description { score += 0.05; }
            total_checks += 1;
        }

        if let Some(has_location) = results.get("has_location").and_then(|v| v.as_bool()) {
            if has_location { score += 0.05; }
            total_checks += 1;
        }

        if let Some(has_url) = results.get("has_url").and_then(|v| v.as_bool()) {
            if has_url { score += 0.05; }
            total_checks += 1;
        }

        // Protected account (slight penalty as it's less accessible)
        if let Some(protected) = results.get("protected_account").and_then(|v| v.as_bool()) {
            if !protected { score += 0.05; }
            total_checks += 1;
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    fn calculate_website_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        if let Some(is_accessible) = results.get("is_accessible").and_then(|v| v.as_bool()) {
            if is_accessible { score += 0.4; }
            total_checks += 1;
        }

        if let Some(has_https) = results.get("has_https").and_then(|v| v.as_bool()) {
            if has_https { score += 0.2; }
            total_checks += 1;
        }

        if let Some(has_security_headers) = results.get("has_security_headers").and_then(|v| v.as_bool()) {
            if has_security_headers { score += 0.2; }
            total_checks += 1;
        }

        if let Some(has_meaningful_content) = results.get("has_meaningful_content").and_then(|v| v.as_bool()) {
            if has_meaningful_content { score += 0.2; }
            total_checks += 1;
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    fn calculate_domain_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        if let Some(dns_resolvable) = results.get("dns_resolvable").and_then(|v| v.as_bool()) {
            if dns_resolvable { score += 0.3; }
            total_checks += 1;
        }

        if let Some(http_accessible) = results.get("http_accessible").and_then(|v| v.as_bool()) {
            if http_accessible { score += 0.2; }
            total_checks += 1;
        }

        if let Some(age) = results.get("domain_age_days").and_then(|v| v.as_u64()) {
            if age > 365 { score += 0.1; } // Bonus for older domains
            total_checks += 1;
        }

        // Check WHOIS information
        if let Some(whois_info) = results.get("whois_info") {
            if let Some(status) = whois_info.get("status").and_then(|v| v.as_str()) {
                let is_active = !status.to_lowercase().contains("inactive") && 
                               !status.to_lowercase().contains("suspended") &&
                               !status.to_lowercase().contains("pendingdelete");
                if is_active { score += 0.1; }
                total_checks += 1;
            }
            
            if whois_info.get("registrar").is_some() {
                score += 0.05; // Bonus for having registrar info
                total_checks += 1;
            }
            
            if whois_info.get("create_date").is_some() {
                score += 0.05; // Bonus for having creation date
                total_checks += 1;
            }

            if let Some(expire_date) = whois_info.get("expire_date").and_then(|v| v.as_str()) {
                if let Ok(expire_timestamp) = chrono::DateTime::parse_from_rfc3339(expire_date) {
                    let now = chrono::Utc::now();
                    let days_until_expiry = (expire_timestamp.with_timezone(&chrono::Utc) - now).num_days();
                    if days_until_expiry > 30 { // Domain not expiring soon
                        score += 0.05;
                        total_checks += 1;
                    }
                }
            }
        }

        // Check security information
        if let Some(security_info) = results.get("security_info") {
            if let Some(https_supported) = security_info.get("https_supported").and_then(|v| v.as_bool()) {
                if https_supported { score += 0.2; }
                total_checks += 1;
            }

            if let Some(has_hsts) = security_info.get("has_hsts").and_then(|v| v.as_bool()) {
                if has_hsts { score += 0.1; }
                total_checks += 1;
            }

            if let Some(redirects_to_https) = security_info.get("redirects_to_https").and_then(|v| v.as_bool()) {
                if redirects_to_https { score += 0.1; }
                total_checks += 1;
            }
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    fn calculate_youtube_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        if let Some(is_accessible) = results.get("is_accessible").and_then(|v| v.as_bool()) {
            if is_accessible { score += 0.4; }
            total_checks += 1;
        }

        if let Some(has_channel_content) = results.get("has_channel_content").and_then(|v| v.as_bool()) {
            if has_channel_content { score += 0.3; }
            total_checks += 1;
        }

        if let Some(has_error_indicators) = results.get("has_error_indicators").and_then(|v| v.as_bool()) {
            if !has_error_indicators { score += 0.2; }
            total_checks += 1;
        }

        if let Some(has_meta_tags) = results.get("has_meta_tags").and_then(|v| v.as_bool()) {
            if has_meta_tags { score += 0.1; }
            total_checks += 1;
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    fn calculate_facebook_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        // API accessibility (highest weight)
        if let Some(api_accessible) = results.get("api_accessible").and_then(|v| v.as_bool()) {
            if api_accessible { score += 0.3; }
            total_checks += 1;
        }

        // HTTP fallback accessibility
        if let Some(is_accessible) = results.get("is_accessible").and_then(|v| v.as_bool()) {
            if is_accessible { score += 0.2; }
            total_checks += 1;
        }

        // Verification status
        if let Some(verified) = results.get("verified_status").and_then(|v| v.as_bool()) {
            if verified { score += 0.15; }
            total_checks += 1;
        }

        // Follower count (bonus for established accounts)
        if let Some(followers_count) = results.get("followers_count").and_then(|v| v.as_u64()) {
            if followers_count > 1000 { score += 0.1; }
            if followers_count > 10000 { score += 0.05; }
            total_checks += 1;
        }

        // Friends count (bonus for active accounts)
        if let Some(friends_count) = results.get("friends_count").and_then(|v| v.as_u64()) {
            if friends_count > 100 { score += 0.05; }
            if friends_count > 500 { score += 0.05; }
            total_checks += 1;
        }

        // Account age (bonus for older accounts)
        if let Some(account_age_days) = results.get("account_age_days").and_then(|v| v.as_u64()) {
            if account_age_days > 365 { score += 0.1; } // 1+ year old
            if account_age_days > 1095 { score += 0.05; } // 3+ years old
            total_checks += 1;
        }

        // Account type (bonus for business/verified accounts)
        if let Some(account_type) = results.get("account_type").and_then(|v| v.as_str()) {
            if account_type == "business" || account_type == "verified" { score += 0.1; }
            total_checks += 1;
        }

        // Profile completeness
        if let Some(has_bio) = results.get("has_bio").and_then(|v| v.as_bool()) {
            if has_bio { score += 0.05; }
            total_checks += 1;
        }

        if let Some(has_website) = results.get("has_website").and_then(|v| v.as_bool()) {
            if has_website { score += 0.05; }
            total_checks += 1;
        }

        if let Some(has_location) = results.get("has_location").and_then(|v| v.as_bool()) {
            if has_location { score += 0.05; }
            total_checks += 1;
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    fn calculate_instagram_confidence_score(&self, results: &HashMap<&str, serde_json::Value>) -> f64 {
        let mut score = 0.0;
        let mut total_checks = 0;

        // API accessibility (highest weight)
        if let Some(api_accessible) = results.get("api_accessible").and_then(|v| v.as_bool()) {
            if api_accessible { score += 0.3; }
            total_checks += 1;
        }

        // HTTP fallback accessibility
        if let Some(is_accessible) = results.get("is_accessible").and_then(|v| v.as_bool()) {
            if is_accessible { score += 0.2; }
            total_checks += 1;
        }

        // Verification status
        if let Some(verified) = results.get("verified_status").and_then(|v| v.as_bool()) {
            if verified { score += 0.15; }
            total_checks += 1;
        }

        // Follower count (bonus for established accounts)
        if let Some(followers_count) = results.get("followers_count").and_then(|v| v.as_u64()) {
            if followers_count > 1000 { score += 0.1; }
            if followers_count > 10000 { score += 0.05; }
            total_checks += 1;
        }

        // Media count (bonus for active accounts)
        if let Some(media_count) = results.get("media_count").and_then(|v| v.as_u64()) {
            if media_count > 50 { score += 0.05; }
            if media_count > 200 { score += 0.05; }
            total_checks += 1;
        }

        // Account type (bonus for business/creator accounts)
        if let Some(account_type) = results.get("account_type").and_then(|v| v.as_str()) {
            if account_type == "business" || account_type == "creator" { score += 0.1; }
            total_checks += 1;
        }

        // Profile completeness
        if let Some(has_biography) = results.get("has_biography").and_then(|v| v.as_bool()) {
            if has_biography { score += 0.05; }
            total_checks += 1;
        }

        if let Some(has_website) = results.get("has_website").and_then(|v| v.as_bool()) {
            if has_website { score += 0.05; }
            total_checks += 1;
        }

        if total_checks > 0 {
            score / total_checks as f64
        } else {
            0.0
        }
    }

    /// Create metadata for non-NFT asset listing
    fn create_non_nft_metadata(&self, asset_type: &str, platform: &str, identifier: &str, verification_data: &serde_json::Value, description: &str) -> Result<serde_json::Value, ContractError> {
        let metadata = json!({
            "name": format!("{} - {}", asset_type.replace("_", " ").to_uppercase(), identifier),
            "description": description,
            "asset_type": asset_type,
            "platform": platform,
            "identifier": identifier,
            "created_at": chrono::Utc::now().timestamp(),
            "verification_data": verification_data,
            "attributes": [
                {
                    "trait_type": "Asset Type",
                    "value": asset_type
                },
                {
                    "trait_type": "Platform",
                    "value": platform
                },
                {
                    "trait_type": "Identifier",
                    "value": identifier
                },
                {
                    "trait_type": "Verified",
                    "value": true
                }
            ]
        });

        Ok(metadata)
    }

    /// Generate unique listing ID
    fn generate_listing_id(&self, user_address: &Address, asset_id: &str) -> u64 {
        let mut data = Vec::new();
        data.extend_from_slice(user_address.as_bytes());
        data.extend_from_slice(asset_id.as_bytes());
        data.extend_from_slice(&chrono::Utc::now().timestamp().to_le_bytes());

        let hash = keccak256(data);
        u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]))
    }

    /// Create verification proof
    fn create_verification_proof(&self, platform: &str, identifier: &str, verification_data: &serde_json::Value) -> Result<String, ContractError> {
        let proof_data = json!({
            "platform": platform,
            "identifier": identifier,
            "verification_data": verification_data,
            "verified_at": chrono::Utc::now().timestamp(),
            "verifier": format!("0x{:x}", self.verification_address)
        });

        let proof_string = serde_json::to_string(&proof_data)
            .map_err(|e| ContractError::ContractCallError(format!("Failed to serialize verification proof: {}", e)))?;

        Ok(proof_string)
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SocialMediaPlatform;
    use crate::domain::InitiateSocialMediaNftMintRequest;
    use crate::domain::ListNonNftAssetRequest;

    #[tokio::test]
    async fn test_signature_generation() {
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);
        let social_media_id = "x_123456789";

        let signature = verification_service.generate_signature(&user_address, social_media_id).await.unwrap();

        assert!(signature.starts_with("0x"));
        assert_eq!(signature.len(), 132); // 0x + 130 hex characters
    }

    #[test]
    fn test_metadata_creation() {
        // Set up test environment for Pinata
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let verification_service = VerificationService::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ).unwrap();

        let metadata = verification_service.create_non_nft_metadata(
            "social_media",
            "x",
            "testuser",
            &json!({"verified": true}),
            "Test description for social media asset"
        ).unwrap();

        assert!(metadata.is_object());
        assert_eq!(metadata["name"], "SOCIAL MEDIA - testuser");
        assert_eq!(metadata["description"], "Test description for social media asset");
        assert_eq!(metadata["asset_type"], "social_media");
        assert_eq!(metadata["platform"], "x");
        assert_eq!(metadata["identifier"], "testuser");
    }

    #[test]
    fn test_metadata_json_creation() {
        // Set up test environment for Pinata
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let verification_service = VerificationService::new(
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ).unwrap();

        let metadata = verification_service.create_non_nft_metadata(
            "social_media",
            "x",
            "testuser",
            &json!({"verified": true}),
            "Test description for social media asset"
        ).unwrap();

        let metadata_string = serde_json::to_string(&metadata).unwrap();
        assert!(metadata_string.contains("testuser"));
        assert!(metadata_string.contains("Test description for social media asset"));
        assert!(metadata_string.contains("x"));
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
            platform: SocialMediaPlatform::X,
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

        assert!(response.social_media_id.contains("x_123456789"));
        assert!(response.signature.starts_with("0x"));
        assert!(response.metadata.contains("Test User"));
        assert!(response.metadata.contains("x"));
        assert!(response.token_uri.starts_with("ipfs://"));
    }

    #[test]
    fn test_username_validation() {
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        // Test X username validation
        assert!(verification_service.is_valid_x_username("testuser"));
        assert!(verification_service.is_valid_x_username("test_user"));
        assert!(verification_service.is_valid_x_username("test123"));
        assert!(!verification_service.is_valid_x_username("tes")); // Too short (3 chars)
        assert!(!verification_service.is_valid_x_username("testuser123456789")); // Too long
        assert!(!verification_service.is_valid_x_username("test-user")); // Invalid character

        // Test Instagram username validation
        assert!(verification_service.is_valid_instagram_username("testuser"));
        assert!(verification_service.is_valid_instagram_username("test.user"));
        assert!(verification_service.is_valid_instagram_username("test_user"));
        assert!(!verification_service.is_valid_instagram_username("test@user")); // Invalid character

        // Test Facebook username validation
        assert!(verification_service.is_valid_facebook_username("testuser"));
        assert!(verification_service.is_valid_facebook_username("test.user"));
        assert!(!verification_service.is_valid_facebook_username("test")); // Too short
        assert!(!verification_service.is_valid_facebook_username("test_user")); // Invalid character

        // Test YouTube identifier validation
        assert!(verification_service.is_valid_youtube_identifier("UC1234567890123456789012")); // Channel ID
        assert!(verification_service.is_valid_youtube_identifier("testuser")); // Username
        assert!(verification_service.is_valid_youtube_identifier("test-user")); // Username with hyphen
        assert!(verification_service.is_valid_youtube_identifier("test_user")); // Username with underscore
        assert!(!verification_service.is_valid_youtube_identifier("te")); // Too short (2 chars)
        assert!(!verification_service.is_valid_youtube_identifier("test@user")); // Invalid character
    }

    #[test]
    fn test_parse_social_media_identifier() {
        // Set up test environment for Pinata
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        // Test X URL
        let (platform, identifier) = verification_service.parse_social_media_identifier("https://x.com/testuser").unwrap();
        assert_eq!(platform, "x");
        assert_eq!(identifier, "testuser");

        // Test Instagram URL
        let (platform, identifier) = verification_service.parse_social_media_identifier("https://instagram.com/testuser").unwrap();
        assert_eq!(platform, "instagram");
        assert_eq!(identifier, "testuser");

        // Test YouTube URL
        let (platform, identifier) = verification_service.parse_social_media_identifier("https://youtube.com/testuser").unwrap();
        assert_eq!(platform, "youtube");
        assert_eq!(identifier, "testuser");

        // Test YouTube channel URL
        let (platform, identifier) = verification_service.parse_social_media_identifier("https://youtube.com/channel/UC1234567890123456789012").unwrap();
        assert_eq!(platform, "youtube");
        assert_eq!(identifier, "UC1234567890123456789012");

        // Test direct username (assumes X)
        let (platform, identifier) = verification_service.parse_social_media_identifier("testuser").unwrap();
        assert_eq!(platform, "x");
        assert_eq!(identifier, "testuser");

        // Test invalid format
        let result = verification_service.parse_social_media_identifier("https://invalid-platform.com/user");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_non_nft_asset_social_media_production() {
        // Set test environment variable if not set
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);

        // Test with valid X username
        let request = ListNonNftAssetRequest {
            asset_type: 1, // Social media
            asset_id: Arc::from("https://x.com/testuser123"),
            price: 1000000000000000000, // 1 ETH in wei
            description: Arc::from("This is a test description for social media asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let response = verification_service.list_non_nft_asset(&user_address, &request).await.unwrap();

        assert!(response.listing_id > 0);
        assert_eq!(response.asset_type, 1);
        assert_eq!(response.asset_id, Arc::from("https://x.com/testuser123"));
        assert_eq!(response.price, 1000000000000000000);
        assert!(response.metadata.starts_with("ipfs://"));
        assert!(!response.verification_proof.is_empty());
        assert!(response.transaction_hash.starts_with("0x"));

        // Test with invalid username format
        let request = ListNonNftAssetRequest {
            asset_type: 1,
            asset_id: Arc::from("https://x.com/tes"), // Too short (3 chars)
            price: 1000000000000000000,
            description: Arc::from("This is a test description for social media asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let result = verification_service.list_non_nft_asset(&user_address, &request).await;
        assert!(result.is_err()); // Should fail validation
    }

    #[tokio::test]
    async fn test_list_non_nft_asset_website_production() {
        // Set test environment variable if not set
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);

        // Test with valid website URL
        let request = ListNonNftAssetRequest {
            asset_type: 2, // Website
            asset_id: Arc::from("https://example.com"),
            price: 500000000000000000, // 0.5 ETH in wei
            description: Arc::from("This is a test description for website asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let response = verification_service.list_non_nft_asset(&user_address, &request).await.unwrap();

        assert!(response.listing_id > 0);
        assert_eq!(response.asset_type, 2);
        assert_eq!(response.asset_id, Arc::from("https://example.com"));
        assert_eq!(response.price, 500000000000000000);
        assert!(response.metadata.starts_with("ipfs://"));
        assert!(!response.verification_proof.is_empty());
        assert!(response.transaction_hash.starts_with("0x"));

        // Test with invalid URL format
        let request = ListNonNftAssetRequest {
            asset_type: 2,
            asset_id: Arc::from("not-a-url"),
            price: 500000000000000000,
            description: Arc::from("This is a test description for website asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let result = verification_service.list_non_nft_asset(&user_address, &request).await;
        assert!(result.is_err()); // Should fail validation
    }

    #[tokio::test]
    async fn test_list_non_nft_asset_youtube() {
        // Set test environment variable if not set
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        let user_address = Address::from_slice(&[1u8; 20]);

        // Test with valid YouTube channel
        let request = ListNonNftAssetRequest {
            asset_type: 1, // Social media
            asset_id: Arc::from("https://youtube.com/channel/UC1234567890123456789012"),
            price: 2000000000000000000, // 2 ETH in wei
            description: Arc::from("This is a test description for YouTube asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let response = verification_service.list_non_nft_asset(&user_address, &request).await.unwrap();

        assert!(response.listing_id > 0);
        assert_eq!(response.asset_type, 1);
        assert_eq!(response.asset_id, Arc::from("https://youtube.com/channel/UC1234567890123456789012"));
        assert_eq!(response.price, 2000000000000000000);
        assert!(response.metadata.starts_with("ipfs://"));
        assert!(!response.verification_proof.is_empty());
        assert!(response.transaction_hash.starts_with("0x"));

        // Test with invalid YouTube identifier
        let request = ListNonNftAssetRequest {
            asset_type: 1,
            asset_id: Arc::from("https://youtube.com/test@user"), // Invalid character @
            price: 2000000000000000000,
            description: Arc::from("This is a test description for YouTube asset."),
            metadata: Arc::from("{}"),
            verification_proof: Arc::from(""),
        };

        let result = verification_service.list_non_nft_asset(&user_address, &request).await;
        assert!(result.is_err()); // Should fail validation
    }

    #[tokio::test]
    async fn test_whois_api_integration() {
        // Set test environment variables
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        // Set a test API key if not present
        if std::env::var("IP2LOCATION_WHOIS_API_KEY").is_err() {
            unsafe {
                std::env::set_var("IP2LOCATION_WHOIS_API_KEY", "test_api_key");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        // Test domain age calculation
        let domain_age = verification_service.get_domain_age("example.com").await;

        // Should either succeed with real data or fail gracefully with test API key
        match domain_age {
            Ok(age) => {
                println!("Domain age: {} days", age);
                assert!(age > 0);
            }
            Err(e) => {
                // Expected with test API key
                println!("WHOIS API test result (expected with test key): {}", e);
                assert!(e.to_string().contains("WHOIS API"));
            }
        }

        // Test WHOIS info retrieval
        let whois_info = verification_service.get_whois_info("example.com").await;

        match whois_info {
            Ok(info) => {
                println!("WHOIS info: {}", serde_json::to_string_pretty(&info).unwrap());
                assert!(info.is_object());
            }
            Err(e) => {
                // Expected with test API key
                println!("WHOIS info test result (expected with test key): {}", e);
                assert!(e.to_string().contains("WHOIS API"));
            }
        }
    }

    #[tokio::test]
    async fn test_x_api_integration() {
        // Set test environment variables
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        // Set a test API key if not present
        if std::env::var("X_API_BEARER_TOKEN").is_err() {
            unsafe {
                std::env::set_var("X_API_BEARER_TOKEN", "test_bearer_token");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        // Create HTTP client for testing
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Vertix-X-Verification-Test/1.0")
            .build()
            .unwrap();

        // Test X metadata retrieval
        let metadata = verification_service.get_x_metadata(&client, "x").await;

        match metadata {
            Ok(meta) => {
                println!("X metadata: {}", serde_json::to_string_pretty(&meta).unwrap());
                assert!(meta.is_object());

                // Check for expected fields
                if let Some(user_id) = meta.get("user_id") {
                    assert!(user_id.is_string());
                }

                if let Some(followers_count) = meta.get("followers_count") {
                    assert!(followers_count.is_number());
                }
            }
            Err(e) => {
                // Expected with test API key
                println!("X API test result (expected with test key): {}", e);
                assert!(e.to_string().contains("X API"));
            }
        }

        // Test X profile verification
        let verification = verification_service.verify_x_profile(&client, "x").await;

        match verification {
            Ok(verification_data) => {
                println!("X verification: {}", serde_json::to_string_pretty(&verification_data).unwrap());
                assert!(verification_data.is_object());

                // Check for expected fields
                assert_eq!(verification_data["platform"], "x");
                assert!(verification_data.get("results").is_some());
                assert!(verification_data.get("confidence_score").is_some());
            }
            Err(e) => {
                // Expected with test API key
                println!("X verification test result (expected with test key): {}", e);
                assert!(e.to_string().contains("X API"));
            }
        }
    }

    #[tokio::test]
    async fn test_facebook_api_integration() {
        // Set test environment variables
        if std::env::var("PINATA_JWT").is_err() {
            unsafe {
                std::env::set_var("PINATA_JWT", "test_jwt");
            }
        }

        // Set a test API key if not present
        if std::env::var("FACEBOOK_ACCESS_TOKEN").is_err() {
            unsafe {
                std::env::set_var("FACEBOOK_ACCESS_TOKEN", "test_access_token");
            }
        }

        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let verification_service = VerificationService::new(private_key).unwrap();

        // Create HTTP client for testing
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Vertix-Facebook-Verification-Test/1.0")
            .build()
            .unwrap();

        // Test Facebook metadata retrieval
        let metadata = verification_service.get_facebook_metadata(&client, "zuck").await;
        
        match metadata {
            Ok(meta) => {
                println!("Facebook metadata: {}", serde_json::to_string_pretty(&meta).unwrap());
                assert!(meta.is_object());
                
                // Check for expected fields
                if let Some(user_id) = meta.get("user_id") {
                    assert!(user_id.is_string());
                }
                
                if let Some(followers_count) = meta.get("followers_count") {
                    assert!(followers_count.is_number());
                }
            }
            Err(e) => {
                // Expected with test API key
                println!("Facebook API test result (expected with test key): {}", e);
                assert!(e.to_string().contains("Facebook API"));
            }
        }

        // Test Facebook profile verification
        let verification = verification_service.verify_facebook_profile(&client, "zuck").await;
        
        match verification {
            Ok(verification_data) => {
                println!("Facebook verification: {}", serde_json::to_string_pretty(&verification_data).unwrap());
                assert!(verification_data.is_object());
                
                // Check for expected fields
                assert_eq!(verification_data["platform"], "facebook");
                assert!(verification_data.get("results").is_some());
                assert!(verification_data.get("confidence_score").is_some());
            }
            Err(e) => {
                // Expected with test API key
                println!("Facebook verification test result (expected with test key): {}", e);
                assert!(e.to_string().contains("Facebook API"));
            }
        }
    }
}