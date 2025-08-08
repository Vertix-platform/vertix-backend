use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use ethers::utils::{hash_message, to_checksum};
use ethers::types::Signature;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse as OAuthTokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;
use std::env;


use crate::api::dto::LoginResponse;
use crate::domain::{User, ConnectWalletRequest, UpdateProfileRequest};
use crate::infrastructure::repositories::UserRepository;

// Social Media OAuth Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocialMediaPlatform {
    Twitter,
    Instagram,
    Facebook,
}

impl SocialMediaPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            SocialMediaPlatform::Twitter => "twitter",
            SocialMediaPlatform::Instagram => "instagram",
            SocialMediaPlatform::Facebook => "facebook",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialMediaProfile {
    pub platform: SocialMediaPlatform,
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub profile_image_url: Option<String>,
    pub follower_count: Option<u64>,
    pub verified: bool,
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    sub: String, // User ID
    exp: usize,  // Expiration timestamp
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Argon2 error: {0}")]
    Argon2Error(String),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("OAuth error: {0}")]
    OAuthError(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid wallet address")]
    InvalidWalletAddress,
}

// ============ CONTRACT ERROR TYPES ============

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },
    #[error("Contract call error: {0}")]
    ContractCallError(String),
    #[error("Transaction error: {0}")]
    TransactionError(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Invalid uint96 value: {reason}")]
    InvalidUint96Value { reason: String },
    #[error("Escrow error: {reason}")]
    EscrowError { reason: String },
    #[error("Invalid royalty value")]
    InvalidRoyaltyValue,
    #[error("Social media ID already used: {social_media_id}")]
    SocialMediaIdAlreadyUsed { social_media_id: String },
    #[error("Wallet mismatch: provided {provided}, connected {connected}")]
    WalletMismatch { provided: String, connected: String },
    #[error("Insufficient balance: current {current}, required {required}")]
    InsufficientBalance { current: String, required: String },
    #[error("User not verified: {user_id} - {reason}")]
    UserNotVerified { user_id: String, reason: String },
    #[error("User wallet not connected: {user_id} - {reason}")]
    UserWalletNotConnected { user_id: String, reason: String },
    #[error("User wallet mismatch: {user_id} - provided {provided}, connected {connected}")]
    UserWalletMismatch { user_id: String, provided: String, connected: String },
    #[error("ABI error: {0}")]
    AbiError(String),
}

impl From<ethers::contract::AbiError> for ContractError {
    fn from(err: ethers::contract::AbiError) -> Self {
        ContractError::AbiError(err.to_string())
    }
}

pub struct AuthService {
    user_repo: UserRepository,
}

impl AuthService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            user_repo: UserRepository::new(pool),
        }
    }

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<User, ServiceError> {
        let password_hash = self.hash_password(password)?;
        let user = self.user_repo.create_user(email, &password_hash, first_name, last_name).await?;
        Ok(user)
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<LoginResponse, ServiceError> {
        let user = self.user_repo.find_by_email(email).await?
            .ok_or(ServiceError::InvalidCredentials)?;

        if let Some(password_hash) = user.password_hash {
            if !self.verify_password(&password_hash, password)? {
                return Err(ServiceError::InvalidCredentials);
            }
        } else {
            return Err(ServiceError::InvalidCredentials); // Google-only user
        }

        let token = self.generate_jwt(&user.id.to_string())?;
        Ok(LoginResponse { token })
    }

    pub fn hash_password(&self, password: &str) -> Result<String, ServiceError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| ServiceError::Argon2Error(e.to_string()))?
            .to_string();
        Ok(hash)
    }

    pub fn verify_password(&self, hash: &str, password: &str) -> Result<bool, ServiceError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| ServiceError::Argon2Error(e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub fn generate_jwt(&self, user_id: &str) -> Result<String, ServiceError> {
        Self::generate_jwt_static(user_id)
    }

    pub fn generate_jwt_static(user_id: &str) -> Result<String, ServiceError> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::hours(24))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )?;
        Ok(token)
    }

    pub fn verify_jwt(&self, token: &str) -> Result<String, ServiceError> {
        Self::verify_jwt_static(token)
    }

    pub fn verify_jwt_static(token: &str) -> Result<String, ServiceError> {
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        )?;
        Ok(token_data.claims.sub)
    }

    pub async fn connect_wallet(
        &self,
        user_id: Option<Uuid>,
        request: ConnectWalletRequest,
    ) -> Result<User, ServiceError> {
        let wallet_address = request.wallet_address.to_lowercase();
        if !wallet_address.starts_with("0x") || wallet_address.len() != 42 {
            return Err(ServiceError::InvalidWalletAddress);
        }

        // Verify nonce
        let is_valid_nonce = self.user_repo.verify_nonce(&wallet_address, &request.nonce).await?;
        if !is_valid_nonce {
            return Err(ServiceError::InvalidSignature);
        }

        // Verify signature
        let message = format!("Connect to Vertix: {}", request.nonce);
        let message_hash = hash_message(&message);
        let signature_bytes = hex::decode(&request.signature[2..])
            .map_err(|_| ServiceError::InvalidSignature)?;
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| ServiceError::InvalidSignature)?;
        let recovered_address = signature
            .recover(message_hash)
            .map_err(|_| ServiceError::InvalidSignature)?;

        if to_checksum(&recovered_address, None).to_lowercase() != wallet_address {
            return Err(ServiceError::InvalidSignature);
        }

        // Update or create user with wallet address
        let user = if let Some(user_id) = user_id {
            // Seller: Update existing user's wallet address
            self.user_repo.update_wallet_address(user_id, &wallet_address).await?
        } else {
            // Buyer: Check if wallet exists or create minimal user
            let existing_user = self.user_repo.find_by_wallet_address(&wallet_address).await?;
            match existing_user {
                Some(user) => user,
                None => {
                    self.user_repo.create_user(
                        &format!("{}@vertix.io", wallet_address),
                        &self.hash_password(&Uuid::new_v4().to_string())?,
                        "Buyer",
                        "Unknown",
                    ).await?
                }
            }
        };

        Ok(user)
    }

    pub fn google_oauth_client() -> BasicClient {
        let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set");
        let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set");
        let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set");

        BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
    }

    pub fn google_auth_url() -> (String, CsrfToken) {
        let client = Self::google_oauth_client();
        let (pkce_code_challenge, _pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        (auth_url.to_string(), csrf_token)
    }

    pub async fn google_callback(
        &self,
        code: &str,
        _: &str,
    ) -> Result<LoginResponse, ServiceError> {
        let client = Self::google_oauth_client();
        let token_response = client
            .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?;

        let client = reqwest::Client::new();
        let user_info: serde_json::Value = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(token_response.access_token().secret())
            .send()
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?;

        let google_id = user_info["id"]
            .as_str()
            .ok_or_else(|| ServiceError::OAuthError("Missing Google ID".to_string()))?;
        let email = user_info["email"]
            .as_str()
            .ok_or_else(|| ServiceError::OAuthError("Missing email".to_string()))?;
        let first_name = user_info["given_name"]
            .as_str()
            .unwrap_or("Unknown");
        let last_name = user_info["family_name"]
            .as_str()
            .unwrap_or("Unknown");

        let user = self.user_repo.find_by_google_id(google_id).await?;
        let user = match user {
            Some(user) => user,
            None => self.user_repo.create_google_user(email, google_id, first_name, last_name).await?,
        };

        let token = self.generate_jwt(&user.id.to_string())?;
        Ok(LoginResponse { token })
    }

    // Social Media OAuth Implementation
    pub fn twitter_oauth_client() -> BasicClient {
        let client_id = env::var("TWITTER_CLIENT_ID").expect("TWITTER_CLIENT_ID must be set");
        let client_secret = env::var("TWITTER_CLIENT_SECRET").expect("TWITTER_CLIENT_SECRET must be set");
        let redirect_uri = env::var("TWITTER_REDIRECT_URI").expect("TWITTER_REDIRECT_URI must be set");

        BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://twitter.com/i/oauth2/authorize".to_string()).unwrap(),
            Some(oauth2::TokenUrl::new("https://api.x.com/2/oauth2/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
    }

    pub fn instagram_oauth_client() -> BasicClient {
        let client_id = env::var("INSTAGRAM_CLIENT_ID").expect("INSTAGRAM_CLIENT_ID must be set");
        let client_secret = env::var("INSTAGRAM_CLIENT_SECRET").expect("INSTAGRAM_CLIENT_SECRET must be set");
        let redirect_uri = env::var("INSTAGRAM_REDIRECT_URI").expect("INSTAGRAM_REDIRECT_URI must be set");

        BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://api.instagram.com/oauth/authorize".to_string()).unwrap(),
            Some(oauth2::TokenUrl::new("https://api.instagram.com/oauth/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
    }

    pub fn facebook_oauth_client() -> BasicClient {
        let client_id = env::var("FACEBOOK_CLIENT_ID").expect("FACEBOOK_CLIENT_ID must be set");
        let client_secret = env::var("FACEBOOK_CLIENT_SECRET").expect("FACEBOOK_CLIENT_SECRET must be set");
        let redirect_uri = env::var("FACEBOOK_REDIRECT_URI").expect("FACEBOOK_REDIRECT_URI must be set");

        BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://www.facebook.com/v18.0/dialog/oauth".to_string()).unwrap(),
            Some(oauth2::TokenUrl::new("https://graph.facebook.com/v18.0/oauth/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
    }

    pub fn get_social_media_auth_url(platform: &SocialMediaPlatform) -> (String, CsrfToken) {
        let (client, scope) = match platform {
            SocialMediaPlatform::Twitter => {
                let client = Self::twitter_oauth_client();
                let scope = "tweet.read users.read offline.access".to_string();
                (client, scope)
            }
            SocialMediaPlatform::Instagram => {
                let client = Self::instagram_oauth_client();
                let scope = "user_profile user_media".to_string();
                (client, scope)
            }
            SocialMediaPlatform::Facebook => {
                let client = Self::facebook_oauth_client();
                let scope = "public_profile email".to_string();
                (client, scope)
            }
        };

        let (pkce_code_challenge, _pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(scope))
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        (auth_url.to_string(), csrf_token)
    }

    pub async fn authenticate_social_media_user(
        &self,
        platform: &SocialMediaPlatform,
        auth_code: &str,
    ) -> Result<SocialMediaProfile, ServiceError> {
        match platform {
            SocialMediaPlatform::Twitter => self.authenticate_twitter_user(auth_code).await,
            SocialMediaPlatform::Instagram => self.authenticate_instagram_user(auth_code).await,
            SocialMediaPlatform::Facebook => self.authenticate_facebook_user(auth_code).await,
        }
    }

    async fn authenticate_twitter_user(&self, auth_code: &str) -> Result<SocialMediaProfile, ServiceError> {
        let client = Self::twitter_oauth_client();
        let token_response = client
            .exchange_code(oauth2::AuthorizationCode::new(auth_code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?;

        let access_token = token_response.access_token().secret();

        // Get user profile
        let client = reqwest::Client::new();
        let profile_response = client
            .get("https://api.x.com/2/users/me")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| ServiceError::OAuthError(format!("Twitter profile request failed: {}", e)))?;

        let profile_data: serde_json::Value = profile_response.json().await
            .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Twitter profile response: {}", e)))?;

        let user_data = &profile_data["data"];

        Ok(SocialMediaProfile {
            platform: SocialMediaPlatform::Twitter,
            user_id: user_data["id"].as_str().unwrap_or("").to_string(),
            username: user_data["username"].as_str().unwrap_or("").to_string(),
            display_name: user_data["name"].as_str().unwrap_or("").to_string(),
            profile_image_url: user_data["profile_image_url"].as_str().map(|s| s.to_string()),
            follower_count: None, // Would need additional API call for follower count
            verified: user_data["verified"].as_bool().unwrap_or(false),
            access_token: access_token.to_string(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().to_string()),
        })
    }

    async fn authenticate_instagram_user(&self, auth_code: &str) -> Result<SocialMediaProfile, ServiceError> {
        let client = Self::instagram_oauth_client();
        let token_response = client
            .exchange_code(oauth2::AuthorizationCode::new(auth_code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?;

        let access_token = token_response.access_token().secret();

        // Get user profile
        let client = reqwest::Client::new();
        let profile_response = client
            .get(&format!("https://graph.instagram.com/me?fields=id,username,account_type&access_token={}", access_token))
            .send()
            .await
            .map_err(|e| ServiceError::OAuthError(format!("Instagram profile request failed: {}", e)))?;

        let profile_data: serde_json::Value = profile_response.json().await
            .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Instagram profile response: {}", e)))?;

        Ok(SocialMediaProfile {
            platform: SocialMediaPlatform::Instagram,
            user_id: profile_data["id"].as_str().unwrap_or("").to_string(),
            username: profile_data["username"].as_str().unwrap_or("").to_string(),
            display_name: profile_data["username"].as_str().unwrap_or("").to_string(), // Instagram doesn't provide display name
            profile_image_url: None, // Would need additional API call for profile image
            follower_count: None, // Would need additional API call for follower count
            verified: false, // Instagram doesn't provide verification status in basic API
            access_token: access_token.to_string(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().to_string()),
        })
    }

    async fn authenticate_facebook_user(&self, auth_code: &str) -> Result<SocialMediaProfile, ServiceError> {
        let client = Self::facebook_oauth_client();
        let token_response = client
            .exchange_code(oauth2::AuthorizationCode::new(auth_code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| ServiceError::OAuthError(e.to_string()))?;

        let access_token = token_response.access_token().secret();

        // Get user profile
        let client = reqwest::Client::new();
        let profile_response = client
            .get(&format!(
                "https://graph.facebook.com/me?fields=id,name,username,picture&access_token={}",
                access_token
            ))
            .send()
            .await
            .map_err(|e| ServiceError::OAuthError(format!("Facebook profile request failed: {}", e)))?;

        let profile_data: serde_json::Value = profile_response.json().await
            .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Facebook profile response: {}", e)))?;

        let profile_image_url = profile_data["picture"]["data"]["url"].as_str().map(|s| s.to_string());

        Ok(SocialMediaProfile {
            platform: SocialMediaPlatform::Facebook,
            user_id: profile_data["id"].as_str().unwrap_or("").to_string(),
            username: profile_data["username"].as_str().unwrap_or("").to_string(),
            display_name: profile_data["name"].as_str().unwrap_or("").to_string(),
            profile_image_url,
            follower_count: None, // Would need additional API call for follower count
            verified: false, // Facebook doesn't provide verification status in basic API
            access_token: access_token.to_string(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().to_string()),
        })
    }

    pub async fn get_social_media_profile_image(&self, profile: &SocialMediaProfile) -> Result<Option<String>, ServiceError> {
        match profile.platform {
            SocialMediaPlatform::Twitter => {
                // Twitter profile image is already included in the profile
                Ok(profile.profile_image_url.clone())
            }
            SocialMediaPlatform::Instagram => {
                // Instagram requires additional API call for profile image
                let client = reqwest::Client::new();
                let response = client
                    .get(&format!(
                        "https://graph.instagram.com/me?fields=profile_picture_url&access_token={}",
                        profile.access_token
                    ))
                    .send()
                    .await
                    .map_err(|e| ServiceError::OAuthError(format!("Instagram profile image request failed: {}", e)))?;

                let data: serde_json::Value = response.json().await
                    .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Instagram profile image response: {}", e)))?;

                Ok(data["profile_picture_url"].as_str().map(|s| s.to_string()))
            }
            SocialMediaPlatform::Facebook => {
                // Facebook profile image is already included in the profile
                Ok(profile.profile_image_url.clone())
            }
        }
    }

    pub async fn get_social_media_follower_count(&self, profile: &SocialMediaProfile) -> Result<Option<u64>, ServiceError> {
        match profile.platform {
            SocialMediaPlatform::Twitter => {
                let client = reqwest::Client::new();
                let response = client
                    .get(&format!(
                        "https://api.x.com/2/users/{}?user.fields=public_metrics",
                        profile.user_id
                    ))
                    .header("Authorization", format!("Bearer {}", profile.access_token))
                    .send()
                    .await
                    .map_err(|e| ServiceError::OAuthError(format!("Twitter follower count request failed: {}", e)))?;

                let data: serde_json::Value = response.json().await
                    .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Twitter follower count response: {}", e)))?;

                let follower_count = data["data"]["public_metrics"]["followers_count"].as_u64();
                Ok(follower_count)
            }
            SocialMediaPlatform::Instagram => {
                // Instagram requires additional API call for follower count
                let client = reqwest::Client::new();
                let response = client
                    .get(&format!(
                        "https://graph.instagram.com/me?fields=followers_count&access_token={}",
                        profile.access_token
                    ))
                    .send()
                    .await
                    .map_err(|e| ServiceError::OAuthError(format!("Instagram follower count request failed: {}", e)))?;

                let data: serde_json::Value = response.json().await
                    .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Instagram follower count response: {}", e)))?;

                let follower_count = data["followers_count"].as_u64();
                Ok(follower_count)
            }
            SocialMediaPlatform::Facebook => {
                // Facebook requires additional API call for follower count
                let client = reqwest::Client::new();
                let response = client
                    .get(&format!(
                        "https://graph.facebook.com/me?fields=followers_count&access_token={}",
                        profile.access_token
                    ))
                    .send()
                    .await
                    .map_err(|e| ServiceError::OAuthError(format!("Facebook follower count request failed: {}", e)))?;

                let data: serde_json::Value = response.json().await
                    .map_err(|e| ServiceError::OAuthError(format!("Failed to parse Facebook follower count response: {}", e)))?;

                let follower_count = data["followers_count"].as_u64();
                Ok(follower_count)
            }
        }
    }

    pub async fn update_profile(
        &self,
        user_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<User, ServiceError> {
        let user = self.user_repo.update_profile(user_id, request).await?;
        Ok(user)
    }

    pub async fn create_nonce(&self, wallet_address: &str) -> Result<String, ServiceError> {
        self.user_repo.create_nonce(wallet_address).await.map_err(ServiceError::from)
    }

    pub async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, ServiceError> {
        self.user_repo.find_by_id(user_id).await.map_err(ServiceError::from)
    }
}