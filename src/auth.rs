use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse as OAuthTokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;
use ethers::utils::{hash_message, to_checksum};
use ethers::types::Signature;
use std::env;
use crate::models::{ConnectWalletRequest, LoginResponse, UpdateProfileRequest, User};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    sub: String, // User ID
    exp: usize,  // Expiration timestamp
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Argon2 error: {0}")]
    Argon2Error(String),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("OAuth error: {0}")]
    OAuthError(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid wallet address")]
    InvalidWalletAddress,
}

pub async fn register(
    pool: &PgPool,
    email: &str,
    password: &str,
    first_name: &str,
    last_name: &str,
) -> Result<User, AuthError> {
    let password_hash = hash_password(password)?;
    let user = crate::db::create_user(pool, email, &password_hash, first_name, last_name).await?;
    Ok(user)
}

pub async fn login(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<LoginResponse, AuthError> {
    let user = crate::db::find_user_by_email(pool, email).await?;
    let user = user.ok_or(AuthError::InvalidCredentials)?;

    if let Some(password_hash) = user.password_hash {
        if !verify_password(&password_hash, password)? {
            return Err(AuthError::InvalidCredentials);
        }
    } else {
        return Err(AuthError::InvalidCredentials); // Google-only user
    }

    let token = generate_jwt(&user.id.to_string())?;
    Ok(LoginResponse { token })
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Argon2Error(e.to_string()))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AuthError::Argon2Error(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn generate_jwt(user_id: &str) -> Result<String, AuthError> {
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

pub fn verify_jwt(token: &str) -> Result<String, AuthError> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;
    Ok(token_data.claims.sub)
}

pub async fn connect_wallet(
    pool: &PgPool,
    user_id: Option<Uuid>,
    request: ConnectWalletRequest,
) -> Result<User, AuthError> {
    let wallet_address = request.wallet_address.to_lowercase();
    if !wallet_address.starts_with("0x") || wallet_address.len() != 42 {
        return Err(AuthError::InvalidWalletAddress);
    }

    // Verify nonce
    let is_valid_nonce = crate::db::verify_nonce(pool, &wallet_address, &request.nonce).await?;
    if !is_valid_nonce {
        return Err(AuthError::InvalidSignature);
    }

    // Verify signature
    let message = format!("Connect to Vertix: {}", request.nonce);
    let message_hash = hash_message(&message);
    let signature_bytes = hex::decode(&request.signature[2..])
        .map_err(|_| AuthError::InvalidSignature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| AuthError::InvalidSignature)?;
    let recovered_address = signature
        .recover(message_hash)
        .map_err(|_| AuthError::InvalidSignature)?;

    if to_checksum(&recovered_address, None).to_lowercase() != wallet_address {
        return Err(AuthError::InvalidSignature);
    }

    // Update or create user with wallet address
    let user = if let Some(user_id) = user_id {
        // Seller: Update existing user's wallet address
        crate::db::update_wallet_address(pool, user_id, &wallet_address).await?
    } else {
        // Buyer: Check if wallet exists or create minimal user
        let existing_user = crate::db::find_user_by_wallet_address(pool, &wallet_address).await?;
        match existing_user {
            Some(user) => user,
            None => {
                crate::db::create_user(
                    pool,
                    &format!("{}@vertix.io", wallet_address),
                    &hash_password(&Uuid::new_v4().to_string())?,
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
    let client = google_oauth_client();
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
    pool: &PgPool,
    code: &str,
    _: &str,
) -> Result<LoginResponse, AuthError> {
    let client = google_oauth_client();
    let token_response = client
        .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| AuthError::OAuthError(e.to_string()))?;

    let client = reqwest::Client::new();
    let user_info: serde_json::Value = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(token_response.access_token().secret())
        .send()
        .await
        .map_err(|e| AuthError::OAuthError(e.to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::OAuthError(e.to_string()))?;

    let google_id = user_info["id"]
        .as_str()
        .ok_or_else(|| AuthError::OAuthError("Missing Google ID".to_string()))?;
    let email = user_info["email"]
        .as_str()
        .ok_or_else(|| AuthError::OAuthError("Missing email".to_string()))?;
    let first_name = user_info["given_name"]
        .as_str()
        .unwrap_or("Unknown");
    let last_name = user_info["family_name"]
        .as_str()
        .unwrap_or("Unknown");

    let user = crate::db::find_user_by_google_id(pool, google_id).await?;
    let user = match user {
        Some(user) => user,
        None => crate::db::create_google_user(pool, email, google_id, first_name, last_name).await?,
    };

    let token = generate_jwt(&user.id.to_string())?;
    Ok(LoginResponse { token })
}

pub async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    request: UpdateProfileRequest,
) -> Result<User, AuthError> {
    let user = crate::db::update_user_profile(pool, user_id, request).await?;
    Ok(user)
}

// pub async fn initiate_kyc(
//     pool: &PgPool,
//     request: KycRequest,
// ) -> Result<String, AuthError> {
//     // Placeholder: Simulate KYC provider integration (e.g., Sumsub)
//     // In practice, use Sumsub SDK or API to create a verification session
//     let kyc_url = format!("https://kyc-provider.com/verify?user_id={}", request.user_id);
    
//     // TODO: Integrate real KYC provider
//     // Example with Sumsub (pseudo-code):
//     // let client = SumsubClient::new(env::var("SUMSUB_API_KEY")?);
//     // let session = client.create_verification_session(request.user_id.to_string()).await?;
//     // let kyc_url = session.url;

//     Ok(kyc_url)
// }

// pub async fn complete_kyc(
//     pool: &PgPool,
//     callback: KycCallback,
// ) -> Result<User, AuthError> {
//     let is_verified = callback.status == "verified";
    
//     // Update user KYC status
//     let user = crate::db::update_kyc_status(pool, callback.user_id, is_verified).await?;
    
//     // TODO: Validate callback signature from KYC provider
//     // Example with Sumsub webhook:
//     // if !client.verify_webhook_signature(callback.signature, callback.payload) {
//     //     return Err(AuthError::InvalidSignature);
//     // }

//     Ok(user)
// }