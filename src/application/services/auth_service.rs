use sqlx::PgPool;
use uuid::Uuid;

use crate::api::dto::{LoginResponse, ConnectWalletRequest, UpdateProfileRequest, RefreshTokenResponse};
use crate::domain::{User, ServiceError};
use crate::application::use_cases::{
    RegisterUserUseCase, LoginUserUseCase, ConnectWalletUseCase,
    UpdateProfileUseCase, GetUserProfileUseCase, CreateNonceUseCase
};

#[derive(Clone)]
pub struct AuthService {
    pub pool: PgPool,
}

impl AuthService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<LoginResponse, ServiceError> {
        let use_case = RegisterUserUseCase::new(self.pool.clone());
        use_case.execute(email, password, first_name, last_name).await
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<LoginResponse, ServiceError> {
        let use_case = LoginUserUseCase::new(self.pool.clone());
        use_case.execute(email, password).await
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<RefreshTokenResponse, ServiceError> {
        let domain_service = crate::domain::services::AuthService::new(self.pool.clone());
        domain_service.refresh_token(refresh_token).await
    }

    pub async fn revoke_token(&self, refresh_token: &str) -> Result<(), ServiceError> {
        let domain_service = crate::domain::services::AuthService::new(self.pool.clone());
        domain_service.revoke_token(refresh_token).await
    }

    pub async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<(), ServiceError> {
        let domain_service = crate::domain::services::AuthService::new(self.pool.clone());
        domain_service.revoke_all_user_tokens(user_id).await
    }

    pub async fn connect_wallet(
        &self,
        user_id: Option<Uuid>,
        request: ConnectWalletRequest,
    ) -> Result<User, ServiceError> {
        let use_case = ConnectWalletUseCase::new(self.pool.clone());
        use_case.execute(user_id, request).await
    }

    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<User, ServiceError> {
        let use_case = GetUserProfileUseCase::new(self.pool.clone());
        use_case.execute(user_id).await
    }

    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<User, ServiceError> {
        let use_case = UpdateProfileUseCase::new(self.pool.clone());
        use_case.execute(user_id, request).await
    }

    pub async fn create_nonce(&self, wallet_address: &str) -> Result<String, ServiceError> {
        let use_case = CreateNonceUseCase::new(self.pool.clone());
        use_case.execute(wallet_address).await
    }

    // JWT-related methods stay here as they're utility functions
    pub fn verify_jwt(&self, token: &str) -> Result<String, ServiceError> {
        crate::domain::services::AuthService::verify_jwt_static(token)
    }

    pub fn generate_jwt(&self, user_id: &str) -> Result<String, ServiceError> {
        crate::domain::services::AuthService::generate_access_token_static(user_id)
    }

    // Static methods that don't need database access
    pub fn google_auth_url() -> (String, oauth2::CsrfToken) {
        crate::domain::services::AuthService::google_auth_url()
    }

    pub async fn google_callback(
        &self,
        code: &str,
        state: &str,
    ) -> Result<LoginResponse, ServiceError> {
        let domain_service = crate::domain::services::AuthService::new(self.pool.clone());
        domain_service.google_callback(code, state).await
    }
}