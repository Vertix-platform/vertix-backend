use sqlx::PgPool;

use crate::domain::ServiceError;
use crate::domain::services::AuthService as DomainAuthService;

pub struct CreateNonceUseCase {
    domain_auth_service: DomainAuthService,
}

impl CreateNonceUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(&self, wallet_address: &str) -> Result<String, ServiceError> {
        // Business logic: Create nonce for wallet address
        self.domain_auth_service.create_nonce(wallet_address).await
    }
}