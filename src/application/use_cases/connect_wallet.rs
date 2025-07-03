use sqlx::PgPool;
use uuid::Uuid;

use crate::api::dto::ConnectWalletRequest;
use crate::domain::{User, ServiceError};
use crate::domain::services::AuthService as DomainAuthService;

pub struct ConnectWalletUseCase {
    domain_auth_service: DomainAuthService,
}

impl ConnectWalletUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(
        &self,
        user_id: Option<Uuid>,
        request: ConnectWalletRequest,
    ) -> Result<User, ServiceError> {
        // Convert API DTO to domain model
        let domain_request = crate::domain::models::ConnectWalletRequest {
            wallet_address: request.wallet_address,
            signature: request.signature,
            nonce: request.nonce,
        };

        // Business logic: Connect wallet with signature verification
        self.domain_auth_service.connect_wallet(user_id, domain_request).await
    }
}