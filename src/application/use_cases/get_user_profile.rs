use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{User, ServiceError};
use crate::domain::services::AuthService as DomainAuthService;

pub struct GetUserProfileUseCase {
    domain_auth_service: DomainAuthService,
}

impl GetUserProfileUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(&self, user_id: Uuid) -> Result<User, ServiceError> {
        // Business logic: Get user profile
        self.domain_auth_service.find_user_by_id(user_id)
            .await?
            .ok_or(ServiceError::InvalidCredentials)
    }
}