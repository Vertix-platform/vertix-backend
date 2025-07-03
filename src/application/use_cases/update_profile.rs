use sqlx::PgPool;
use uuid::Uuid;

use crate::api::dto::UpdateProfileRequest;
use crate::domain::{User, ServiceError};
use crate::domain::services::AuthService as DomainAuthService;

pub struct UpdateProfileUseCase {
    domain_auth_service: DomainAuthService,
}

impl UpdateProfileUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(
        &self,
        user_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<User, ServiceError> {
        // Convert API DTO to domain model
        let domain_request = crate::domain::models::UpdateProfileRequest {
            username: request.username,
        };

        // Business logic: Update user profile
        self.domain_auth_service.update_profile(user_id, domain_request).await
    }
}