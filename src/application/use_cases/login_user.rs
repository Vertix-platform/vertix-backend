use sqlx::PgPool;

use crate::api::dto::LoginResponse;
use crate::domain::ServiceError;
use crate::domain::services::AuthService as DomainAuthService;

pub struct LoginUserUseCase {
    domain_auth_service: DomainAuthService,
}

impl LoginUserUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(
        &self,
        email: &str,
        password: &str,
    ) -> Result<LoginResponse, ServiceError> {
        // Business logic: Login user and generate token pair
        self.domain_auth_service.login(email, password).await
    }
}