use sqlx::PgPool;

use crate::api::dto::LoginResponse;
use crate::domain::ServiceError;
use crate::domain::services::AuthService as DomainAuthService;

pub struct RegisterUserUseCase {
    domain_auth_service: DomainAuthService,
}

impl RegisterUserUseCase {
    pub fn new(pool: PgPool) -> Self {
        Self {
            domain_auth_service: DomainAuthService::new(pool),
        }
    }

    pub async fn execute(
        &self,
        email: &str,
        password: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<LoginResponse, ServiceError> {
        // Business logic: Register user and generate token
        let user = self.domain_auth_service.register(email, password, first_name, last_name).await?;
        let token = self.domain_auth_service.generate_jwt(&user.id.to_string())?;

        Ok(LoginResponse { token })
    }
}