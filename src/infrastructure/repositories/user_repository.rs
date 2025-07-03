use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::models::{UpdateProfileRequest, User};

pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, email, password_hash, first_name, last_name, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
            "#
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(password_hash)
        .bind(first_name)
        .bind(last_name)
        .bind(false)
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn create_google_user(
        &self,
        email: &str,
        google_id: &str,
        first_name: &str,
        last_name: &str,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, email, google_id, first_name, last_name, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
            "#
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(google_id)
        .bind(first_name)
        .bind(last_name)
        .bind(true)
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_google_id(&self, google_id: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE google_id = $1"
        )
        .bind(google_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn update_wallet_address(&self, user_id: Uuid, wallet_address: &str) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET wallet_address = $1
            WHERE id = $2
            RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
            "#
        )
        .bind(wallet_address)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_wallet_address(&self, wallet_address: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE wallet_address = $1"
        )
        .bind(wallet_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(user)
    }

    pub async fn create_nonce(&self, wallet_address: &str) -> Result<String, sqlx::Error> {
        let nonce = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO nonces (wallet_address, nonce) VALUES ($1, $2)"
        )
        .bind(wallet_address)
        .bind(&nonce)
        .execute(&self.pool)
        .await?;
        Ok(nonce)
    }

    pub async fn verify_nonce(&self, wallet_address: &str, nonce: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "SELECT nonce FROM nonces WHERE wallet_address = $1 AND nonce = $2"
        )
        .bind(wallet_address)
        .bind(nonce)
        .fetch_optional(&self.pool)
        .await?;
        if result.is_some() {
            // Delete nonce after verification to prevent reuse
            sqlx::query(
                "DELETE FROM nonces WHERE wallet_address = $1 AND nonce = $2"
            )
            .bind(wallet_address)
            .bind(nonce)
            .execute(&self.pool)
            .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn update_profile(
        &self,
        user_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET username = COALESCE($1, username)
            WHERE id = $2
            RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
            "#
        )
        .bind(request.username)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }
}