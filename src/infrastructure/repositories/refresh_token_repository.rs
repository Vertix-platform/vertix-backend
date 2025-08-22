use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use crate::domain::RefreshToken;

pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub async fn create_refresh_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
        family_id: Uuid,
    ) -> Result<RefreshToken, sqlx::Error> {
        let token_hash = self.hash_token(token);
        
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, family_id) 
             VALUES ($1, $2, $3, $4) 
             RETURNING id, user_id, token_hash, expires_at, created_at, revoked_at, family_id"
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at)
        .bind(family_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(refresh_token)
    }

    pub async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>, sqlx::Error> {
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            "SELECT id, user_id, token_hash, expires_at, created_at, revoked_at, family_id 
             FROM refresh_tokens 
             WHERE token_hash = $1 AND revoked_at IS NULL"
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(refresh_token)
    }

    pub async fn find_by_family_id(&self, family_id: Uuid) -> Result<Vec<RefreshToken>, sqlx::Error> {
        let refresh_tokens = sqlx::query_as::<_, RefreshToken>(
            "SELECT id, user_id, token_hash, expires_at, created_at, revoked_at, family_id 
             FROM refresh_tokens 
             WHERE family_id = $1 
             ORDER BY created_at DESC"
        )
        .bind(family_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(refresh_tokens)
    }

    pub async fn revoke_token(&self, token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE refresh_tokens 
             SET revoked_at = NOW() 
             WHERE token_hash = $1"
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn revoke_family(&self, family_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE refresh_tokens 
             SET revoked_at = NOW() 
             WHERE family_id = $1"
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn revoke_user_tokens(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE refresh_tokens 
             SET revoked_at = NOW() 
             WHERE user_id = $1"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens 
             WHERE expires_at < NOW()"
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_active_token_count(&self, user_id: Uuid) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) 
             FROM refresh_tokens 
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }
}
