use sqlx::PgPool;
use uuid::Uuid;

/// Repository for social media NFT events
#[derive(Clone)]
pub struct SocialMediaEventsRepository {
    pool: PgPool,
}

impl SocialMediaEventsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store social media NFT mint event in the database
    pub async fn store_social_media_nft_mint_event(
        &self,
        chain_id: u64,
        to_address: &str,
        token_id: u64,
        social_media_id: &str,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query(
            r#"
            INSERT INTO social_media_nft_events (id, chain_id, to_address, token_id, social_media_id, transaction_hash, block_number, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (transaction_hash, token_id, chain_id) DO NOTHING
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(chain_id as i64)
        .bind(to_address)
        .bind(token_id as i64)
        .bind(social_media_id)
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get social media NFT events by address
    pub async fn get_social_media_nft_events_by_address(
        &self,
        address: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<SocialMediaNftEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, SocialMediaNftEvent>(
            r#"
            SELECT id, chain_id, to_address, token_id, social_media_id, transaction_hash, block_number, created_at
            FROM social_media_nft_events
            WHERE to_address = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get latest block number from social media NFT events
    pub async fn get_latest_block_number(&self) -> Result<Option<u64>, sqlx::Error> {
        let result = sqlx::query_as::<_, (Option<i64>,)>(
            r#"
            SELECT MAX(block_number) as max_block
            FROM social_media_nft_events
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.and_then(|r| r.0).map(|b| b as u64))
    }

    /// Store social media NFT minted event in the database (alias for compatibility)
    pub async fn store_social_media_nft_minted_event(
        &self,
        chain_id: u64,
        to_address: &str,
        token_id: u64,
        social_media_id: &str,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        self.store_social_media_nft_mint_event(chain_id, to_address, token_id, social_media_id, tx_hash, block_number).await
    }
}

/// Data model for social media NFT events
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct SocialMediaNftEvent {
    pub id: Uuid,
    pub chain_id: i64,
    pub to_address: String,
    pub token_id: i64,
    pub social_media_id: String,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
