use sqlx::PgPool;
use uuid::Uuid;
use ethers::types::Address;

pub struct BlockchainEventsRepository {
    pool: PgPool,
}

impl BlockchainEventsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store NFT mint event in the database
    pub async fn store_nft_mint_event(
        &self,
        to_address: Address,
        token_id: u64,
        collection_id: u64,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query_as::<_, NftMintEvent>(
            r#"
            INSERT INTO nft_mint_events (id, to_address, token_id, collection_id, transaction_hash, block_number, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (transaction_hash, token_id) DO NOTHING
            RETURNING id, to_address, token_id, collection_id, transaction_hash, block_number, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("{:?}", to_address))
        .bind(token_id as i64)
        .bind(collection_id as i64)
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    /// Store collection created event in the database
    pub async fn store_collection_created_event(
        &self,
        collection_id: u64,
        creator_address: Address,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query_as::<_, CollectionEvent>(
            r#"
            INSERT INTO collection_events (id, collection_id, creator_address, transaction_hash, block_number, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (transaction_hash, collection_id) DO NOTHING
            RETURNING id, collection_id, creator_address, transaction_hash, block_number, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(collection_id as i64)
        .bind(format!("{:?}", creator_address))
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    /// Store social media NFT mint event in the database
    pub async fn store_social_media_nft_mint_event(
        &self,
        to_address: Address,
        token_id: u64,
        social_media_id: String,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query_as::<_, SocialMediaNftEvent>(
            r#"
            INSERT INTO social_media_nft_events (id, to_address, token_id, social_media_id, transaction_hash, block_number, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (transaction_hash, token_id) DO NOTHING
            RETURNING id, to_address, token_id, social_media_id, transaction_hash, block_number, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(format!("{:?}", to_address))
        .bind(token_id as i64)
        .bind(social_media_id)
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    /// Get NFT mint events by address
    pub async fn get_nft_mint_events_by_address(
        &self,
        address: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<NftMintEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, NftMintEvent>(
            r#"
            SELECT id, to_address, token_id, collection_id, transaction_hash, block_number, created_at
            FROM nft_mint_events
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

    /// Get collection events by creator address
    pub async fn get_collection_events_by_creator(
        &self,
        creator_address: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<CollectionEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, CollectionEvent>(
            r#"
            SELECT id, collection_id, creator_address, transaction_hash, block_number, created_at
            FROM collection_events
            WHERE creator_address = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(creator_address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
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
            SELECT id, to_address, token_id, social_media_id, transaction_hash, block_number, created_at
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

    /// Get latest block number from events
    pub async fn get_latest_block_number(&self) -> Result<Option<u64>, sqlx::Error> {
        let result = sqlx::query_as::<_, (Option<i64>,)>(
            r#"
            SELECT MAX(block_number) as max_block
            FROM (
                SELECT block_number FROM nft_mint_events
                UNION ALL
                SELECT block_number FROM collection_events
                UNION ALL
                SELECT block_number FROM social_media_nft_events
            ) as all_events
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.and_then(|r| r.0).map(|b| b as u64))
    }
}

// Data models for blockchain events
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NftMintEvent {
    pub id: Uuid,
    pub to_address: String,
    pub token_id: i64,
    pub collection_id: Option<i64>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct CollectionEvent {
    pub id: Uuid,
    pub collection_id: i64,
    pub creator_address: String,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct SocialMediaNftEvent {
    pub id: Uuid,
    pub to_address: String,
    pub token_id: i64,
    pub social_media_id: String,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
