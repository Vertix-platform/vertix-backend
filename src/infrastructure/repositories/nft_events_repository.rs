use sqlx::PgPool;
use uuid::Uuid;

/// Repository for NFT mint events
#[derive(Clone)]
pub struct NftEventsRepository {
    pool: PgPool,
}

impl NftEventsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }



    /// Store NFT mint event with metadata in the database
    pub async fn store_nft_mint_event(
        &self,
        chain_id: u64,
        to_address: &str,
        token_id: u64,
        collection_id: Option<u64>,
        tx_hash: &[u8; 32],
        block_number: u64,
        token_uri: &str,
        metadata_hash: &str,
        royalty_recipient: &str,
        royalty_bps: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query(
            r#"
            INSERT INTO nft_mint_events (id, chain_id, to_address, token_id, collection_id, transaction_hash, block_number, token_uri, metadata_hash, royalty_recipient, royalty_bps, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
            ON CONFLICT (transaction_hash, token_id, chain_id) DO UPDATE SET
                token_uri = EXCLUDED.token_uri,
                metadata_hash = EXCLUDED.metadata_hash,
                royalty_recipient = EXCLUDED.royalty_recipient,
                royalty_bps = EXCLUDED.royalty_bps
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(chain_id as i64)
        .bind(to_address)
        .bind(token_id as i64)
        .bind(collection_id.map(|id| id as i64))
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .bind(token_uri)
        .bind(metadata_hash)
        .bind(royalty_recipient)
        .bind(royalty_bps as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get NFT mint event by token ID and owner address (since we don't have contract mapping)
    pub async fn get_nft_mint_event_by_token_and_owner(
        &self,
        chain_id: u64,
        token_id: u64,
        owner_address: &str,
    ) -> Result<Option<NftMintEvent>, sqlx::Error> {
        let result = sqlx::query_as::<_, NftMintEvent>(
            r#"
            SELECT * FROM nft_mint_events
            WHERE chain_id = $1
              AND token_id = $2
              AND to_address = $3
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(chain_id as i64)
        .bind(token_id as i64)
        .bind(owner_address.to_lowercase())
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
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

        // Normalize address to lowercase for case-insensitive comparison
        let normalized_address = address.to_lowercase();

        let events = sqlx::query_as::<_, NftMintEvent>(
            r#"
            SELECT id, chain_id, to_address, token_id, collection_id, transaction_hash, block_number, token_uri, metadata_hash, royalty_recipient, royalty_bps, created_at
            FROM nft_mint_events
            WHERE LOWER(to_address) = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(normalized_address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get latest block number from NFT mint events
    pub async fn get_latest_block_number(&self) -> Result<Option<u64>, sqlx::Error> {
        let result = sqlx::query_as::<_, (Option<i64>,)>(
            r#"
            SELECT MAX(block_number) as max_block
            FROM nft_mint_events
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.and_then(|r| r.0).map(|b| b as u64))
    }
}

/// Data model for NFT mint events
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NftMintEvent {
    pub id: Uuid,
    pub chain_id: i64,
    pub to_address: String,
    pub token_id: i64,
    pub collection_id: Option<i64>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub token_uri: String,
    pub metadata_hash: String,
    pub royalty_recipient: String,
    pub royalty_bps: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
