use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Data model for NFT listing events
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NftListingEvent {
    pub id: Uuid,
    pub chain_id: i64,
    pub listing_id: i64,
    pub nft_contract: String,
    pub token_id: i64,
    pub seller_address: String,
    pub price_wei: String,
    pub is_auction: bool,
    pub auction_end_time: Option<DateTime<Utc>>,
    pub reserve_price_wei: Option<String>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub event_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository for NFT listing events
#[derive(Clone)]
pub struct NftListingEventsRepository {
    pool: PgPool,
}

impl NftListingEventsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store NFT listing event in the database
    pub async fn store_nft_listing_event(
        &self,
        chain_id: u64,
        listing_id: u64,
        nft_contract: &str,
        token_id: u64,
        seller_address: &str,
        price_wei: u128,
        is_auction: bool,
        auction_end_time: Option<DateTime<Utc>>,
        reserve_price_wei: Option<u128>,
        tx_hash: &[u8; 32],
        block_number: u64,
        event_type: &str,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));
        let price_numeric = price_wei.to_string();
        let reserve_price_numeric = reserve_price_wei.map(|p| p.to_string());

        sqlx::query(
            r#"
            INSERT INTO nft_listing_events (
                id, chain_id, listing_id, nft_contract, token_id, seller_address,
                price_wei, is_auction, auction_end_time, reserve_price_wei,
                transaction_hash, block_number, event_type, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::numeric, $8, $9, $10::numeric, $11, $12, $13, NOW(), NOW())
            ON CONFLICT (transaction_hash, listing_id, chain_id) DO UPDATE SET
                event_type = EXCLUDED.event_type,
                updated_at = NOW()
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(chain_id as i64)
        .bind(listing_id as i64)
        .bind(nft_contract)
        .bind(token_id as i64)
        .bind(seller_address)
        .bind(price_numeric)
        .bind(is_auction)
        .bind(auction_end_time)
        .bind(reserve_price_numeric)
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .bind(event_type)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get active listings for a specific NFT
    pub async fn get_active_listing_for_nft(
        &self,
        chain_id: u64,
        nft_contract: &str,
        token_id: u64,
    ) -> Result<Option<NftListingEvent>, sqlx::Error> {
        let result = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT * FROM nft_listing_events
            WHERE chain_id = $1
              AND nft_contract = $2
              AND token_id = $3
              AND event_type IN ('LISTED', 'AUCTION_STARTED')
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(chain_id as i64)
        .bind(nft_contract)
        .bind(token_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get all active listings for a seller
    pub async fn get_active_listings_for_seller(
        &self,
        chain_id: u64,
        seller_address: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<NftListingEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT * FROM nft_listing_events
            WHERE chain_id = $1 
              AND seller_address = $2 
              AND event_type IN ('LISTED', 'AUCTION_STARTED')
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(chain_id as i64)
        .bind(seller_address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get listing history for a specific NFT
    pub async fn get_listing_history_for_nft(
        &self,
        chain_id: u64,
        nft_contract: &str,
        token_id: u64,
    ) -> Result<Vec<NftListingEvent>, sqlx::Error> {
        let events = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT * FROM nft_listing_events
            WHERE chain_id = $1 
              AND nft_contract = $2 
              AND token_id = $3
            ORDER BY created_at DESC
            "#,
        )
        .bind(chain_id as i64)
        .bind(nft_contract)
        .bind(token_id as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get current listing status for multiple NFTs
    pub async fn get_listing_status_for_nfts(
        &self,
        chain_id: u64,
        nft_contract: &str,
        token_ids: &[u64],
    ) -> Result<HashMap<u64, NftListingEvent>, sqlx::Error> {
        if token_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let token_ids_i64: Vec<i64> = token_ids.iter().map(|&id| id as i64).collect();
        
        let events = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT DISTINCT ON (token_id) *
            FROM nft_listing_events
            WHERE chain_id = $1 
              AND nft_contract = $2 
              AND token_id = ANY($3)
              AND event_type IN ('LISTED', 'AUCTION_STARTED')
            ORDER BY token_id, created_at DESC
            "#,
        )
        .bind(chain_id as i64)
        .bind(nft_contract)
        .bind(&token_ids_i64)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for event in events {
            result.insert(event.token_id as u64, event);
        }

        Ok(result)
    }

    /// Get auction events that are ending soon
    pub async fn get_auctions_ending_soon(
        &self,
        chain_id: u64,
        hours_ahead: i64,
    ) -> Result<Vec<NftListingEvent>, sqlx::Error> {
        let events = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT * FROM nft_listing_events
            WHERE chain_id = $1 
              AND is_auction = true
              AND event_type = 'AUCTION_STARTED'
              AND auction_end_time IS NOT NULL
              AND auction_end_time <= NOW() + INTERVAL '%s hours'
            ORDER BY auction_end_time ASC
            "#,
        )
        .bind(chain_id as i64)
        .bind(hours_ahead)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get all active listings across the marketplace (basic version)
    pub async fn get_all_active_listings(
        &self,
        chain_id: u64,
        limit: Option<i64>,
        offset: Option<i64>,
        asset_type: Option<u8>,
        min_price_wei: Option<u128>,
        max_price_wei: Option<u128>,
        is_auction: Option<bool>,
    ) -> Result<Vec<NftListingEvent>, sqlx::Error> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let events = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT
                id, chain_id, listing_id, nft_contract, token_id, seller_address,
                price_wei::text, is_auction, auction_end_time,
                reserve_price_wei::text, transaction_hash, block_number,
                event_type, created_at, updated_at
            FROM nft_listing_events
            WHERE chain_id = $1
              AND event_type IN ('LISTED', 'AUCTION_STARTED')
              AND ($5::numeric IS NULL OR price_wei >= $5::numeric)
              AND ($6::numeric IS NULL OR price_wei <= $6::numeric)
              AND ($7::boolean IS NULL OR is_auction = $7::boolean)
              ORDER BY created_at DESC
              LIMIT $2 OFFSET $3
            "#,
        )
        .bind(chain_id as i64)
        .bind(limit)
        .bind(offset)
        .bind(asset_type.map(|at| at as i32)) // asset_type parameter (not used in query but needed for function signature)
        .bind(min_price_wei.map(|p| p as i64))
        .bind(max_price_wei.map(|p| p as i64))
        .bind(is_auction)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Get listing statistics for a seller
    pub async fn get_listing_stats_for_seller(
        &self,
        chain_id: u64,
        seller_address: &str,
    ) -> Result<(i64, i64, i64), sqlx::Error> {
        let result = sqlx::query(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE event_type = 'LISTED') as total_listed,
                COUNT(*) FILTER (WHERE event_type = 'SOLD') as total_sold,
                COUNT(*) FILTER (WHERE event_type = 'UNLISTED') as total_unlisted
            FROM nft_listing_events
            WHERE chain_id = $1 AND seller_address = $2
            "#,
        )
        .bind(chain_id as i64)
        .bind(seller_address)
        .fetch_one(&self.pool)
        .await?;

        let total_listed: i64 = result.get("total_listed");
        let total_sold: i64 = result.get("total_sold");
        let total_unlisted: i64 = result.get("total_unlisted");

        Ok((total_listed, total_sold, total_unlisted))
    }

    /// Get a single listing by ID
    pub async fn get_listing_by_id(
        &self,
        chain_id: u64,
        listing_id: u64,
    ) -> Result<Option<NftListingEvent>, sqlx::Error> {
        let result = sqlx::query_as::<_, NftListingEvent>(
            r#"
            SELECT
                id, chain_id, listing_id, nft_contract, token_id, seller_address,
                price_wei::text, is_auction, auction_end_time,
                reserve_price_wei::text, transaction_hash, block_number,
                event_type, created_at, updated_at
            FROM nft_listing_events
            WHERE chain_id = $1 AND listing_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(chain_id as i64)
        .bind(listing_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }
}
