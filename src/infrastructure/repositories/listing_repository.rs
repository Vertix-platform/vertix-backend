use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Data models for listings
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NftListingData {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub nft_contract: String,
    pub token_id: i64,
    pub price: i64,
    pub description: String,
    pub active: bool,
    pub is_auction: bool,
    pub metadata_uri: Option<String>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NonNftListingData {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub asset_type: i16,
    pub asset_id: String,
    pub price: i64,
    pub description: String,
    pub platform: Option<String>,
    pub identifier: Option<String>,
    pub metadata_uri: Option<String>,
    pub verification_proof: Option<String>,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct SocialMediaNftListingData {
    pub id: Uuid,
    pub listing_id: i64,
    pub creator_address: String,
    pub token_id: i64,
    pub price: i64,
    pub description: String,
    pub social_media_id: String,
    pub signature: String,
    pub active: bool,
    pub is_auction: bool,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Combined listing data for unified queries
#[derive(Debug, Clone)]
pub struct CombinedListingData {
    pub listing_id: i64,
    pub creator_address: String,
    pub listing_type: String,
    pub asset_id: Option<String>,
    pub token_id: Option<i64>,
    pub price: i64,
    pub description: String,
    pub active: bool,
    pub is_auction: bool,
    pub created_at: DateTime<Utc>,
}

pub struct ListingRepository {
    pool: PgPool,
}

impl ListingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // NFT Listings
    pub async fn create_nft_listing(&self, listing: &NftListingData) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, NftListingData>(
            r#"
            INSERT INTO nft_listings (
                id, listing_id, creator_address, nft_contract, token_id, price, description,
                active, is_auction, metadata_uri, transaction_hash, block_number, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (listing_id) DO NOTHING
            RETURNING id, listing_id, creator_address, nft_contract, token_id, price, description,
                     active, is_auction, metadata_uri, transaction_hash, block_number, created_at, updated_at
            "#,
        )
        .bind(listing.id)
        .bind(listing.listing_id)
        .bind(&listing.creator_address)
        .bind(&listing.nft_contract)
        .bind(listing.token_id)
        .bind(listing.price)
        .bind(&listing.description)
        .bind(listing.active)
        .bind(listing.is_auction)
        .bind(&listing.metadata_uri)
        .bind(&listing.transaction_hash)
        .bind(listing.block_number)
        .bind(listing.created_at)
        .bind(listing.updated_at)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_nft_listing(&self, listing_id: i64) -> Result<Option<NftListingData>, sqlx::Error> {
        let row = sqlx::query_as::<_, NftListingData>(
            r#"
            SELECT id, listing_id, creator_address, nft_contract, token_id, price, description,
                   active, is_auction, metadata_uri, transaction_hash, block_number, created_at, updated_at
            FROM nft_listings WHERE listing_id = $1
            "#,
        )
        .bind(listing_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_active_nft_listings(&self, limit: i64, offset: i64) -> Result<Vec<NftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, NftListingData>(
            r#"
            SELECT id, listing_id, creator_address, nft_contract, token_id, price, description,
                   active, is_auction, metadata_uri, transaction_hash, block_number, created_at, updated_at
            FROM nft_listings 
            WHERE active = true 
            ORDER BY created_at DESC 
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    pub async fn search_nft_listings(&self, query: &str, limit: i64, offset: i64) -> Result<Vec<NftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, NftListingData>(
            r#"
            SELECT id, listing_id, creator_address, nft_contract, token_id, price, description,
                   active, is_auction, metadata_uri, transaction_hash, block_number, created_at, updated_at
            FROM nft_listings
            WHERE active = true
            AND to_tsvector('english', description) @@ plainto_tsquery('english', $1)
            ORDER BY ts_rank(to_tsvector('english', description), plainto_tsquery('english', $1)) DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(query)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    // Non-NFT Listings
    pub async fn create_non_nft_listing(&self, listing: &NonNftListingData) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, NonNftListingData>(
            r#"
            INSERT INTO non_nft_listings (
                id, listing_id, creator_address, asset_type, asset_id, price, description,
                platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ON CONFLICT (listing_id) DO NOTHING
            RETURNING id, listing_id, creator_address, asset_type, asset_id, price, description,
                     platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            "#,
        )
        .bind(listing.id)
        .bind(listing.listing_id)
        .bind(&listing.creator_address)
        .bind(listing.asset_type)
        .bind(&listing.asset_id)
        .bind(listing.price)
        .bind(&listing.description)
        .bind(&listing.platform)
        .bind(&listing.identifier)
        .bind(&listing.metadata_uri)
        .bind(&listing.verification_proof)
        .bind(&listing.transaction_hash)
        .bind(listing.block_number)
        .bind(listing.created_at)
        .bind(listing.updated_at)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_non_nft_listing(&self, listing_id: i64) -> Result<Option<NonNftListingData>, sqlx::Error> {
        let row = sqlx::query_as::<_, NonNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, asset_type, asset_id, price, description,
                   platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            FROM non_nft_listings WHERE listing_id = $1
            "#,
        )
        .bind(listing_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_active_non_nft_listings(&self, limit: i64, offset: i64) -> Result<Vec<NonNftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, NonNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, asset_type, asset_id, price, description,
                   platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            FROM non_nft_listings 
            ORDER BY created_at DESC 
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    pub async fn get_non_nft_listings_by_asset_type(&self, asset_type: i16, limit: i64, offset: i64) -> Result<Vec<NonNftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, NonNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, asset_type, asset_id, price, description,
                   platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            FROM non_nft_listings 
            WHERE asset_type = $1
            ORDER BY created_at DESC 
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(asset_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    pub async fn search_non_nft_listings(&self, query: &str, limit: i64, offset: i64) -> Result<Vec<NonNftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, NonNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, asset_type, asset_id, price, description,
                   platform, identifier, metadata_uri, verification_proof, transaction_hash, block_number, created_at, updated_at
            FROM non_nft_listings 
            WHERE to_tsvector('english', description) @@ plainto_tsquery('english', $1)
            ORDER BY ts_rank(to_tsvector('english', description), plainto_tsquery('english', $1)) DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(query)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    // Social Media NFT Listings
    pub async fn create_social_media_nft_listing(&self, listing: &SocialMediaNftListingData) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, SocialMediaNftListingData>(
            r#"
            INSERT INTO social_media_nft_listings (
                id, listing_id, creator_address, token_id, price, description,
                social_media_id, signature, active, is_auction, transaction_hash, block_number, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (listing_id) DO NOTHING
            RETURNING id, listing_id, creator_address, token_id, price, description,
                     social_media_id, signature, active, is_auction, transaction_hash, block_number, created_at, updated_at
            "#,
        )
        .bind(listing.id)
        .bind(listing.listing_id)
        .bind(&listing.creator_address)
        .bind(listing.token_id)
        .bind(listing.price)
        .bind(&listing.description)
        .bind(&listing.social_media_id)
        .bind(&listing.signature)
        .bind(listing.active)
        .bind(listing.is_auction)
        .bind(&listing.transaction_hash)
        .bind(listing.block_number)
        .bind(listing.created_at)
        .bind(listing.updated_at)
        .fetch_optional(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_social_media_nft_listing(&self, listing_id: i64) -> Result<Option<SocialMediaNftListingData>, sqlx::Error> {
        let row = sqlx::query_as::<_, SocialMediaNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, token_id, price, description,
                   social_media_id, signature, active, is_auction, transaction_hash, block_number, created_at, updated_at
            FROM social_media_nft_listings WHERE listing_id = $1
            "#,
        )
        .bind(listing_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_active_social_media_nft_listings(&self, limit: i64, offset: i64) -> Result<Vec<SocialMediaNftListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, SocialMediaNftListingData>(
            r#"
            SELECT id, listing_id, creator_address, token_id, price, description,
                   social_media_id, signature, active, is_auction, transaction_hash, block_number, created_at, updated_at
            FROM social_media_nft_listings 
            WHERE active = true 
            ORDER BY created_at DESC 
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(listings)
    }

    // General listing operations
    pub async fn get_listings_by_creator(&self, creator_address: &str, limit: i64, offset: i64) -> Result<Vec<CombinedListingData>, sqlx::Error> {
        // Combine all listing types for a creator using UNION
        let listings = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<i64>, i64, String, bool, bool, DateTime<Utc>)>(
            r#"
            SELECT 
                listing_id, creator_address, 'nft' as listing_type, 
                nft_contract as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM nft_listings 
            WHERE creator_address = $1 AND active = true
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'non_nft' as listing_type,
                asset_id, NULL as token_id, price, description,
                true as active, false as is_auction, created_at
            FROM non_nft_listings 
            WHERE creator_address = $1
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'social_media_nft' as listing_type,
                social_media_id as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM social_media_nft_listings 
            WHERE creator_address = $1 AND active = true
            
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(creator_address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        // Convert to CombinedListingData
        let combined_listings = listings
            .into_iter()
            .map(|(listing_id, creator_address, listing_type, asset_id, token_id, price, description, active, is_auction, created_at)| {
                CombinedListingData {
                    listing_id,
                    creator_address,
                    listing_type,
                    asset_id,
                    token_id,
                    price,
                    description,
                    active,
                    is_auction,
                    created_at,
                }
            })
            .collect();

        Ok(combined_listings)
    }

    /// Get total count of listings by creator
    pub async fn get_listing_count_by_creator(&self, creator_address: &str) -> Result<i64, sqlx::Error> {
        let result = sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT COUNT(*) as total
            FROM (
                SELECT listing_id FROM nft_listings WHERE creator_address = $1 AND active = true
                UNION ALL
                SELECT listing_id FROM non_nft_listings WHERE creator_address = $1
                UNION ALL
                SELECT listing_id FROM social_media_nft_listings WHERE creator_address = $1 AND active = true
            ) as all_listings
            "#,
        )
        .bind(creator_address)
        .fetch_one(&self.pool)
        .await?;

        Ok(result.0)
    }

    /// Get listings by price range
    pub async fn get_listings_by_price_range(&self, min_price: i64, max_price: i64, limit: i64, offset: i64) -> Result<Vec<CombinedListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<i64>, i64, String, bool, bool, DateTime<Utc>)>(
            r#"
            SELECT 
                listing_id, creator_address, 'nft' as listing_type, 
                nft_contract as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM nft_listings 
            WHERE active = true AND price BETWEEN $1 AND $2
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'non_nft' as listing_type,
                asset_id, NULL as token_id, price, description,
                true as active, false as is_auction, created_at
            FROM non_nft_listings 
            WHERE price BETWEEN $1 AND $2
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'social_media_nft' as listing_type,
                social_media_id as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM social_media_nft_listings 
            WHERE active = true AND price BETWEEN $1 AND $2
            
            ORDER BY price ASC, created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(min_price)
        .bind(max_price)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let combined_listings = listings
            .into_iter()
            .map(|(listing_id, creator_address, listing_type, asset_id, token_id, price, description, active, is_auction, created_at)| {
                CombinedListingData {
                    listing_id,
                    creator_address,
                    listing_type,
                    asset_id,
                    token_id,
                    price,
                    description,
                    active,
                    is_auction,
                    created_at,
                }
            })
            .collect();

        Ok(combined_listings)
    }

    /// Search across all listing types
    pub async fn search_all_listings(&self, query: &str, limit: i64, offset: i64) -> Result<Vec<CombinedListingData>, sqlx::Error> {
        let listings = sqlx::query_as::<_, (i64, String, String, Option<String>, Option<i64>, i64, String, bool, bool, DateTime<Utc>)>(
            r#"
            SELECT 
                listing_id, creator_address, 'nft' as listing_type, 
                nft_contract as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM nft_listings 
            WHERE active = true AND to_tsvector('english', description) @@ plainto_tsquery('english', $1)
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'non_nft' as listing_type,
                asset_id, NULL as token_id, price, description,
                true as active, false as is_auction, created_at
            FROM non_nft_listings 
            WHERE to_tsvector('english', description) @@ plainto_tsquery('english', $1)
            
            UNION ALL
            
            SELECT 
                listing_id, creator_address, 'social_media_nft' as listing_type,
                social_media_id as asset_id, token_id, price, description,
                active, is_auction, created_at
            FROM social_media_nft_listings 
            WHERE active = true AND to_tsvector('english', description) @@ plainto_tsquery('english', $1)
            
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(query)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let combined_listings = listings
            .into_iter()
            .map(|(listing_id, creator_address, listing_type, asset_id, token_id, price, description, active, is_auction, created_at)| {
                CombinedListingData {
                    listing_id,
                    creator_address,
                    listing_type,
                    asset_id,
                    token_id,
                    price,
                    description,
                    active,
                    is_auction,
                    created_at,
                }
            })
            .collect();

        Ok(combined_listings)
    }
}
