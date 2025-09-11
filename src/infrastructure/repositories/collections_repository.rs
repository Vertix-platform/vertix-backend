use sqlx::PgPool;
use uuid::Uuid;
use ethers::types::Address;
use hex;

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Collection {
    pub id: Uuid,
    pub collection_id: i64,
    pub chain_id: i64,
    pub name: String,
    pub symbol: String,
    pub image: Option<String>,
    pub max_supply: i64,
    pub current_supply: i64,
    pub creator_address: String,
    pub transaction_hash: String,
    pub block_number: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct CollectionsRepository {
    pool: PgPool,
}

impl CollectionsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store collection in the database
    pub async fn store_collection(
        &self,
        collection_id: u64,
        chain_id: u64,
        name: &str,
        symbol: &str,
        image: Option<&str>,
        max_supply: u64,
        current_supply: u64,
        creator_address: Address,
        tx_hash: &[u8; 32],
        block_number: u64,
    ) -> Result<(), sqlx::Error> {
        let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

        sqlx::query(
            r#"
            INSERT INTO collections (id, collection_id, chain_id, name, symbol, image, max_supply, current_supply, creator_address, transaction_hash, block_number, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
            ON CONFLICT (collection_id, chain_id) DO UPDATE SET
                name = EXCLUDED.name,
                symbol = EXCLUDED.symbol,
                image = EXCLUDED.image,
                max_supply = EXCLUDED.max_supply,
                current_supply = EXCLUDED.current_supply,
                creator_address = EXCLUDED.creator_address,
                transaction_hash = EXCLUDED.transaction_hash,
                block_number = EXCLUDED.block_number,
                updated_at = NOW()
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(collection_id as i64)
        .bind(chain_id as i64)
        .bind(name)
        .bind(symbol)
        .bind(image)
        .bind(max_supply as i64)
        .bind(current_supply as i64)
        .bind(format!("{:?}", creator_address))
        .bind(tx_hash_hex)
        .bind(block_number as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all collections
    pub async fn get_all_collections(&self) -> Result<Vec<Collection>, sqlx::Error> {
        let collections = sqlx::query_as::<_, Collection>(
            r#"
            SELECT id, collection_id, chain_id, name, symbol, image, max_supply, current_supply, creator_address, transaction_hash, block_number, created_at, updated_at
            FROM collections
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(collections)
    }

    /// Get collection by ID
    pub async fn get_collection_by_id(&self, collection_id: u64) -> Result<Option<Collection>, sqlx::Error> {
        let collection = sqlx::query_as::<_, Collection>(
            r#"
            SELECT id, collection_id, chain_id, name, symbol, image, max_supply, current_supply, creator_address, transaction_hash, block_number, created_at, updated_at
            FROM collections
            WHERE collection_id = $1
            "#,
        )
        .bind(collection_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(collection)
    }

    /// Get collections by creator address
    pub async fn get_collections_by_creator(&self, creator_address: &str) -> Result<Vec<Collection>, sqlx::Error> {
        let collections = sqlx::query_as::<_, Collection>(
            r#"
            SELECT id, collection_id, chain_id, name, symbol, image, max_supply, current_supply, creator_address, transaction_hash, block_number, created_at, updated_at
            FROM collections
            WHERE creator_address = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(creator_address)
        .fetch_all(&self.pool)
        .await?;

        Ok(collections)
    }

    /// Update collection supply
    pub async fn update_collection_supply(&self, collection_id: u64, current_supply: u64) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE collections
            SET current_supply = $1, updated_at = NOW()
            WHERE collection_id = $2
            "#,
        )
        .bind(current_supply as i64)
        .bind(collection_id as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get total collections count
    pub async fn get_total_collections_count(&self) -> Result<i64, sqlx::Error> {
        let result = sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT COUNT(*) as count
            FROM collections
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result.0)
    }
}
