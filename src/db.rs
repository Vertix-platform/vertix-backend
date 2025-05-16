use sqlx::{PgPool, Error};
use tracing::info;
use crate::models::{UpdateProfileRequest, User};
use uuid::Uuid;

pub async fn init_pool() -> Result<PgPool, Error> {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&database_url)
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to database: {}", e);
            e
        })?;
    info!("Connected to database");

    // Check migrations
    let migrations: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT version, description, success FROM _sqlx_migrations ORDER BY version"
    )
    .fetch_all(&pool)
    .await?;
    info!("Applied migrations: {:?}", migrations);

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to run migrations: {}", e);
            e
        })?;
    info!("Migrations applied");

    // List tables
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    )
    .fetch_all(&pool)
    .await?;
    info!("Tables in database: {:?}", tables);

    info!("Database pool initialized");
    Ok(pool)
}

pub async fn create_user(
    pool: &PgPool,
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
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn create_google_user(
    pool: &PgPool,
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
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn find_user_by_google_id(pool: &PgPool, google_id: &str) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE google_id = $1"
    )
    .bind(google_id)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn update_wallet_address(pool: &PgPool, user_id: Uuid, wallet_address: &str) -> Result<User, sqlx::Error> {
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
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn find_user_by_wallet_address(pool: &PgPool, wallet_address: &str) -> Result<Option<User>, sqlx::Error> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at FROM users WHERE wallet_address = $1"
    )
    .bind(wallet_address)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn create_nonce(pool: &PgPool, wallet_address: &str) -> Result<String, sqlx::Error> {
    let nonce = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO nonces (wallet_address, nonce) VALUES ($1, $2)"
    )
    .bind(wallet_address)
    .bind(&nonce)
    .execute(pool)
    .await?;
    Ok(nonce)
}

pub async fn verify_nonce(pool: &PgPool, wallet_address: &str, nonce: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "SELECT nonce FROM nonces WHERE wallet_address = $1 AND nonce = $2"
    )
    .bind(wallet_address)
    .bind(nonce)
    .fetch_optional(pool)
    .await?;
    if result.is_some() {
        // Delete nonce after verification to prevent reuse
        sqlx::query(
            "DELETE FROM nonces WHERE wallet_address = $1 AND nonce = $2"
        )
        .bind(wallet_address)
        .bind(nonce)
        .execute(pool)
        .await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// pub async fn cleanup_nonces(pool: &PgPool) -> Result<(), sqlx::Error> {
//     sqlx::query(
//         "DELETE FROM nonces WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 hour'"
//     )
//     .execute(pool)
//     .await?;
//     Ok(())
// }

pub async fn update_user_profile(
    pool: &PgPool,
    user_id: Uuid,
    request: UpdateProfileRequest,
) -> Result<User, sqlx::Error> {
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET username = COALESCE($1, username),
            is_verified = COALESCE($2, is_verified)
        WHERE id = $3
        RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
        "#
    )
    .bind(request.username)
    .bind(request.is_verified)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

// pub async fn update_kyc_status(pool: &PgPool, user_id: Uuid, is_verified: bool) -> Result<User, sqlx::Error> {
//     let user = sqlx::query_as::<_, User>(
//         r#"
//         UPDATE users
//         SET is_verified = $1
//         WHERE id = $2
//         RETURNING id, email, password_hash, google_id, first_name, last_name, username, wallet_address, is_verified, created_at
//         "#
//     )
//     .bind(is_verified)
//     .bind(user_id)
//     .fetch_one(pool)
//     .await?;
//     Ok(user)
// }