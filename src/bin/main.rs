use dotenvy::dotenv;
use std::net::SocketAddr;
use tracing::{info, error};
use tracing_subscriber;

use vertix_backend::infrastructure::db::postgres::init_pool;
use vertix_backend::handlers::routes::create_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Initialize database pool
    let pool = init_pool().await.map_err(|e| {
        error!("Failed to initialize database pool: {}", e);
        e
    })?;

    // Create router
    let app = create_router(pool).await;

    // Load server address from environment
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    // Start the server
    info!("Server running at http://{}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await?,
        app.into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    info!("Received shutdown signal");
}