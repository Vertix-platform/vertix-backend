use axum::{Router, Server};
use dotenvy::dotenv;
use std::net::SocketAddr;
use tracing_subscriber;

mod config;
mod models;
mod routes;
mod services;

#[tokio::main]
async fn main() {
    // Load .env file
    dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create Axum router
    let app = Router::new()
        .merge(routes::create_routes())
        .layer(tower_http::cors::CorsLayer::permissive()); // For local testing

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server running at http://{}", addr);
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}