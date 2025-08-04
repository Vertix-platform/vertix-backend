use axum::Router;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use sqlx::PgPool;

use crate::application::services::AuthService;
use crate::api::v1::create_v1_router;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth_service: AuthService,
}

pub async fn create_router(pool: PgPool) -> Router {
    let auth_service = AuthService::new(pool.clone());

    Router::new()
        .nest("/v1", create_v1_router(auth_service))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
}