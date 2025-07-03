use axum::Router;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use sqlx::PgPool;

use crate::application::services::AuthService;
use crate::api::v1::create_v1_router;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

pub fn create_router(state: AppState) -> Router {
    let auth_service = AuthService::new(state.pool);

    Router::new()
        .nest("/v1", create_v1_router(auth_service))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
}