use axum::Router;

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
    let app_state = AppState {
        pool,
        auth_service,
    };

    Router::new()
        .nest("/api/v1", create_v1_router(app_state))
        .layer(TraceLayer::new_for_http())
}