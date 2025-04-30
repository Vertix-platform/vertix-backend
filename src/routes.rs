use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use crate::config::Config;
use crate::models::{ErrorResponse, ValueRequest, ValueResponse, VerifyRequest, VerifyResponse};
use crate::services::{calculate_value, verify_asset};

pub fn create_routes() -> Router {
    let config = Config::load();
    Router::new()
        .route("/verify", get(verify).with_state(config.clone()))
        .route("/value", get(value).with_state(config))
}

async fn verify(
    Query(params): Query<VerifyRequest>,
    axum::extract::State(config): axum::extract::State<Config>,
) -> Result<Json<VerifyResponse>, AppError> {
    if params.asset_type.is_empty() || params.asset_id.is_empty() {
        return Err(AppError::InvalidInput("asset_type or asset_id is empty".to_string()));
    }
    let response = verify_asset(¶ms.asset_type, ¶ms.asset_id, ¶ms.proof, &config).await;
    Ok(Json(response))
}

async fn value(
    Query(params): Query<ValueRequest>,
    axum::extract::State(config): axum::extract::State<Config>,
) -> Result<Json<ValueResponse>, AppError> {
    if params.asset_type.is_empty() || params.asset_id.is_empty() {
        return Err(AppError::InvalidInput("asset_type or asset_id is empty".to_string()));
    }
    let response = calculate_value(¶ms.asset_type, ¶ms.asset_id, &config).await;
    Ok(Json(response))
}

pub enum AppError {
    InvalidInput(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
        };
        let body = Json(ErrorResponse {
            error: error_message,
        });
        (status, body).into_response()
    }
}