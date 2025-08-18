use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{post, get},
    Router,
};
use serde_json::json;
use std::sync::Arc;

use crate::application::services::admin_service::AdminService;
use crate::domain::models::{
    AddSupportedNftContractRequest, RemoveSupportedNftContractRequest,
    SetPlatformFeeRequest, SetFeeRecipientRequest,
    ResolveDisputeRequest, SetEscrowDurationRequest,
    PauseContractRequest, UnpauseContractRequest,
};

/// Admin API state
pub struct AdminApiState {
    pub admin_service: Arc<AdminService>,
}

/// Create admin API router
pub fn create_admin_router(state: AdminApiState) -> Router {
    Router::new()
        .route("/governance/add-supported-nft", post(add_supported_nft_contract))
        .route("/governance/remove-supported-nft", post(remove_supported_nft_contract))
        .route("/governance/set-platform-fee", post(set_platform_fee))
        .route("/governance/set-fee-recipient", post(set_fee_recipient))
        .route("/escrow/resolve-dispute", post(resolve_dispute))
        .route("/escrow/set-duration", post(set_escrow_duration))
        .route("/contracts/pause", post(pause_contract))
        .route("/contracts/unpause", post(unpause_contract))
        .route("/admin/address", get(get_admin_address))
        .with_state(Arc::new(state))
}

// ============ GOVERNANCE ENDPOINTS ============

/// Add an NFT contract as supported
async fn add_supported_nft_contract(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<AddSupportedNftContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.add_supported_nft_contract(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

/// Remove an NFT contract from supported list
async fn remove_supported_nft_contract(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<RemoveSupportedNftContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.remove_supported_nft_contract(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

/// Set platform fee
async fn set_platform_fee(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<SetPlatformFeeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.set_platform_fee(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

/// Set fee recipient
async fn set_fee_recipient(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<SetFeeRecipientRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.set_fee_recipient(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

// ============ ESCROW ENDPOINTS ============

/// Resolve a dispute in escrow
async fn resolve_dispute(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<ResolveDisputeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.resolve_dispute(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

/// Set escrow duration
async fn set_escrow_duration(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<SetEscrowDurationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.set_escrow_duration(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

// ============ CONTRACT MANAGEMENT ENDPOINTS ============

/// Pause a contract
async fn pause_contract(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<PauseContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.pause_contract(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

/// Unpause a contract
async fn unpause_contract(
    State(state): State<Arc<AdminApiState>>,
    Json(request): Json<UnpauseContractRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.admin_service.unpause_contract(request).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "data": response
        }))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": e.to_string()
            }))
        ))
    }
}

// ============ UTILITY ENDPOINTS ============

/// Get admin wallet address
async fn get_admin_address(
    State(state): State<Arc<AdminApiState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let address = state.admin_service.get_admin_address();
    Ok(Json(json!({
        "success": true,
        "data": {
            "admin_address": address
        }
    })))
}
