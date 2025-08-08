use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::validation::ValidationError;
use crate::domain::services::{ServiceError, ContractError};

/// API error response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub success: bool,
    pub error: String,
    pub error_code: String,
    pub details: Option<serde_json::Value>,
    pub validation_errors: Option<Vec<ValidationError>>,
}

/// API error types with corresponding HTTP status codes
#[derive(Debug)]
pub enum ApiError {
    // Client errors (4xx)
    BadRequest(String),
    ValidationError(Vec<ValidationError>),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    UnprocessableEntity(String),

    // Server errors (5xx)
    InternalServerError(String),
    ServiceUnavailable(String),

    // Contract-specific errors
    ContractError(ContractError),

    // Service-specific errors
    ServiceError(ServiceError),
}

impl ApiError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::ValidationError(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::ContractError(_) => StatusCode::BAD_REQUEST, // Most contract errors are client-side
            ApiError::ServiceError(service_error) => match service_error {
                ServiceError::InvalidCredentials => StatusCode::UNAUTHORIZED,
                ServiceError::InvalidSignature => StatusCode::UNAUTHORIZED,
                ServiceError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }

    /// Get the error code string for this error
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "BAD_REQUEST",
            ApiError::ValidationError(_) => "VALIDATION_ERROR",
            ApiError::Unauthorized(_) => "UNAUTHORIZED",
            ApiError::Forbidden(_) => "FORBIDDEN",
            ApiError::NotFound(_) => "NOT_FOUND",
            ApiError::Conflict(_) => "CONFLICT",
            ApiError::UnprocessableEntity(_) => "UNPROCESSABLE_ENTITY",
            ApiError::InternalServerError(_) => "INTERNAL_SERVER_ERROR",
            ApiError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            ApiError::ContractError(_) => "CONTRACT_ERROR",
            ApiError::ServiceError(_) => "SERVICE_ERROR",
        }
    }

    /// Get the error message
    pub fn message(&self) -> String {
        match self {
            ApiError::BadRequest(msg) => msg.clone(),
            ApiError::ValidationError(errors) => {
                if errors.len() == 1 {
                    format!("Validation failed: {}", errors[0].message)
                } else {
                    format!("Validation failed with {} errors", errors.len())
                }
            },
            ApiError::Unauthorized(msg) => msg.clone(),
            ApiError::Forbidden(msg) => msg.clone(),
            ApiError::NotFound(msg) => msg.clone(),
            ApiError::Conflict(msg) => msg.clone(),
            ApiError::UnprocessableEntity(msg) => msg.clone(),
            ApiError::InternalServerError(msg) => msg.clone(),
            ApiError::ServiceUnavailable(msg) => msg.clone(),
            ApiError::ContractError(contract_error) => format!("Contract error: {}", contract_error),
            ApiError::ServiceError(service_error) => format!("Service error: {}", service_error),
        }
    }

    /// Convert validation errors to API error
    pub fn from_validation_errors(errors: Vec<ValidationError>) -> Self {
        ApiError::ValidationError(errors)
    }

    /// Create a bad request error with context
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::BadRequest(message.into())
    }

    /// Create an internal server error with context
    pub fn internal_server_error(message: impl Into<String>) -> Self {
        ApiError::InternalServerError(message.into())
    }

    /// Create a not found error with context
    pub fn not_found(message: impl Into<String>) -> Self {
        ApiError::NotFound(message.into())
    }

    /// Create an unauthorized error with context
    pub fn unauthorized(message: impl Into<String>) -> Self {
        ApiError::Unauthorized(message.into())
    }

    /// Create a conflict error with context
    pub fn conflict(message: impl Into<String>) -> Self {
        ApiError::Conflict(message.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        let message = self.message();

        let validation_errors = match &self {
            ApiError::ValidationError(errors) => Some(errors.clone()),
            _ => None,
        };

        let details = match &self {
            ApiError::ContractError(contract_error) => {
                Some(serde_json::json!({
                    "contract_error_type": format!("{:?}", contract_error)
                }))
            },
            ApiError::ServiceError(service_error) => {
                Some(serde_json::json!({
                    "service_error_type": format!("{:?}", service_error)
                }))
            },
            _ => None,
        };

        let error_response = ApiErrorResponse {
            success: false,
            error: message,
            error_code: error_code.to_string(),
            details,
            validation_errors,
        };

        (status, Json(error_response)).into_response()
    }
}

impl From<ContractError> for ApiError {
    fn from(error: ContractError) -> Self {
        ApiError::ContractError(error)
    }
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        ApiError::ServiceError(error)
    }
}

impl From<Vec<ValidationError>> for ApiError {
    fn from(errors: Vec<ValidationError>) -> Self {
        ApiError::ValidationError(errors)
    }
}

impl From<std::env::VarError> for ApiError {
    fn from(error: std::env::VarError) -> Self {
        ApiError::InternalServerError(format!("Environment variable error: {}", error))
    }
}

/// Type alias for API results
pub type ApiResult<T> = Result<T, ApiError>;

/// Utility trait for converting results to API results
pub trait IntoApiResult<T> {
    fn into_api_result(self) -> ApiResult<T>;
}

impl<T, E> IntoApiResult<T> for Result<T, E>
where
    E: Into<ApiError>,
{
    fn into_api_result(self) -> ApiResult<T> {
        self.map_err(|e| e.into())
    }
}

/// Helper macro for creating API errors
#[macro_export]
macro_rules! api_error {
    (bad_request, $msg:expr) => {
        ApiError::bad_request($msg)
    };
    (not_found, $msg:expr) => {
        ApiError::not_found($msg)
    };
    (unauthorized, $msg:expr) => {
        ApiError::unauthorized($msg)
    };
    (internal, $msg:expr) => {
        ApiError::internal_server_error($msg)
    };
}

pub use api_error;
