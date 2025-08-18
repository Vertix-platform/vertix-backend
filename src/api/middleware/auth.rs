use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, HeaderMap, request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::handlers::AppState;

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

pub async fn auth_middleware(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, String> {
    let auth_header = headers.get(header::AUTHORIZATION)
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    let token = auth_header.strip_prefix("Bearer ")
        .ok_or("Invalid Bearer token")?;

    let user_id_str = app_state.auth_service.verify_jwt(token)
        .map_err(|e| format!("JWT verification failed: {:?}", e))?;

    let user_id = Uuid::parse_str(&user_id_str)
        .map_err(|_| "Invalid user ID")?;

    // Add the authenticated user to request extensions
    request.extensions_mut().insert(AuthenticatedUser { user_id });

    Ok(next.run(request).await)
}

// Extractor for getting the authenticated user in handlers
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "User not authenticated"))
    }
}