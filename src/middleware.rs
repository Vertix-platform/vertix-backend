use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::{Response},
    body::Body,
};
use crate::auth::{verify_jwt};
use uuid::Uuid;

pub async fn auth_middleware<B>(
    mut req: Request<B>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization header format".to_string()))?;

    let user_id = verify_jwt(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {:?}", e)))?;

    let user_id = Uuid::parse_str(&user_id)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid user ID".to_string()))?;

    // Add user_id to request extensions
    let extensions = req.extensions_mut();
    extensions.insert(user_id);

    let (parts, _) = req.into_parts();
    let req = Request::from_parts(parts, Body::empty());
    Ok(next.run(req).await)
}