pub mod v1;
pub mod dto;
pub mod middleware;
pub mod validation;
pub mod errors;

// Re-export specific items to avoid naming conflicts
pub use v1::{
    register_handler, login_handler, google_auth_handler, google_callback_handler,
    connect_wallet_handler, get_nonce_handler, profile_handler, update_profile_handler,
    create_v1_router
};
pub use dto::*;
pub use middleware::AuthenticatedUser;