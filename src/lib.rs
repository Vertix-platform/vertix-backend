pub mod api;
pub mod application;
pub mod domain;
pub mod handlers;
pub mod infrastructure;

// Main exports for external use
pub use handlers::routes::{AppState, create_router};