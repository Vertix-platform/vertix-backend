pub mod api;
pub mod application;
pub mod domain;
pub mod handlers;
pub mod infrastructure;
pub mod tests;

// Main exports for external use
pub use handlers::routes::{AppState, create_router};