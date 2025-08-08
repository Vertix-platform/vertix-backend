pub mod contract_tests;
#[cfg(test)]
pub mod auth_tests;
#[cfg(test)]
pub mod validation_tests;

// Re-export test modules for easy access
pub use contract_tests::*;