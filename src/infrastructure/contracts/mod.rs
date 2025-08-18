// Contract integration module
// This module handles all smart contract interactions

pub mod abis;
pub mod addresses;
pub mod client;
pub mod admin_client;
pub mod types;
pub mod config;
pub mod utils;


// Re-export main components for easy access
pub use client::ContractClient;
pub use admin_client::AdminContractClient;
pub use types::*;