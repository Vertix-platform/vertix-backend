use serde::{Deserialize, Serialize};
use ethers::types::Address;

/// Validation error types for API requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, Vec<ValidationError>>;

/// Validation utilities for API requests
pub struct Validator;

impl Validator {
    /// Validate Ethereum address format
    pub fn validate_ethereum_address(address: &str, field_name: &str) -> Result<(), ValidationError> {
        if address.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Address cannot be empty".to_string(),
            });
        }

        // Remove 0x prefix if present
        let clean_address = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        // Check if it's exactly 40 hex characters
        if clean_address.len() != 40 {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Address must be 40 characters long (excluding 0x prefix)".to_string(),
            });
        }

        // Check if all characters are valid hex
        if !clean_address.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Address must contain only hexadecimal characters".to_string(),
            });
        }

        // Try to parse as ethers Address to validate checksum
        if address.parse::<Address>().is_err() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Invalid Ethereum address format".to_string(),
            });
        }

        Ok(())
    }

    /// Validate IPFS URI format
    pub fn validate_ipfs_uri(uri: &str, field_name: &str) -> Result<(), ValidationError> {
        if uri.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "URI cannot be empty".to_string(),
            });
        }

        // IPFS URI should start with ipfs://
        if !uri.starts_with("ipfs://") {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "URI must be a valid IPFS URI (starting with ipfs://)".to_string(),
            });
        }

        // Extract the hash part
        let hash = &uri[7..]; // Remove "ipfs://" prefix

        // Basic IPFS hash validation (should be around 46 characters for v0 hashes)
        if hash.len() < 10 || hash.len() > 100 {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Invalid IPFS hash length".to_string(),
            });
        }

        Ok(())
    }

    /// Validate hex string format (for metadata hash, signature, etc.)
    pub fn validate_hex_string(hex_str: &str, field_name: &str, expected_length: Option<usize>) -> Result<(), ValidationError> {
        if hex_str.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot be empty", field_name),
            });
        }

        // Remove 0x prefix if present
        let clean_hex = if hex_str.starts_with("0x") {
            &hex_str[2..]
        } else {
            hex_str
        };

        // Check if all characters are valid hex
        if !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must contain only hexadecimal characters", field_name),
            });
        }

        // Check expected length if provided
        if let Some(expected) = expected_length {
            if clean_hex.len() != expected {
                return Err(ValidationError {
                    field: field_name.to_string(),
                    message: format!("{} must be exactly {} characters long (excluding 0x prefix)", field_name, expected),
                });
            }
        }

        // Ensure even number of characters (pairs of hex digits)
        if clean_hex.len() % 2 != 0 {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must have an even number of characters", field_name),
            });
        }

        Ok(())
    }

    /// Validate basis points (0-10000, representing 0-100%)
    pub fn validate_basis_points(bps: u16, field_name: &str) -> Result<(), ValidationError> {
        if bps > 10000 {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: "Basis points cannot exceed 10000 (100%)".to_string(),
            });
        }
        Ok(())
    }

    /// Validate social media platform
    pub fn validate_social_media_platform(platform: &str, field_name: &str) -> Result<(), ValidationError> {
        let valid_platforms = ["twitter", "instagram", "facebook"];
        if !valid_platforms.contains(&platform.to_lowercase().as_str()) {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("Platform must be one of: {}", valid_platforms.join(", ")),
            });
        }
        Ok(())
    }

    /// Validate string is not empty and within length limits
    pub fn validate_string(value: &str, field_name: &str, min_length: usize, max_length: usize) -> Result<(), ValidationError> {
        if value.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot be empty", field_name),
            });
        }

        if value.len() < min_length {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must be at least {} characters long", field_name, min_length),
            });
        }

        if value.len() > max_length {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot exceed {} characters", field_name, max_length),
            });
        }

        Ok(())
    }

    /// Validate URL format
    pub fn validate_url(url: &str, field_name: &str) -> Result<(), ValidationError> {
        if url.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot be empty", field_name),
            });
        }

        // Basic URL validation - check if it starts with http:// or https://
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must be a valid HTTP/HTTPS URL", field_name),
            });
        }

        // Additional basic checks
        if url.len() < 10 || url.contains(' ') {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must be a valid HTTP/HTTPS URL", field_name),
            });
        }

        Ok(())
    }

    /// Validate numeric string (for price values)
    pub fn validate_numeric_string(value: &str, field_name: &str) -> Result<(), ValidationError> {
        if value.is_empty() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot be empty", field_name),
            });
        }

        // Try to parse as decimal number
        if value.parse::<f64>().is_err() {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must be a valid number", field_name),
            });
        }

        // Check for negative values
        if value.starts_with('-') {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} cannot be negative", field_name),
            });
        }

        Ok(())
    }

    /// Validate positive integer
    pub fn validate_positive_integer(value: u64, field_name: &str) -> Result<(), ValidationError> {
        if value == 0 {
            return Err(ValidationError {
                field: field_name.to_string(),
                message: format!("{} must be greater than 0", field_name),
            });
        }
        Ok(())
    }

    /// Combine multiple validation results
    pub fn combine_results(results: Vec<Result<(), ValidationError>>) -> ValidationResult<()> {
        let errors: Vec<ValidationError> = results
            .into_iter()
            .filter_map(|result| result.err())
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Trait for validating API request types
pub trait Validate {
    fn validate(&self) -> ValidationResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ethereum_address() {
        // Valid address
        assert!(Validator::validate_ethereum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "wallet_address").is_ok());
        
        // Invalid format
        assert!(Validator::validate_ethereum_address("invalid", "wallet_address").is_err());
        
        // Empty address
        assert!(Validator::validate_ethereum_address("", "wallet_address").is_err());
        
        // Wrong length
        assert!(Validator::validate_ethereum_address("0x123", "wallet_address").is_err());
    }

    #[test]
    fn test_validate_hex_string() {
        // Valid hex
        assert!(Validator::validate_hex_string("0x1234abcd", "hash", Some(8)).is_ok());
        
        // Invalid hex characters
        assert!(Validator::validate_hex_string("0x123xyz", "hash", None).is_err());
        
        // Wrong length
        assert!(Validator::validate_hex_string("0x123", "hash", Some(8)).is_err());
        
        // Odd number of characters
        assert!(Validator::validate_hex_string("0x123", "hash", None).is_err());
    }

    #[test]
    fn test_validate_basis_points() {
        // Valid basis points
        assert!(Validator::validate_basis_points(500, "royalty_bps").is_ok());
        assert!(Validator::validate_basis_points(10000, "royalty_bps").is_ok());
        
        // Invalid basis points
        assert!(Validator::validate_basis_points(10001, "royalty_bps").is_err());
    }

    #[test]
    fn test_validate_social_media_platform() {
        // Valid platforms
        assert!(Validator::validate_social_media_platform("twitter", "platform").is_ok());
        assert!(Validator::validate_social_media_platform("Instagram", "platform").is_ok());
        
        // Invalid platform
        assert!(Validator::validate_social_media_platform("tiktok", "platform").is_err());
    }
}
