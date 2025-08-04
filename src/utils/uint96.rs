use ethers::types::U256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Uint96Error {
    #[error("Value exceeds uint96 maximum (2^96 - 1)")]
    Overflow,
}

/// A wrapper type representing a uint96 value (stored as u128 since Rust has no native u96).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uint96(pub u128);

impl Uint96 {
    /// Maximum value a uint96 can hold (2^96 - 1).
    pub const MAX: Uint96 = Uint96((1 << 96) - 1);

    /// Converts a U256 to Uint96 with bounds checking.
    pub fn from_u256(value: U256) -> Result<Self, Uint96Error> {
        let max_u96 = U256::from(2).pow(U256::from(96)) - 1;
        if value > max_u96 {
            return Err(Uint96Error::Overflow);
        }
        Ok(Uint96(value.as_u128()))
    }

    /// Converts to U256 (for compatibility with ethers-rs).
    pub fn to_u256(&self) -> U256 {
        U256::from(self.0)
    }
}

// Implement From<u64> for convenience
impl From<u64> for Uint96 {
    fn from(value: u64) -> Self {
        Uint96(value as u128)
    }
}