//! Block cipher modes of operation.
//!
//! This module provides implementations of various block cipher modes
//! for AES-128 encryption. Each mode provides different security properties
//! and use cases.
//!
//! # Implemented Modes
//!
//! - [`Ecb`] - Electronic Codebook (not recommended for most uses)
//! - [`Cbc`] - Cipher Block Chaining (provides diffusion)
//! - [`Cfb`] - Cipher Feedback (stream cipher mode)
//! - [`Ofb`] - Output Feedback (stream cipher mode)
//! - [`Ctr`] - Counter mode (parallelizable, widely used)
//! - [`Gcm`] - Galois/Counter Mode (authenticated encryption)
//!
//! # Security Recommendations
//!
//! - **Avoid ECB** for encrypting more than one block of data
//! - **Prefer GCM** when authentication is required
//! - **Use CTR or CBC** for confidentiality-only requirements
//! - **Always use unique IVs/nonces** for each encryption

pub mod cbc;
pub mod cfb;
pub mod ctr;
pub mod ecb;
pub mod gcm;
pub mod ofb;

use anyhow::Result;

/// Trait for block cipher modes of operation.
///
/// Defines the common interface for all encryption modes.
/// Each mode must implement both encryption and decryption operations.
pub trait BlockMode {
    /// Encrypts plaintext using the specified initialization vector.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `iv` - Initialization vector (requirements vary by mode)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Encrypted ciphertext
    /// * `Err(anyhow::Error)` - If encryption fails
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext using the specified initialization vector.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Data to decrypt
    /// * `iv` - Initialization vector (must match encryption IV)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(anyhow::Error)` - If decryption fails
    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for creating mode instances from raw key bytes.
///
/// Provides a standardized way to create mode instances from
/// a 16-byte key array.
pub trait FromKeyBytes {
    /// Creates a new mode instance from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - New mode instance
    /// * `Err(anyhow::Error)` - If key is invalid
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self>
    where
        Self: Sized;
}

// Re-exports for convenient access
pub use cbc::Cbc;
pub use cfb::Cfb;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::Gcm;
pub use ofb::Ofb;

// Implement FromKeyBytes for all modes
impl FromKeyBytes for Cbc {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Cbc::new_from_bytes(key)
    }
}

impl FromKeyBytes for Cfb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Cfb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ofb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ofb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ctr {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ctr::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ecb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ecb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Gcm {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Gcm::new_from_bytes(key)
    }
}

#[cfg(test)]
#[allow(dead_code)]
/// Test helper function to create any mode from key bytes.
///
/// # Type Parameters
///
/// * `M` - Mode type implementing `FromKeyBytes`
///
/// # Arguments
///
/// * `key` - 16-byte AES key
///
/// # Returns
///
/// * `Ok(M)` - Created mode instance
/// * `Err(anyhow::Error)` - If creation fails
pub fn create_mode_from_bytes<M: FromKeyBytes>(key: &[u8; 16]) -> Result<M> {
    M::from_key_bytes(key)
}