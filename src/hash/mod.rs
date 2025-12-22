//! Hash function implementations.
//!
//! This module provides implementations of cryptographic hash functions
//! with a uniform interface for computing message digests.
//!
//! # Available Algorithms
//!
//! - [`sha256`] - SHA-256 implementation (from scratch)
//! - [`sha3_256`] - SHA3-256 implementation (via sha3 crate)
//!
//! # Usage
//!
//! ```
//! use cryptocore::hash::{HashAlgorithm, HashType};
//!
//! // Create a hasher by type
//! let hash_type = HashType::Sha256;
//! let hasher = hash_type.create_hasher();
//! let hash = hasher.hash_data(b"Hello, world!").unwrap();
//!
//! // Or use specific implementation
//! use cryptocore::hash::sha256::Sha256;
//! let sha256 = Sha256::new();
//! let hash = sha256.hash_data(b"Hello, world!").unwrap();
//! ```

use std::path::Path;

use anyhow::Result;

pub mod sha256;
pub mod sha3_256;

pub use sha256::Sha256;
pub use sha3_256::Sha3_256;

/// Supported hash algorithm types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    /// SHA-256 (SHA-2 family, 256-bit output)
    Sha256,
    /// SHA3-256 (SHA-3 family, 256-bit output)
    Sha3_256,
}

impl HashType {
    /// Converts a string to a `HashType`.
    ///
    /// # Arguments
    ///
    /// * `s` - String representation of hash algorithm
    ///
    /// # Returns
    ///
    /// * `Some(HashType)` - If string matches a supported algorithm
    /// * `None` - If string doesn't match any supported algorithm
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::hash::HashType;
    ///
    /// assert_eq!(HashType::from_str("sha256"), Some(HashType::Sha256));
    /// assert_eq!(HashType::from_str("SHA256"), Some(HashType::Sha256));
    /// assert_eq!(HashType::from_str("sha3-256"), Some(HashType::Sha3_256));
    /// assert_eq!(HashType::from_str("md5"), None);
    /// ```
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha256" => Some(Self::Sha256),
            "sha3-256" => Some(Self::Sha3_256),
            _ => None,
        }
    }

    /// Creates a hasher instance for this hash type.
    ///
    /// # Returns
    ///
    /// Boxed hasher implementing `HashAlgorithm`
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::hash::HashType;
    ///
    /// let hash_type = HashType::Sha256;
    /// let hasher = hash_type.create_hasher();
    /// let hash = hasher.hash_data(b"test").unwrap();
    /// ```
    pub fn create_hasher(&self) -> Box<dyn HashAlgorithm> {
        match self {
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha3_256 => Box::new(Sha3_256::new()),
        }
    }
}

/// Trait for cryptographic hash algorithms.
pub trait HashAlgorithm {
    /// Computes the hash of a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file to hash, or "-" for stdin
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Hexadecimal hash digest
    /// * `Err(anyhow::Error)` - If file cannot be read or hashing fails
    #[allow(dead_code)]
    fn hash_file(&self, file_path: &Path) -> Result<String>;

    /// Computes the hash of data in memory.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Hexadecimal hash digest
    /// * `Err(anyhow::Error)` - If hashing fails
    fn hash_data(&self, data: &[u8]) -> Result<String>;
}