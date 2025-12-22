//! SHA3-256 hash function implementation (using sha3 crate).
//!
//! This module provides SHA3-256 functionality using the well-audited
//! `sha3` crate from RustCrypto.
//!
//! # Algorithm Details
//!
//! - Based on Keccak sponge construction
//! - Block size: 1088 bits (136 bytes) for SHA3-256
//! - Capacity: 512 bits
//! - Digest size: 256 bits (32 bytes)
//! - Security: 128-bit collision resistance
//!
//! # Note
//!
//! Unlike the SHA-256 implementation in this crate, SHA3-256 uses
//! an external library for production-quality implementation.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::Result;
use sha3::{Digest, Sha3_256 as Sha3_256Lib};

use crate::hash::HashAlgorithm;

/// SHA3-256 hasher implementation (wrapper around sha3 crate).
#[derive(Debug, Clone)]
pub struct Sha3_256;

impl Sha3_256 {
    /// Creates a new SHA3-256 hasher.
    ///
    /// # Returns
    ///
    /// New SHA3-256 hasher instance
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::hash::sha3_256::Sha3_256;
    ///
    /// let sha3_256 = Sha3_256::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl HashAlgorithm for Sha3_256 {
    fn hash_file(&self, file_path: &Path) -> Result<String> {
        // Handle stdin special case
        if file_path.to_str() == Some("-") {
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            return self.hash_data(&data);
        }

        // Read file in chunks to handle large files efficiently
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha3_256Lib::new();

        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    fn hash_data(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha3_256Lib::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests SHA3-256 with empty input (known test vector).
    #[test]
    fn test_sha3_256_empty() {
        let sha3 = Sha3_256::new();
        let hash = sha3.hash_data(b"").unwrap();
        assert_eq!(
            hash,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    /// Tests SHA3-256 with "abc" input (known test vector).
    #[test]
    fn test_sha3_256_abc() {
        let sha3 = Sha3_256::new();
        let hash = sha3.hash_data(b"abc").unwrap();
        assert_eq!(
            hash,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}