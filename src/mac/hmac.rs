//! Hash-based Message Authentication Code (HMAC) implementation.
//!
//! HMAC is a specific construction for creating a message authentication code
//! using a cryptographic hash function in combination with a secret key.
//!
//! # Algorithm
//!
//! HMAC is defined as:
//!
//! HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
//!
//! where:
//! - `H` is a cryptographic hash function
//! - `K` is the secret key
//! - `m` is the message
//! - `opad` = 0x5c repeated B times
//! - `ipad` = 0x36 repeated B times
//! - `B` is the block size of the hash function (64 bytes for SHA-256)
//!
//! # Security Properties
//!
//! - Provides message authentication and integrity verification
//! - Security depends on the underlying hash function
//! - Resistant to length extension attacks (unlike naive H(K||m))
//!
//! # References
//!
//! - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
//! - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)

use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};

use crate::hash::HashType;

/// Hash-based Message Authentication Code (HMAC) implementation.
#[derive(Debug, Clone)]
pub struct HMAC {
    /// Secret key for HMAC computation.
    key: Vec<u8>,
    /// Hash function to use (e.g., SHA-256).
    hash_function: HashType,
    /// Block size of the hash function in bytes.
    block_size: usize,
}

impl HMAC {
    /// Creates a new HMAC instance with the specified key and hash function.
    ///
    /// # Arguments
    ///
    /// * `key` - Secret key for HMAC (arbitrary length)
    /// * `hash_function` - Hash function to use (e.g., `HashType::Sha256`)
    ///
    /// # Returns
    ///
    /// New HMAC instance
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::mac::hmac::HMAC;
    /// use cryptocore::hash::HashType;
    ///
    /// let key = b"secret-key";
    /// let hmac = HMAC::new(key, HashType::Sha256);
    /// ```
    pub fn new(key: &[u8], hash_function: HashType) -> Self {
        // Standard HMAC block size for SHA-256 family
        let block_size = 64;

        let key_vec = key.to_vec();

        Self {
            key: key_vec,
            hash_function,
            block_size,
        }
    }

    /// Processes the key according to HMAC specification.
    ///
    /// If key is longer than block size, it is hashed first.
    /// If key is shorter than block size, it is padded with zeros.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Processed key of exactly `block_size` bytes
    /// * `Err(anyhow::Error)` - If key processing fails
    fn get_processed_key(&self) -> Result<Vec<u8>> {
        let mut processed_key = if self.key.len() > self.block_size {
            // Hash key if it's longer than block size
            let hasher = self.hash_function.create_hasher();
            let hash_result = hasher
                .hash_data(&self.key)
                .map_err(|e| anyhow!("Failed to hash key: {}", e))?;

            hex::decode(&hash_result)
                .map_err(|e| anyhow!("Failed to decode hash: {}", e))?
        } else {
            self.key.to_vec()
        };

        // Pad with zeros if shorter than block size
        if processed_key.len() < self.block_size {
            processed_key.resize(self.block_size, 0);
        }

        Ok(processed_key)
    }

    /// XORs two byte arrays of equal length.
    ///
    /// # Arguments
    ///
    /// * `a` - First byte array
    /// * `b` - Second byte array
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - XOR result
    /// * `Err(anyhow::Error)` - If arrays have different lengths
    fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
        if a.len() != b.len() {
            return Err(anyhow!("Buffers must be same length for XOR"));
        }

        Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
    }

    /// Computes HMAC for a message, returning raw bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to compute HMAC for
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - HMAC value as raw bytes
    /// * `Err(anyhow::Error)` - If HMAC computation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::mac::hmac::HMAC;
    /// use cryptocore::hash::HashType;
    ///
    /// let hmac = HMAC::new(b"key", HashType::Sha256);
    /// let result = hmac.compute_bytes(b"message").unwrap();
    /// assert_eq!(result.len(), 32); // SHA-256 produces 32 bytes
    /// ```
    pub fn compute_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        // HMAC constants
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let processed_key = self.get_processed_key()?;

        // Create inner and outer padded keys
        let k_ipad = HMAC::xor_bytes(&processed_key, &ipad)?;
        let k_opad = HMAC::xor_bytes(&processed_key, &opad)?;

        // Inner hash: H((K ⊕ ipad) || message)
        let mut inner_data = k_ipad;
        inner_data.extend_from_slice(message);

        let hasher = self.hash_function.create_hasher();
        let inner_hash = hasher
            .hash_data(&inner_data)
            .map_err(|e| anyhow!("Inner hash failed: {}", e))?;
        let inner_hash_bytes = hex::decode(&inner_hash)
            .map_err(|e| anyhow!("Failed to decode inner hash: {}", e))?;

        // Outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);

        let outer_hash = hasher
            .hash_data(&outer_data)
            .map_err(|e| anyhow!("Outer hash failed: {}", e))?;

        hex::decode(&outer_hash).map_err(|e| anyhow!("Failed to decode outer hash: {}", e))
    }

    /// Computes HMAC for a message, returning hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `message` - Message to compute HMAC for
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - HMAC value as hexadecimal string
    /// * `Err(anyhow::Error)` - If HMAC computation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::mac::hmac::HMAC;
    /// use cryptocore::hash::HashType;
    ///
    /// let hmac = HMAC::new(b"key", HashType::Sha256);
    /// let result = hmac.compute(b"message").unwrap();
    /// assert_eq!(result.len(), 64); // 32 bytes = 64 hex characters
    /// ```
    #[allow(dead_code)]
    pub fn compute(&self, message: &[u8]) -> Result<String> {
        let bytes = self.compute_bytes(message)?;
        Ok(hex::encode(bytes))
    }

    /// Computes HMAC for a file, returning hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file to compute HMAC for, or "-" for stdin
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - HMAC value as hexadecimal string
    /// * `Err(anyhow::Error)` - If file cannot be read or HMAC computation fails
    #[allow(dead_code)]
    pub fn compute_file(&self, file_path: &Path) -> Result<String> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let processed_key = self.get_processed_key()?;
        let k_ipad = HMAC::xor_bytes(&processed_key, &ipad)?;
        let k_opad = HMAC::xor_bytes(&processed_key, &opad)?;

        // Compute inner hash over file with prefix
        let inner_hash = self.hash_file_with_prefix(file_path, &k_ipad)?;
        let inner_hash_bytes = hex::decode(&inner_hash)
            .map_err(|e| anyhow!("Failed to decode inner hash: {}", e))?;

        // Compute outer hash
        let hasher = self.hash_function.create_hasher();
        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);
        let outer_hash = hasher.hash_data(&outer_data)?;

        Ok(outer_hash)
    }

    /// Computes hash of file data with a prefix.
    ///
    /// Used internally for HMAC file computation.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file, or "-" for stdin
    /// * `prefix` - Bytes to prepend to file data (must be `block_size` bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Hash as hexadecimal string
    /// * `Err(anyhow::Error)` - If file cannot be read or hashing fails
    fn hash_file_with_prefix(&self, file_path: &Path, prefix: &[u8]) -> Result<String> {
        if prefix.len() != self.block_size {
            return Err(anyhow!("Prefix must be exactly {} bytes", self.block_size));
        }

        if file_path.to_str() == Some("-") {
            // Read from stdin
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            let mut combined = prefix.to_vec();
            combined.extend_from_slice(&data);
            return self.hash_function.create_hasher().hash_data(&combined);
        }

        // Read from file
        let file_content = std::fs::read(file_path)?;
        let mut combined = prefix.to_vec();
        combined.extend_from_slice(&file_content);

        self.hash_function.create_hasher().hash_data(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests HMAC with RFC 2104 test case 1.
    #[test]
    fn test_rfc_2104_test_case_1() -> Result<()> {
        let key = vec![0x0b; 20];
        let data = b"Hi There";

        let hmac = HMAC::new(&key, HashType::Sha256);
        let result = hmac.compute(data)?;

        // Note: This is a basic test, not verifying against known RFC vectors
        println!("RFC 2104 Test 1 (conceptual): {}", result);

        // Verify deterministic output
        let result2 = hmac.compute(data)?;
        assert_eq!(result, result2);

        Ok(())
    }

    /// Tests HMAC key processing (padding and hashing).
    #[test]
    fn test_key_padding() -> Result<()> {
        // Test short key (padded with zeros)
        let short_key = b"short";
        let hmac_short = HMAC::new(short_key, HashType::Sha256);
        let result_short = hmac_short.compute(b"test")?;

        // Test long key (hashed first)
        let long_key = vec![0x42; 100];
        let hmac_long = HMAC::new(&long_key, HashType::Sha256);
        let result_long = hmac_long.compute(b"test")?;

        // Test exact block size key
        let exact_key = vec![0x42; 64];
        let hmac_exact = HMAC::new(&exact_key, HashType::Sha256);
        let result_exact = hmac_exact.compute(b"test")?;

        // All should produce valid (but different) HMACs
        assert_ne!(result_short, result_long);
        assert_ne!(result_short, result_exact);
        assert_ne!(result_long, result_exact);

        Ok(())
    }

    /// Tests HMAC edge cases (empty key, boundary lengths).
    #[test]
    fn test_edge_cases() -> Result<()> {
        // Empty key
        let empty_key = b"";
        let hmac_empty = HMAC::new(empty_key, HashType::Sha256);
        let result_empty = hmac_empty.compute(b"data")?;

        // Key length 63 (one less than block size)
        let key_63 = vec![0x01; 63];
        let hmac_63 = HMAC::new(&key_63, HashType::Sha256);
        let result_63 = hmac_63.compute(b"data")?;

        // Key length 65 (one more than block size)
        let key_65 = vec![0x02; 65];
        let hmac_65 = HMAC::new(&key_65, HashType::Sha256);
        let result_65 = hmac_65.compute(b"data")?;

        // All should produce valid non-empty HMACs
        assert!(!result_empty.is_empty());
        assert!(!result_63.is_empty());
        assert!(!result_65.is_empty());

        Ok(())
    }
}