//! Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
//!
//! This module provides cryptographically secure random number generation
//! using OpenSSL's RAND_bytes implementation. It generates keys, IVs,
//! salts, and other random data required for cryptographic operations.
//!
//! # Security Notes
//!
//! All functions in this module use cryptographically secure random
//! number generation suitable for cryptographic keys and nonces.
//!
//! # Examples
//!
//! ```
//! use cryptocore::csprng::Csprng;
//!
//! // Generate a random AES key
//! let key = Csprng::generate_key().unwrap();
//! assert_eq!(key.len(), 16);
//!
//! // Generate a random IV
//! let iv = Csprng::generate_iv().unwrap();
//! assert_eq!(iv.len(), 16);
//!
//! // Generate a random salt for PBKDF2
//! let salt = Csprng::generate_salt().unwrap();
//! assert_eq!(salt.len(), 16);
//! ```

use anyhow::{anyhow, Result};
use openssl::rand;

/// Size of cryptographic keys in bytes (AES-128)
const KEY_SIZE: usize = 16;

/// Size of initialization vectors in bytes
const IV_SIZE: usize = 16;

/// Size of salts for key derivation in bytes
const SALT_SIZE: usize = 16;

/// CSPRNG utility struct providing cryptographic random number generation.
///
/// This is a zero-sized type (struct with no fields) that provides
/// static methods for generating cryptographically secure random data.
#[derive(Debug, Clone, Copy)]
pub struct Csprng;

impl Csprng {
    /// Generates a cryptographically secure random AES-128 key.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; KEY_SIZE])` - A 16-byte random key
    /// * `Err(anyhow::Error)` - If random number generation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::csprng::Csprng;
    ///
    /// let key = Csprng::generate_key().unwrap();
    /// assert_eq!(key.len(), 16);
    /// ```
    pub fn generate_key() -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        rand::rand_bytes(&mut key)?;
        Ok(key)
    }

    /// Generates a cryptographically secure random initialization vector.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; IV_SIZE])` - A 16-byte random IV
    /// * `Err(anyhow::Error)` - If random number generation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::csprng::Csprng;
    ///
    /// let iv = Csprng::generate_iv().unwrap();
    /// assert_eq!(iv.len(), 16);
    /// ```
    pub fn generate_iv() -> Result<[u8; IV_SIZE]> {
        let mut iv = [0u8; IV_SIZE];
        rand::rand_bytes(&mut iv)?;
        Ok(iv)
    }

    /// Generates a cryptographically secure random salt.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; SALT_SIZE])` - A 16-byte random salt
    /// * `Err(anyhow::Error)` - If random number generation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::csprng::Csprng;
    ///
    /// let salt = Csprng::generate_salt().unwrap();
    /// assert_eq!(salt.len(), 16);
    /// ```
    pub fn generate_salt() -> Result<[u8; SALT_SIZE]> {
        let mut salt = [0u8; SALT_SIZE];
        rand::rand_bytes(&mut salt)?;
        Ok(salt)
    }

    /// Generates a cryptographically secure random nonce of specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Desired size of the nonce in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector of random bytes of the specified size
    /// * `Err(anyhow::Error)` - If random number generation fails
    #[allow(dead_code)]
    pub fn generate_nonce(size: usize) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; size];
        rand::rand_bytes(&mut nonce)?;
        Ok(nonce)
    }

    /// Generates cryptographically secure random bytes of specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of random bytes to generate
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector of random bytes of the specified size
    /// * `Err(anyhow::Error)` - If random number generation fails
    ///
    /// # Note
    ///
    /// Returns an empty vector if `size` is 0.
    #[allow(dead_code)]
    pub fn generate_random_bytes(size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut bytes = vec![0u8; size];
        rand::rand_bytes(&mut bytes)?;
        Ok(bytes)
    }

    /// Generates a large amount of cryptographically secure random data.
    ///
    /// This is an alias for `generate_random_bytes` for semantic clarity.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of random bytes to generate
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector of random bytes of the specified size
    /// * `Err(anyhow::Error)` - If random number generation fails
    #[allow(dead_code)]
    pub fn generate_large_random_data(size: usize) -> Result<Vec<u8>> {
        Self::generate_random_bytes(size)
    }

    /// Tests the randomness of the CSPRNG by checking for duplicates.
    ///
    /// Generates 1000 keys, IVs, and salts and verifies they are all unique.
    /// This is a diagnostic function and should not be used in production.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all generated values are unique
    /// * `Err(anyhow::Error)` - If any duplicates are found
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::csprng::Csprng;
    ///
    /// // Run randomness test (may take a moment)
    /// if let Err(e) = Csprng::test_randomness() {
    ///     eprintln!("Randomness test failed: {}", e);
    /// }
    /// ```
    #[allow(dead_code)]
    pub fn test_randomness() -> Result<()> {
        let mut key_set = std::collections::HashSet::new();
        let mut iv_set = std::collections::HashSet::new();
        let mut salt_set = std::collections::HashSet::new();

        for _ in 0..1000 {
            let key = Self::generate_key()?;
            let iv = Self::generate_iv()?;
            let salt = Self::generate_salt()?;

            if !key_set.insert(key) {
                return Err(anyhow!("Duplicate key generated!"));
            }
            if !iv_set.insert(iv) {
                return Err(anyhow!("Duplicate IV generated!"));
            }
            if !salt_set.insert(salt) {
                return Err(anyhow!("Duplicate salt generated!"));
            }
        }

        println!("[SUCCESS] All 1000 keys, IVs, and salts are unique!");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that generated keys are unique.
    #[test]
    fn test_key_generation() -> Result<()> {
        let key1 = Csprng::generate_key()?;
        let key2 = Csprng::generate_key()?;

        assert_ne!(key1, key2);
        Ok(())
    }

    /// Tests that generated IVs are unique.
    #[test]
    fn test_iv_generation() -> Result<()> {
        let iv1 = Csprng::generate_iv()?;
        let iv2 = Csprng::generate_iv()?;

        assert_ne!(iv1, iv2);
        Ok(())
    }

    /// Tests that generated salts are unique.
    #[test]
    fn test_salt_generation() -> Result<()> {
        let salt1 = Csprng::generate_salt()?;
        let salt2 = Csprng::generate_salt()?;

        assert_ne!(salt1, salt2);
        Ok(())
    }
}