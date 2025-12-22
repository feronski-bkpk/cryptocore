//! HMAC-based Key Derivation Function (HKDF) implementation.
//!
//! HKDF is a simple key derivation function that can be used to derive
//! multiple keys from a single master key or from a password-derived key.
//!
//! # Algorithm
//!
//! HKDF consists of two stages:
//! 1. **Extract**: HKDF-Extract(salt, IKM) -> PRK
//!    - `salt` optional salt value (can be empty)
//!    - `IKM` Input Keying Material
//!    - `PRK` Pseudorandom Key
//!
//! 2. **Expand**: HKDF-Expand(PRK, info, L) -> OKM
//!    - `PRK` Pseudorandom Key from extract stage
//!    - `info` context-specific information
//!    - `L` length of output keying material in bytes
//!    - `OKM` Output Keying Material
//!
//! # Security Properties
//!
//! - Provides cryptographic separation between derived keys
//! - Context string ("info") ensures different keys for different purposes
//! - Should be used with cryptographically strong input key material
//!
//! # Warning
//!
//! HKDF is **not** suitable for password-based key derivation.
//! Use PBKDF2 for passwords, then HKDF for further key derivation.
//!
//! # References
//!
//! - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

use anyhow::Result;
use hex;

use crate::hash::HashType;
use crate::mac::hmac::HMAC;

/// Derives one or more cryptographic keys from a master key using HKDF.
///
/// This is a simplified HKDF implementation that combines extract and expand
/// stages into a single function.
///
/// # Arguments
///
/// * `master_key` - Input keying material (should be cryptographically strong)
/// * `context` - Context/application-specific information string
/// * `length` - Desired length of derived key in bytes
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Derived key of specified length
/// * `Err(anyhow::Error)` - If derivation fails
///
/// # Examples
///
/// ```
/// use cryptocore::kdf::derive_key;
///
/// let master_key = b"cryptographically_strong_master_key";
/// let encryption_key = derive_key(master_key, "encryption", 32).unwrap();
/// let mac_key = derive_key(master_key, "authentication", 32).unwrap();
///
/// assert_eq!(encryption_key.len(), 32);
/// assert_eq!(mac_key.len(), 32);
/// assert_ne!(encryption_key, mac_key); // Different contexts produce different keys
/// ```
#[allow(dead_code)]
pub fn derive_key(master_key: &[u8], context: &str, length: usize) -> Result<Vec<u8>> {
    // Extract stage: PRK = HMAC-Hash(salt, IKM)
    // Using empty salt as per simplified implementation
    let salt = &[];
    let hmac_extract = HMAC::new(salt, HashType::Sha256);
    let prk_hex = hmac_extract.compute(master_key)?;
    let prk = hex::decode(&prk_hex)?;

    // Expand stage: OKM = HKDF-Expand(PRK, info, L)
    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new(); // T(0) is empty
    let mut counter: u8 = 1;

    // Generate enough output material
    while okm.len() < length {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        let mut input = t.clone();
        input.extend_from_slice(context.as_bytes());
        input.push(counter);

        let hmac_expand = HMAC::new(&prk, HashType::Sha256);
        t = hex::decode(hmac_expand.compute(&input)?)?;

        okm.extend_from_slice(&t);
        counter += 1;
    }

    // Truncate to requested length
    Ok(okm[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests basic HKDF properties (determinism, output length).
    #[test]
    fn test_derive_key_basic() -> Result<()> {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let context = "encryption";
        let length = 32;

        let key1 = derive_key(master_key, context, length)?;
        let key2 = derive_key(master_key, context, length)?;

        assert_eq!(key1.len(), length);
        assert_eq!(key2.len(), length);
        assert_eq!(key1, key2); // Deterministic

        Ok(())
    }

    /// Tests that different contexts produce different keys.
    #[test]
    fn test_context_separation() -> Result<()> {
        let master_key = b"0123456789abcdef0123456789abcdef";

        let key1 = derive_key(master_key, "encryption", 32)?;
        let key2 = derive_key(master_key, "authentication", 32)?;

        // Different contexts should produce different keys
        assert_ne!(key1, key2);

        Ok(())
    }

    /// Tests HKDF with various output lengths.
    #[test]
    fn test_various_lengths() -> Result<()> {
        let master_key = b"masterkey";

        for length in [1, 16, 32, 48, 64, 100] {
            let key = derive_key(master_key, "test", length)?;
            assert_eq!(key.len(), length);
        }

        Ok(())
    }

    /// Tests that different master keys produce different derived keys.
    #[test]
    fn test_different_master_keys() -> Result<()> {
        let context = "encryption";
        let length = 32;

        let key1 = derive_key(b"key1", context, length)?;
        let key2 = derive_key(b"key2", context, length)?;

        // Different master keys should produce different derived keys
        assert_ne!(key1, key2);

        Ok(())
    }
}