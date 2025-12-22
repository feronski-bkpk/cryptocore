//! Cryptocore Library
//!
//! This library provides a comprehensive set of cryptographic primitives
//! including symmetric encryption, hashing, message authentication codes (MAC),
//! and key derivation functions (KDF). It's designed for both educational
//! purposes and practical cryptographic operations.
//!
//! # Modules
//!
//! - [`cli`] - Command-line interface types and argument parsing
//! - [`crypto`] - Core cryptographic operations and modes
//! - [`csprng`] - Cryptographically secure pseudo-random number generation
//! - [`file`] - File I/O operations for cryptographic data
//! - [`hash`] - Hash function implementations (SHA-256, SHA3-256)
//! - [`mac`] - Message authentication code implementations (HMAC)
//! - [`kdf`] - Key derivation functions (PBKDF2, HKDF)
//!
//! # Constants
//!
//! The library uses AES-128 as its primary cipher with the following constants:
//! - [`BLOCK_SIZE`]: 16 bytes (128 bits)
//! - [`IV_SIZE`]: 16 bytes for initialization vectors
//! - [`KEY_SIZE`]: 16 bytes (128 bits) for AES keys
//!
//! # Examples
//!
//! Computing a hash:
//! ```
//! use cryptocore::hash::{HashAlgorithm, sha256::Sha256};
//!
//! let hasher = Sha256::new();
//! let hash = hasher.hash_data(b"Hello, world!").unwrap();
//! ```

pub mod cli;
pub mod crypto;
pub mod file;
pub mod csprng;
pub mod hash;
pub mod mac;
pub mod kdf;

pub use cli::{Algorithm, Cli, Mode, Operation};
pub use crypto::aead::EncryptThenMac;
pub use crypto::modes::{BlockMode, Cbc, Cfb, Ctr, Ecb, FromKeyBytes, Gcm, Ofb};
pub use csprng::Csprng;
pub use kdf::{derive_key, pbkdf2_hmac_sha256};
pub use mac::hmac;

/// Block size in bytes for AES operations (16 bytes = 128 bits)
pub const BLOCK_SIZE: usize = 16;

/// Initialization Vector size in bytes (16 bytes = 128 bits)
pub const IV_SIZE: usize = 16;

/// Key size in bytes for AES-128 (16 bytes = 128 bits)
pub const KEY_SIZE: usize = 16;

/// Converts a hexadecimal string to a fixed-size key array.
///
/// The input string can optionally be prefixed with '@' (as used in CLI).
/// The hex string must contain exactly 32 characters (16 bytes when decoded).
///
/// # Arguments
///
/// * `hex_str` - Hexadecimal string representation of the key, optionally prefixed with '@'
///
/// # Returns
///
/// * `Ok([u8; KEY_SIZE])` - The decoded key as a byte array
/// * `Err(anyhow::Error)` - If the string has invalid length or contains non-hex characters
///
/// # Examples
///
/// ```
/// use cryptocore::hex_to_key;
///
/// let key = hex_to_key("00112233445566778899aabbccddeeff").unwrap();
/// assert_eq!(key.len(), 16);
///
/// // Also works with '@' prefix
/// let key2 = hex_to_key("@00112233445566778899aabbccddeeff").unwrap();
/// assert_eq!(key, key2);
/// ```
pub fn hex_to_key(hex_str: &str) -> Result<[u8; KEY_SIZE], anyhow::Error> {
    use hex;
    let key_str = hex_str.trim_start_matches('@');
    if key_str.len() != KEY_SIZE * 2 {
        return Err(anyhow::anyhow!("Key must be {} hex characters", KEY_SIZE * 2));
    }

    let key_bytes = hex::decode(key_str)?;
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);

    Ok(key)
}

/// Converts a key byte array to a hexadecimal string.
///
/// # Arguments
///
/// * `key` - A byte array of size [`KEY_SIZE`]
///
/// # Returns
///
/// A hexadecimal string representation of the key (32 characters).
///
/// # Examples
///
/// ```
/// use cryptocore::{key_to_hex, hex_to_key};
///
/// let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// let hex = key_to_hex(&key);
/// assert_eq!(hex, "00112233445566778899aabbccddeeff");
///
/// // Round-trip conversion
/// let key2 = hex_to_key(&hex).unwrap();
/// assert_eq!(key, key2);
/// ```
pub fn key_to_hex(key: &[u8; KEY_SIZE]) -> String {
    use hex;
    hex::encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecb_creation() {
        let result = Ecb::new("00112233445566778899aabbccddeeff");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_key() {
        let result = Ecb::new("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_enum_values() {
        let _mode = Mode::Ecb;
        let _mode = Mode::Cbc;
        let _op = Operation::Encrypt;
        let _op = Operation::Decrypt;
    }

    #[test]
    fn test_hex_key_conversion() {
        let hex_key = "00112233445566778899aabbccddeeff";
        let key_bytes = hex_to_key(hex_key).unwrap();
        let hex_again = key_to_hex(&key_bytes);

        assert_eq!(hex_key, hex_again);
    }

    #[test]
    fn test_hex_key_with_prefix() {
        let hex_key = "@00112233445566778899aabbccddeeff";
        let key_bytes = hex_to_key(hex_key).unwrap();
        let hex_again = key_to_hex(&key_bytes);

        assert_eq!("00112233445566778899aabbccddeeff", hex_again);
    }
}