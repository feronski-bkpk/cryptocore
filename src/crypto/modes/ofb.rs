//! Output Feedback (OFB) mode implementation.
//!
//! OFB mode turns a block cipher into a synchronous stream cipher.
//! It generates a keystream independent of the plaintext/ciphertext.
//!
//! # Characteristics
//!
//! - Stream cipher mode (no padding required)
//! - Keystream generation is independent of data
//! - Errors propagate indefinitely (not self-synchronizing)
//! - Requires unique IV for each encryption with the same key
//!
//! # Security Note
//!
//! OFB provides confidentiality but **not authentication**.
//! The same keystream cannot be reused with different plaintexts.

use anyhow::{anyhow, Result};
use hex;
use openssl::symm::{Cipher, Crypter, Mode};

/// Block size in bytes for AES operations.
const BLOCK_SIZE: usize = 16;

/// Output Feedback (OFB) mode implementation.
#[derive(Debug, Clone)]
pub struct Ofb {
    /// AES-128 encryption key.
    key: [u8; BLOCK_SIZE],
}

impl Ofb {
    /// Creates a new OFB instance from a hexadecimal key string.
    ///
    /// # Arguments
    ///
    /// * `key_hex` - 32-character hexadecimal string (16 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Ofb)` - New OFB instance
    /// * `Err(anyhow::Error)` - If key format is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::crypto::modes::Ofb;
    ///
    /// let ofb = Ofb::new("00112233445566778899aabbccddeeff").unwrap();
    /// ```
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    /// Creates a new OFB instance from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    ///
    /// # Returns
    ///
    /// * `Ok(Ofb)` - New OFB instance
    /// * `Err(anyhow::Error)` - If key length is invalid
    #[allow(dead_code)]
    pub fn new_from_bytes(key: &[u8; BLOCK_SIZE]) -> Result<Self> {
        if key.len() != BLOCK_SIZE {
            return Err(anyhow!("Key must be {} bytes", BLOCK_SIZE));
        }

        let mut key_array = [0u8; BLOCK_SIZE];
        key_array.copy_from_slice(key);

        Ok(Self { key: key_array })
    }

    /// Creates a new OFB instance from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Byte slice containing the key
    ///
    /// # Returns
    ///
    /// * `Ok(Ofb)` - New OFB instance
    /// * `Err(anyhow::Error)` - If key length is invalid
    #[allow(dead_code)]
    pub fn new_from_key_bytes(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != BLOCK_SIZE {
            return Err(anyhow!("Key must be {} bytes", BLOCK_SIZE));
        }

        let mut key = [0u8; BLOCK_SIZE];
        key.copy_from_slice(key_bytes);

        Ok(Self { key })
    }

    /// Generates a keystream block by encrypting the feedback register.
    ///
    /// # Arguments
    ///
    /// * `input` - Current feedback register value
    ///
    /// # Returns
    ///
    /// Generated keystream block
    fn generate_keystream_block(&self, input: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(input, &mut output)?;
        output.truncate(count);
        Ok(output)
    }
}

impl super::BlockMode for Ofb {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut feedback = iv.to_vec();

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let keystream = self.generate_keystream_block(&feedback)?;

            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }

            // Update feedback with keystream (not ciphertext)
            feedback = keystream;
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        // OFB decryption is identical to encryption
        self.encrypt(ciphertext, iv)
    }
}

/// Parses a hexadecimal string into a fixed-size key array.
///
/// # Arguments
///
/// * `key_hex` - Hexadecimal string, optionally prefixed with '@'
///
/// # Returns
///
/// * `Ok([u8; BLOCK_SIZE])` - Parsed key
/// * `Err(anyhow::Error)` - If string has invalid length or format
fn parse_hex_key(key_hex: &str) -> Result<[u8; BLOCK_SIZE]> {
    let key_str = key_hex.trim_start_matches('@');
    if key_str.len() != BLOCK_SIZE * 2 {
        return Err(anyhow!("Key must be {} hex characters", BLOCK_SIZE * 2));
    }

    let key_bytes = hex::decode(key_str)?;
    let mut key = [0u8; BLOCK_SIZE];
    key.copy_from_slice(&key_bytes);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlockMode;

    /// Tests OFB encryption and decryption round trip.
    #[test]
    fn test_ofb_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x00; 16];
        let ofb = Ofb::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore OFB Mode!";

        let ciphertext = ofb.encrypt(plaintext, &iv).unwrap();
        let decrypted = ofb.decrypt(&ciphertext, &iv).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    /// Tests creating OFB from both bytes and hex produces same results.
    #[test]
    fn test_ofb_from_bytes() {
        let key_bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let iv = vec![0x00; 16];
        let plaintext = b"Test OFB from bytes";

        let ofb_from_bytes = Ofb::new_from_bytes(&key_bytes).unwrap();
        let ofb_from_hex = Ofb::new("00112233445566778899aabbccddeeff").unwrap();

        let ciphertext1 = ofb_from_bytes.encrypt(plaintext, &iv).unwrap();
        let ciphertext2 = ofb_from_hex.encrypt(plaintext, &iv).unwrap();

        assert_eq!(ciphertext1, ciphertext2);

        let decrypted1 = ofb_from_bytes.decrypt(&ciphertext1, &iv).unwrap();
        let decrypted2 = ofb_from_hex.decrypt(&ciphertext2, &iv).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    /// Tests OFB with various data sizes.
    #[test]
    fn test_ofb_different_sizes() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x01; 16];
        let ofb = Ofb::new(key).unwrap();

        let test_cases = [
            b"A".to_vec(),
            b"Short text".to_vec(),
            b"Medium length text here".to_vec(),
            b"This is a much longer test message to ensure OFB works with various sizes".to_vec(),
        ];

        for original in test_cases {
            let ciphertext = ofb.encrypt(&original, &iv).unwrap();
            let decrypted = ofb.decrypt(&ciphertext, &iv).unwrap();
            assert_eq!(original, decrypted);
        }
    }
}