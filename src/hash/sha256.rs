//! SHA-256 hash function implementation (from scratch).
//!
//! This module provides a pure Rust implementation of the SHA-256
//! cryptographic hash function as specified in FIPS 180-4.
//!
//! # Algorithm Details
//!
//! - Block size: 512 bits (64 bytes)
//! - Word size: 32 bits
//! - Digest size: 256 bits (32 bytes)
//! - Security: 128-bit collision resistance
//!
//! # Implementation Notes
//!
//! This is an educational implementation that demonstrates the
//! internal workings of SHA-256. For production use, consider
//! using optimized library implementations.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::Result;

use crate::hash::HashAlgorithm;

/// SHA-256 hasher implementation.
#[derive(Debug, Clone)]
pub struct Sha256;

impl Sha256 {
    /// Creates a new SHA-256 hasher.
    ///
    /// # Returns
    ///
    /// New SHA-256 hasher instance
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::hash::sha256::Sha256;
    ///
    /// let sha256 = Sha256::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
}

impl HashAlgorithm for Sha256 {
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
        let mut hasher = Sha256Hasher::new();

        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }

    fn hash_data(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(data);
        Ok(hasher.finalize())
    }
}

/// Internal SHA-256 hasher state.
///
/// Implements the SHA-256 compression function and message scheduling.
pub struct Sha256Hasher {
    /// Hash state (8 32-bit words)
    h: [u32; 8],
    /// Total message length in bytes
    message_len: u64,
    /// Buffer for incomplete blocks
    buffer: Vec<u8>,
}

impl Sha256Hasher {
    /// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// Creates a new SHA-256 hasher with initial state.
    ///
    /// Initial hash values are the first 32 bits of fractional parts
    /// of square roots of first 8 primes.
    ///
    /// # Returns
    ///
    /// New SHA-256 hasher with initial state
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667, // sqrt(2)
                0xbb67ae85, // sqrt(3)
                0x3c6ef372, // sqrt(5)
                0xa54ff53a, // sqrt(7)
                0x510e527f, // sqrt(11)
                0x9b05688c, // sqrt(13)
                0x1f83d9ab, // sqrt(17)
                0x5be0cd19, // sqrt(19)
            ],
            message_len: 0,
            buffer: Vec::new(),
        }
    }

    /// Updates the hash state with new data.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to hash
    pub fn update(&mut self, data: &[u8]) {
        self.message_len += data.len() as u64;
        self.buffer.extend_from_slice(data);

        // Process complete 64-byte blocks
        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer[0..64].to_vec();
            self.process_block(&block);
            self.buffer.drain(0..64);
        }
    }

    /// Finalizes the hash and returns the digest as hexadecimal string.
    ///
    /// # Returns
    ///
    /// SHA-256 digest as 64-character hexadecimal string
    pub fn finalize(mut self) -> String {
        let mut message = std::mem::take(&mut self.buffer);

        // Append padding: 1 bit followed by zeros
        message.push(0x80); // 1 bit (MSB) followed by 7 zeros

        // Pad with zeros until length % 64 == 56
        while (message.len() % 64) != 56 {
            message.push(0x00);
        }

        // Append original message length in bits (big-endian, 64 bits)
        let bit_len = self.message_len * 8;
        message.extend_from_slice(&bit_len.to_be_bytes());

        // Process final blocks
        for chunk in message.chunks(64) {
            self.process_block(chunk);
        }

        // Convert hash state to hexadecimal string
        self.h
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Processes a 64-byte block through the SHA-256 compression function.
    ///
    /// # Arguments
    ///
    /// * `block` - 64-byte block to process
    fn process_block(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];

        // Prepare message schedule (first 16 words from block)
        for (i, chunk) in block.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        // Extend message schedule
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // Compression function main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Update hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests SHA-256 with empty input (known test vector).
    #[test]
    fn test_sha256_empty() {
        let sha256 = Sha256::new();
        let hash = sha256.hash_data(b"").unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Tests SHA-256 with "abc" input (known test vector).
    #[test]
    fn test_sha256_abc() {
        let sha256 = Sha256::new();
        let hash = sha256.hash_data(b"abc").unwrap();
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Tests SHA-256 with longer input (known test vector).
    #[test]
    fn test_sha256_long_text() {
        let sha256 = Sha256::new();
        let hash = sha256
            .hash_data(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            .unwrap();
        assert_eq!(
            hash,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}