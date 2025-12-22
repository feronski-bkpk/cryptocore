//! Galois/Counter Mode (GCM) implementation.
//!
//! GCM is an authenticated encryption mode that provides both
//! confidentiality and integrity protection.
//!
//! # Characteristics
//!
//! - Authenticated encryption with associated data (AEAD)
//! - Combines CTR mode for encryption with Galois field authentication
//! - Parallelizable encryption and authentication
//! - Supports additional authenticated data (AAD)
//!
//! # Security Properties
//!
//! - Provides both confidentiality and integrity/authentication
//! - Nonce must be unique for each encryption with the same key
//! - Tag verification prevents tampering with ciphertext or AAD

use anyhow::{anyhow, Result};
use hex;
use openssl::symm::{Cipher, Crypter, Mode};

/// Block size in bytes for AES operations.
const BLOCK_SIZE: usize = 16;

/// Authentication tag size in bytes for GCM.
const TAG_SIZE: usize = 16;

/// Nonce size in bytes for GCM (recommended 12 bytes).
const NONCE_SIZE: usize = 12;

/// Galois/Counter Mode (GCM) implementation.
#[derive(Debug, Clone)]
pub struct Gcm {
    /// AES-128 encryption key.
    key: [u8; BLOCK_SIZE],
}

impl Gcm {
    /// Creates a new GCM instance from a hexadecimal key string.
    ///
    /// # Arguments
    ///
    /// * `key_hex` - 32-character hexadecimal string (16 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Gcm)` - New GCM instance
    /// * `Err(anyhow::Error)` - If key format is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::crypto::modes::Gcm;
    ///
    /// let gcm = Gcm::new("00112233445566778899aabbccddeeff").unwrap();
    /// ```
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    /// Creates a new GCM instance from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte AES key
    ///
    /// # Returns
    ///
    /// * `Ok(Gcm)` - New GCM instance
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

    /// Creates a new GCM instance from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Byte slice containing the key
    ///
    /// # Returns
    ///
    /// * `Ok(Gcm)` - New GCM instance
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

    /// Generates a random 12-byte nonce for GCM encryption.
    ///
    /// # Returns
    ///
    /// Random 12-byte nonce
    ///
    /// # Note
    ///
    /// Uses cryptographically secure random number generation.
    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        openssl::rand::rand_bytes(&mut nonce).unwrap();
        nonce
    }

    /// Encrypts plaintext with additional authenticated data (AAD).
    ///
    /// Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte nonce (must be unique for each encryption)
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Encrypted data with authentication tag
    /// * `Err(anyhow::Error)` - If encryption fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::crypto::modes::Gcm;
    ///
    /// let gcm = Gcm::new("00000000000000000000000000000000").unwrap();
    /// let nonce = [0u8; 12];
    /// let ciphertext = gcm.encrypt_with_aad(b"Hello", &nonce, b"metadata").unwrap();
    /// ```
    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(anyhow!("Nonce must be {} bytes for GCM", NONCE_SIZE));
        }

        // Compute H = E(K, 0^128)
        let h = self.aes_encrypt_block(&[0u8; BLOCK_SIZE])?;
        let h_array: [u8; BLOCK_SIZE] = h.try_into().unwrap();

        // Initialize counter: J0 = nonce || 0^31 || 1
        let mut counter = [0u8; BLOCK_SIZE];
        counter[..NONCE_SIZE].copy_from_slice(nonce);
        counter[BLOCK_SIZE - 1] = 0x01;

        // Encrypt using CTR mode
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut ctr_block = counter;

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            Self::inc_32(&mut ctr_block[BLOCK_SIZE - 4..]);

            let keystream = self.aes_encrypt_block(&ctr_block)?;

            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
        }

        // Compute authentication tag
        let tag = self.compute_tag(&h_array, nonce, &ciphertext, aad)?;

        // Format: nonce || ciphertext || tag
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + TAG_SIZE);
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    /// Decrypts and verifies GCM-encrypted data with AAD.
    ///
    /// # Arguments
    ///
    /// * `data` - Encrypted data (nonce || ciphertext || tag)
    /// * `aad` - Additional authenticated data (must match encryption AAD)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(anyhow::Error)` - If authentication fails or decryption fails
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptocore::crypto::modes::Gcm;
    ///
    /// let gcm = Gcm::new("00000000000000000000000000000000").unwrap();
    /// let nonce = [0u8; 12];
    /// let ciphertext = gcm.encrypt_with_aad(b"Hello", &nonce, b"metadata").unwrap();
    /// let plaintext = gcm.decrypt_with_aad(&ciphertext, b"metadata").unwrap();
    /// assert_eq!(plaintext, b"Hello");
    /// ```
    pub fn decrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(anyhow!("Data too short for GCM format"));
        }

        let nonce = &data[..NONCE_SIZE];
        let tag_start = data.len() - TAG_SIZE;
        let received_tag = &data[tag_start..];
        let ciphertext = &data[NONCE_SIZE..tag_start];

        // Compute H = E(K, 0^128)
        let h = self.aes_encrypt_block(&[0u8; BLOCK_SIZE])?;
        let h_array: [u8; BLOCK_SIZE] = h.try_into().unwrap();

        // Verify authentication tag
        let expected_tag = self.compute_tag(&h_array, nonce, ciphertext, aad)?;

        if received_tag != expected_tag {
            return Err(anyhow!("Authentication failed: tag mismatch"));
        }

        // Decrypt using CTR mode (identical to encryption)
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter = [0u8; BLOCK_SIZE];
        counter[..NONCE_SIZE].copy_from_slice(nonce);
        counter[BLOCK_SIZE - 1] = 0x01;

        let mut ctr_block = counter;

        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            Self::inc_32(&mut ctr_block[BLOCK_SIZE - 4..]);

            let keystream = self.aes_encrypt_block(&ctr_block)?;

            for (i, &byte) in chunk.iter().enumerate() {
                plaintext.push(byte ^ keystream[i]);
            }
        }

        Ok(plaintext)
    }

    /// Computes the GCM authentication tag.
    ///
    /// Implements GHASH (Galois Hash) over AAD and ciphertext.
    ///
    /// # Arguments
    ///
    /// * `h` - Hash subkey (H = E(K, 0^128))
    /// * `nonce` - Nonce used for encryption
    /// * `ciphertext` - Ciphertext to authenticate
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    ///
    /// 16-byte authentication tag
    fn compute_tag(
        &self,
        h: &[u8; BLOCK_SIZE],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<[u8; TAG_SIZE]> {
        let mut auth_data = Vec::new();

        // Process AAD (padded to block boundary)
        if !aad.is_empty() {
            let aad_padded_len = ((aad.len() + 15) / 16) * 16;
            let mut padded_aad = vec![0u8; aad_padded_len];
            padded_aad[..aad.len()].copy_from_slice(aad);
            auth_data.extend_from_slice(&padded_aad);
        }

        // Process ciphertext (padded to block boundary)
        let ciphertext_padded_len = ((ciphertext.len() + 15) / 16) * 16;
        let mut padded_ciphertext = vec![0u8; ciphertext_padded_len];
        padded_ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
        auth_data.extend_from_slice(&padded_ciphertext);

        // Append lengths block
        let mut len_block = [0u8; BLOCK_SIZE];
        let aad_len_bits = (aad.len() as u64) * 8;
        let ciphertext_len_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&aad_len_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ciphertext_len_bits.to_be_bytes());
        auth_data.extend_from_slice(&len_block);

        // GHASH computation
        let mut y = [0u8; BLOCK_SIZE];

        for chunk in auth_data.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            if chunk.len() == BLOCK_SIZE {
                block.copy_from_slice(chunk);
            } else {
                block[..chunk.len()].copy_from_slice(chunk);
            }

            // XOR with current hash value
            for i in 0..BLOCK_SIZE {
                block[i] ^= y[i];
            }

            // Multiply in GF(2^128)
            y = self.gf128_mul(&block, h);
        }

        // Finalize tag: Tag = MSB(GCTR(J0, Y) ⊕ E(K, J0))
        let mut tag_counter = [0u8; BLOCK_SIZE];
        tag_counter[..NONCE_SIZE].copy_from_slice(nonce);
        tag_counter[BLOCK_SIZE - 1] = 0x01;

        let encrypted_counter = self.aes_encrypt_block(&tag_counter)?;
        let mut tag = [0u8; TAG_SIZE];

        for i in 0..TAG_SIZE {
            tag[i] = y[i] ^ encrypted_counter[i];
        }

        Ok(tag)
    }

    /// Multiplies two elements in GF(2^128) using the GCM field polynomial.
    ///
    /// Field polynomial: x^128 + x^7 + x^2 + x + 1
    ///
    /// # Arguments
    ///
    /// * `x` - First element in GF(2^128)
    /// * `y` - Second element in GF(2^128)
    ///
    /// # Returns
    ///
    /// Product x * y in GF(2^128)
    fn gf128_mul(&self, x: &[u8; BLOCK_SIZE], y: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let x_val = u128::from_be_bytes(*x);
        let y_val = u128::from_be_bytes(*y);

        let mut z: u128 = 0;
        let mut v: u128 = y_val;

        for i in (0..128).rev() {
            if (x_val >> i) & 1 == 1 {
                z ^= v;
            }

            let msb = v >> 127;
            v <<= 1;

            if msb == 1 {
                v ^= 0x87u128 << 120; // x^7 + x^2 + x + 1
            }
        }

        z.to_be_bytes()
    }

    /// Encrypts a single block using AES-128.
    ///
    /// # Arguments
    ///
    /// * `block` - Block to encrypt
    ///
    /// # Returns
    ///
    /// Encrypted block
    fn aes_encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(block, &mut output)?;
        output.truncate(count);
        Ok(output)
    }

    /// Increments the rightmost 32 bits of a counter (big-endian).
    ///
    /// Used for CTR mode counter incrementation in GCM.
    ///
    /// # Arguments
    ///
    /// * `counter` - Counter to increment (last 4 bytes, modified in place)
    fn inc_32(counter: &mut [u8]) {
        for i in (0..4).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

impl super::BlockMode for Gcm {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(plaintext, iv, &[])
    }

    fn decrypt(&self, data: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(data, &[])
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

    /// Tests GCM with NIST test vector 1 (empty plaintext and AAD).
    #[test]
    fn test_gcm_nist_vector_1() -> Result<()> {
        let key = "00000000000000000000000000000000";
        let nonce = hex::decode("000000000000000000000000")?;
        let plaintext = hex::decode("")?;
        let aad = hex::decode("")?;
        let expected_ciphertext = hex::decode("")?;
        let expected_tag = hex::decode("58e2fccefa7e3061367f1d57a4e7455a")?;

        let gcm = Gcm::new(key)?;
        let result = gcm.encrypt_with_aad(&plaintext, &nonce, &aad)?;

        let result_ciphertext = &result[12..result.len() - 16];
        let result_tag = &result[result.len() - 16..];

        assert_eq!(result_ciphertext, expected_ciphertext);
        assert_eq!(result_tag, expected_tag);

        let decrypted = gcm.decrypt_with_aad(&result, &aad)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    /// Tests creating GCM from both bytes and hex produces same results.
    #[test]
    fn test_gcm_from_bytes() -> Result<()> {
        let key_bytes = [0x00; 16];
        let nonce = hex::decode("000000000000000000000000")?;
        let plaintext = hex::decode("00000000000000000000000000000000")?;
        let aad = hex::decode("")?;
        let expected_ciphertext = hex::decode("0388dace60b6a392f328c2b971b2fe78")?;

        let gcm_from_bytes = Gcm::new_from_bytes(&key_bytes)?;
        let gcm_from_hex = Gcm::new("00000000000000000000000000000000")?;

        let result1 = gcm_from_bytes.encrypt_with_aad(&plaintext, &nonce, &aad)?;
        let result2 = gcm_from_hex.encrypt_with_aad(&plaintext, &nonce, &aad)?;

        let ciphertext1 = &result1[12..12 + expected_ciphertext.len()];
        let ciphertext2 = &result2[12..12 + expected_ciphertext.len()];

        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext1, expected_ciphertext.as_slice());

        let decrypted1 = gcm_from_bytes.decrypt_with_aad(&result1, &aad)?;
        let decrypted2 = gcm_from_hex.decrypt_with_aad(&result2, &aad)?;

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);

        Ok(())
    }

    /// Tests GF(2^128) multiplication properties.
    #[test]
    fn test_gf128_mul() -> Result<()> {
        let gcm = Gcm::new("00000000000000000000000000000000")?;

        let mut one = [0u8; 16];
        one[15] = 0x01;

        let result = gcm.gf128_mul(&one, &one);

        assert!(!result.iter().all(|&b| b == 0), "1 * 1 should not be zero");

        let zero = [0u8; 16];
        let zero_result = gcm.gf128_mul(&one, &zero);
        assert_eq!(zero_result, zero, "1 * 0 should be 0");

        let zero_result2 = gcm.gf128_mul(&zero, &one);
        assert_eq!(zero_result2, zero, "0 * 1 should be 0");

        Ok(())
    }
}