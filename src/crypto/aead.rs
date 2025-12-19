use anyhow::{Result, anyhow};
use crate::crypto::modes::{BlockMode, FromKeyBytes};
use crate::mac::hmac::HMAC;
use crate::hash::HashType;
use hex;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;

pub struct EncryptThenMac {
    encryption_key: [u8; BLOCK_SIZE],
    mac_key: [u8; BLOCK_SIZE],
}

impl EncryptThenMac {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;

        let (encryption_key, mac_key) = Self::derive_keys(&key)?;

        Ok(Self {
            encryption_key,
            mac_key,
        })
    }

    fn derive_keys(master_key: &[u8; BLOCK_SIZE]) -> Result<([u8; BLOCK_SIZE], [u8; BLOCK_SIZE])> {
        let mut encryption_key = [0u8; BLOCK_SIZE];
        let mut mac_key = [0u8; BLOCK_SIZE];

        let mut encryption_input = b"encryption".to_vec();
        encryption_input.push(0x01);

        let hmac_enc = HMAC::new(master_key, HashType::Sha256);
        let enc_hex = hmac_enc.compute(&encryption_input)?;
        let enc_bytes = hex::decode(&enc_hex)?;

        if enc_bytes.len() >= BLOCK_SIZE {
            encryption_key.copy_from_slice(&enc_bytes[..BLOCK_SIZE]);
        } else {
            let mut padded = enc_bytes.clone();
            padded.resize(BLOCK_SIZE, 0);
            encryption_key.copy_from_slice(&padded[..BLOCK_SIZE]);
        }

        let mut mac_input = b"authentication".to_vec();
        mac_input.push(0x01);

        let hmac_mac = HMAC::new(master_key, HashType::Sha256);
        let mac_hex = hmac_mac.compute(&mac_input)?;
        let mac_bytes = hex::decode(&mac_hex)?;

        if mac_bytes.len() >= BLOCK_SIZE {
            mac_key.copy_from_slice(&mac_bytes[..BLOCK_SIZE]);
        } else {
            let mut padded = mac_bytes.clone();
            padded.resize(BLOCK_SIZE, 0);
            mac_key.copy_from_slice(&padded[..BLOCK_SIZE]);
        }

        Ok((encryption_key, mac_key))
    }

    pub fn get_encryption_key(&self) -> &[u8; BLOCK_SIZE] {
        &self.encryption_key
    }


    pub fn get_mac_key(&self) -> &[u8; BLOCK_SIZE] {
        &self.mac_key
    }

    pub fn encrypt<M: BlockMode + FromKeyBytes>(
        &self,
        plaintext: &[u8],
        iv: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>> {
        self.encrypt_with_mode::<M>(plaintext, iv, aad)
    }

    pub fn decrypt<M: BlockMode + FromKeyBytes>(
        &self,
        data: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>> {
        self.decrypt_with_mode::<M>(data, aad)
    }

    fn encrypt_with_mode<M: BlockMode + FromKeyBytes>(
        &self,
        plaintext: &[u8],
        iv: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>> {
        let mode = M::from_key_bytes(&self.encryption_key)?;
        let ciphertext = mode.encrypt(plaintext, iv)?;

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&ciphertext);
        mac_input.extend_from_slice(aad);

        let hmac = HMAC::new(&self.mac_key, HashType::Sha256);
        let tag_hex = hmac.compute(&mac_input)?;
        let tag = hex::decode(&tag_hex)?;

        let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + TAG_SIZE);
        result.extend_from_slice(iv);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    fn decrypt_with_mode<M: BlockMode + FromKeyBytes>(
        &self,
        data: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>> {
        if data.len() < BLOCK_SIZE + TAG_SIZE {
            return Err(anyhow!("Data too short for Encrypt-then-MAC format"));
        }

        let iv = &data[..BLOCK_SIZE];
        let tag_start = data.len() - TAG_SIZE;
        let tag_hex_bytes = &data[tag_start..];
        let ciphertext = &data[BLOCK_SIZE..tag_start];

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(ciphertext);
        mac_input.extend_from_slice(aad);

        let hmac = HMAC::new(&self.mac_key, HashType::Sha256);
        let computed_tag_hex = hmac.compute(&mac_input)?;
        let computed_tag = hex::decode(&computed_tag_hex)?;

        if tag_hex_bytes != computed_tag {
            return Err(anyhow!("Authentication failed: MAC mismatch"));
        }

        let mode = M::from_key_bytes(&self.encryption_key)?;
        let plaintext = mode.decrypt(ciphertext, iv)?;

        Ok(plaintext)
    }
}

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

mod tests {
    use super::*;
    use crate::crypto::modes::Cbc;

    #[test]
    fn test_encrypt_then_mac_basic() -> Result<()> {
        let key = "00112233445566778899aabbccddeeff";
        let aead = EncryptThenMac::new(key)?;

        let iv = [0x00; 16];
        let plaintext = b"Test message for Encrypt-then-MAC";
        let aad = b"Associated data";

        let encrypted = aead.encrypt::<Cbc>(plaintext, &iv, aad)?;
        let decrypted = aead.decrypt::<Cbc>(&encrypted, aad)?;

        assert_eq!(plaintext, &decrypted[..]);
        Ok(())
    }

    #[test]
    fn test_key_separation() -> Result<()> {
        let key = "00112233445566778899aabbccddeeff";
        let aead = EncryptThenMac::new(key)?;

        assert_ne!(aead.get_encryption_key(), aead.get_mac_key());

        let original_key = parse_hex_key(key)?;
        assert_ne!(aead.get_encryption_key(), &original_key);
        assert_ne!(aead.get_mac_key(), &original_key);

        Ok(())
    }

    #[test]
    fn test_deterministic_key_derivation() -> Result<()> {
        let key = "0123456789abcdef0123456789abcdef";

        let aead1 = EncryptThenMac::new(key)?;
        let aead2 = EncryptThenMac::new(key)?;

        assert_eq!(aead1.get_encryption_key(), aead2.get_encryption_key());
        assert_eq!(aead1.get_mac_key(), aead2.get_mac_key());

        Ok(())
    }

    #[test]
    fn test_invalid_key_length() -> Result<()> {
        let short_key = "00112233445566778899aabbccddee";
        let result = EncryptThenMac::new(short_key);
        assert!(result.is_err());

        let long_key = "00112233445566778899aabbccddeeff00";
        let result = EncryptThenMac::new(long_key);
        assert!(result.is_err());

        Ok(())
    }
}