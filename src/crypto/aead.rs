use anyhow::{Result, anyhow};
use crate::crypto::modes::BlockMode;
use crate::mac::hmac::HMAC;
use crate::hash::HashType;
use hex;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;

pub struct EncryptThenMac {
    #[allow(dead_code)]
    encryption_key: [u8; BLOCK_SIZE],
    mac_key: [u8; BLOCK_SIZE],
}

impl EncryptThenMac {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;

        let mut encryption_key = [0u8; BLOCK_SIZE];
        let mut mac_key = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            encryption_key[i] = key[i] ^ 0x36;
            mac_key[i] = key[i] ^ 0x5C;
        }

        Ok(Self {
            encryption_key,
            mac_key,
        })
    }

    pub fn encrypt<M: BlockMode + ?Sized>(&self, mode: &M, plaintext: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
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

    pub fn decrypt<M: BlockMode + ?Sized>(&self, mode: &M, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::modes::Cbc;

    #[test]
    fn test_encrypt_then_mac_basic() -> Result<()> {
        let key = "00112233445566778899aabbccddeeff";
        let aead = EncryptThenMac::new(key)?;

        let cbc = Cbc::new(key)?;

        let iv = [0x00; 16];
        let plaintext = b"Test message for Encrypt-then-MAC";
        let aad = b"Associated data";

        let encrypted = aead.encrypt(&cbc, plaintext, &iv, aad)?;
        let decrypted = aead.decrypt(&cbc, &encrypted, aad)?;

        assert_eq!(plaintext, &decrypted[..]);
        Ok(())
    }
}