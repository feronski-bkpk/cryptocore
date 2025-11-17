use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const BLOCK_SIZE: usize = 16;

pub struct Ofb {
    key: [u8; BLOCK_SIZE],
}

impl Ofb {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

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
            
            feedback = keystream;
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(ciphertext, iv)
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
    use crate::crypto::BlockMode;

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