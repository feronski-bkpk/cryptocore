use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const BLOCK_SIZE: usize = 16;

pub struct Cfb {
    key: [u8; BLOCK_SIZE],
}

impl Cfb {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    fn encrypt_keystream(&self, input: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(input, &mut output)?;
        output.truncate(count);
        Ok(output)
    }
}

impl super::BlockMode for Cfb {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut feedback = iv.to_vec();

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let keystream = self.encrypt_keystream(&feedback)?;
            
            let mut encrypted_chunk = Vec::with_capacity(chunk.len());
            for (i, &byte) in chunk.iter().enumerate() {
                encrypted_chunk.push(byte ^ keystream[i]);
            }
            ciphertext.extend_from_slice(&encrypted_chunk);
            
            if encrypted_chunk.len() == BLOCK_SIZE {
                feedback = encrypted_chunk;
            } else {
                feedback = keystream[..BLOCK_SIZE].to_vec();
                for (i, &byte) in encrypted_chunk.iter().enumerate() {
                    feedback[i] = byte;
                }
            }
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut feedback = iv.to_vec();

        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let keystream = self.encrypt_keystream(&feedback)?;
            
            let mut decrypted_chunk = Vec::with_capacity(chunk.len());
            for (i, &byte) in chunk.iter().enumerate() {
                decrypted_chunk.push(byte ^ keystream[i]);
            }
            plaintext.extend_from_slice(&decrypted_chunk);
            
            if chunk.len() == BLOCK_SIZE {
                feedback = chunk.to_vec();
            } else {
                // For partial final block
                feedback = keystream[..BLOCK_SIZE].to_vec();
                for (i, &byte) in chunk.iter().enumerate() {
                    feedback[i] = byte;
                }
            }
        }

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
    use crate::crypto::BlockMode;

    #[test]
    fn test_cfb_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x00; 16];
        let cfb = Cfb::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore CFB Mode!";

        let ciphertext = cfb.encrypt(plaintext, &iv).unwrap();
        let decrypted = cfb.decrypt(&ciphertext, &iv).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_cfb_different_sizes() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x01; 16];
        let cfb = Cfb::new(key).unwrap();

        let test_cases = [
            b"A".to_vec(),
            b"Short text".to_vec(),
            b"Medium length text here".to_vec(),
            b"This is a much longer test message to ensure CFB works with various sizes".to_vec(),
        ];

        for original in test_cases {
            let ciphertext = cfb.encrypt(&original, &iv).unwrap();
            let decrypted = cfb.decrypt(&ciphertext, &iv).unwrap();
            assert_eq!(original, decrypted);
        }
    }
}