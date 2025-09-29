use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const BLOCK_SIZE: usize = 16;

pub struct Ctr {
    key: [u8; BLOCK_SIZE],
}

impl Ctr {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    fn encrypt_counter(&self, counter: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(counter, &mut output)?;
        output.truncate(count);
        Ok(output)
    }

    fn increment_counter(counter: &mut [u8]) {
        for byte in counter.iter_mut().rev() {
            if *byte == 0xff {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
    }
}

impl super::BlockMode for Ctr {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = iv.to_vec();

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let keystream = self.encrypt_counter(&counter)?;
            
            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
            
            Self::increment_counter(&mut counter);
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
    use crate::crypto::BlockMode;
    use super::*;

    #[test]
    fn test_ctr_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x00; 16];
        let ctr = Ctr::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore CTR Mode!";

        let ciphertext = ctr.encrypt(plaintext, &iv).unwrap();
        let decrypted = ctr.decrypt(&ciphertext, &iv).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_counter_increment() {
        let mut counter = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        Ctr::increment_counter(&mut counter);
        assert_eq!(counter[15], 0x01);

        counter[15] = 0xff;
        Ctr::increment_counter(&mut counter);
        assert_eq!(counter[14], 0x01);
        assert_eq!(counter[15], 0x00);
    }

    #[test]
    fn test_ctr_partial_blocks() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x01; 16];
        let ctr = Ctr::new(key).unwrap();
        
        let test_data = [
            vec![0x41; 15],  
            vec![0x42; 17], 
            vec![0x43; 31], 
        ];

        for data in test_data {
            let ciphertext = ctr.encrypt(&data, &iv).unwrap();
            let decrypted = ctr.decrypt(&ciphertext, &iv).unwrap();
            assert_eq!(data, decrypted);
        }
    }
}