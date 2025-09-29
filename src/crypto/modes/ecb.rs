use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const BLOCK_SIZE: usize = 16;

pub struct Ecb {
    key: [u8; BLOCK_SIZE],
}

impl Ecb {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    fn pkcs7_pad(&self, data: &[u8]) -> Vec<u8> {
        let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let padding_byte = padding_len as u8;

        let mut padded = data.to_vec();
        padded.resize(data.len() + padding_len, padding_byte);
        padded
    }

    fn pkcs7_unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(data.to_vec());
        }

        let padding_byte = data[data.len() - 1];
        let padding_len = padding_byte as usize;

        if padding_len == 0 || padding_len > BLOCK_SIZE {
            return Err(anyhow!("Invalid padding"));
        }
        
        for i in (data.len() - padding_len)..data.len() {
            if data[i] != padding_byte {
                return Err(anyhow!("Invalid padding"));
            }
        }

        Ok(data[..data.len() - padding_len].to_vec())
    }
}

impl super::BlockMode for Ecb {
    fn encrypt(&self, plaintext: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let padded = self.pkcs7_pad(plaintext);
        let mut output = vec![0; padded.len() + BLOCK_SIZE];
        let mut count = crypter.update(&padded, &mut output)?;
        count += crypter.finalize(&mut output[count..])?;
        output.truncate(count);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(anyhow!("Ciphertext length must be multiple of block size"));
        }

        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; ciphertext.len() + BLOCK_SIZE];
        let mut count = crypter.update(ciphertext, &mut output)?;
        count += crypter.finalize(&mut output[count..])?;
        output.truncate(count);

        let unpadded = self.pkcs7_unpad(&output)?;
        Ok(unpadded)
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
    fn test_ecb_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let ecb = Ecb::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore ECB Mode!";

        let ciphertext = ecb.encrypt(plaintext, &[]).unwrap();
        let decrypted = ecb.decrypt(&ciphertext, &[]).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ecb_padding() {
        let key = "00112233445566778899aabbccddeeff";
        let ecb = Ecb::new(key).unwrap();
        
        let test_cases = [
            b"".to_vec(),
            b"A".to_vec(),
            b"AB".to_vec(),
            b"ABC".to_vec(),
            b"ABCDEFGHIJKLMNOP".to_vec(),  
            b"ABCDEFGHIJKLMNOPQ".to_vec(), 
        ];

        for original in test_cases {
            let ciphertext = ecb.encrypt(&original, &[]).unwrap();
            let decrypted = ecb.decrypt(&ciphertext, &[]).unwrap();
            assert_eq!(original, decrypted);
        }
    }

    #[test]
    fn test_ecb_deterministic() {
        let key = "00112233445566778899aabbccddeeff";
        let ecb = Ecb::new(key).unwrap();
        let plaintext = b"Same plaintext";

        let ciphertext1 = ecb.encrypt(plaintext, &[]).unwrap();
        let ciphertext2 = ecb.encrypt(plaintext, &[]).unwrap();
        
        assert_eq!(ciphertext1, ciphertext2);
    }
}