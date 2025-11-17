use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const BLOCK_SIZE: usize = 16;

pub struct Cbc {
    key: [u8; BLOCK_SIZE],
}

impl Cbc {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    fn encrypt_block(&self, block: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];

        // XOR с предыдущим блоком (или IV)
        let mut xored = vec![0; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = block[i] ^ iv[i];
        }

        let count = crypter.update(&xored, &mut output)?;
        output.truncate(count);
        Ok(output)
    }

    fn decrypt_block(&self, block: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(block, &mut output)?;
        output.truncate(count);

        // XOR с предыдущим блоком (или IV)
        for i in 0..BLOCK_SIZE {
            output[i] ^= iv[i];
        }

        Ok(output)
    }
}

impl super::BlockMode for Cbc {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        let padded = pkcs7_pad(plaintext, BLOCK_SIZE);
        let mut ciphertext = Vec::new();
        let mut prev_block = iv.to_vec();

        for chunk in padded.chunks(BLOCK_SIZE) {
            let encrypted = self.encrypt_block(chunk, &prev_block)?;
            ciphertext.extend_from_slice(&encrypted);
            prev_block = encrypted;
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if iv.len() != BLOCK_SIZE {
            return Err(anyhow!("IV must be {} bytes", BLOCK_SIZE));
        }

        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(anyhow!("Ciphertext length must be multiple of block size"));
        }

        let mut plaintext = Vec::new();
        let mut prev_block = iv.to_vec();

        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let decrypted = self.decrypt_block(chunk, &prev_block)?;
            plaintext.extend_from_slice(&decrypted);
            prev_block = chunk.to_vec();
        }

        let unpadded = pkcs7_unpad(&plaintext, BLOCK_SIZE)?;
        Ok(unpadded)
    }
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let padding_byte = padding_len as u8;

    let mut padded = data.to_vec();
    padded.resize(data.len() + padding_len, padding_byte);
    padded
}

fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(data.to_vec());
    }

    let padding_byte = data[data.len() - 1];
    let padding_len = padding_byte as usize;

    if padding_len == 0 || padding_len > block_size {
        return Err(anyhow!("Invalid padding"));
    }

    for i in (data.len() - padding_len)..data.len() {
        if data[i] != padding_byte {
            return Err(anyhow!("Invalid padding"));
        }
    }

    Ok(data[..data.len() - padding_len].to_vec())
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
    fn test_cbc_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x00; 16];
        let cbc = Cbc::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore CBC Mode!";

        let ciphertext = cbc.encrypt(plaintext, &iv).unwrap();
        let decrypted = cbc.decrypt(&ciphertext, &iv).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_pkcs7_pad_unpad() {
        let data = b"test";
        let padded = pkcs7_pad(data, 16);
        assert_eq!(padded.len(), 16);

        let unpadded = pkcs7_unpad(&padded, 16).unwrap();
        assert_eq!(data, &unpadded[..]);
    }

    #[test]
    fn test_cbc_different_sizes() {
        let key = "00112233445566778899aabbccddeeff";
        let iv = vec![0x01; 16];
        let cbc = Cbc::new(key).unwrap();

        let test_cases = [
            b"".to_vec(),
            b"A".to_vec(),
            b"Short text".to_vec(),
            b"Medium length text here".to_vec(),
            b"This is a much longer test message to ensure CBC works with various sizes".to_vec(),
        ];

        for original in test_cases {
            let ciphertext = cbc.encrypt(&original, &iv).unwrap();
            let decrypted = cbc.decrypt(&ciphertext, &iv).unwrap();
            assert_eq!(original, decrypted);
        }
    }
}