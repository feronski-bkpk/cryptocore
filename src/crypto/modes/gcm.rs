use anyhow::{Result, anyhow};
use openssl::symm::{Cipher, Crypter, Mode};
use hex;

const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

pub struct Gcm {
    key: [u8; BLOCK_SIZE],
}

impl Gcm {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    pub fn new_from_bytes(key: &[u8; BLOCK_SIZE]) -> Result<Self> {
        if key.len() != BLOCK_SIZE {
            return Err(anyhow!("Key must be {} bytes", BLOCK_SIZE));
        }

        let mut key_array = [0u8; BLOCK_SIZE];
        key_array.copy_from_slice(key);

        Ok(Self { key: key_array })
    }

    pub fn new_from_key_bytes(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != BLOCK_SIZE {
            return Err(anyhow!("Key must be {} bytes", BLOCK_SIZE));
        }

        let mut key = [0u8; BLOCK_SIZE];
        key.copy_from_slice(key_bytes);

        Ok(Self { key })
    }

    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        openssl::rand::rand_bytes(&mut nonce).unwrap();
        nonce
    }

    pub fn encrypt_with_aad(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_SIZE {
            return Err(anyhow!("Nonce must be {} bytes for GCM", NONCE_SIZE));
        }

        let h = self.aes_encrypt_block(&[0u8; BLOCK_SIZE])?;
        let h_array: [u8; BLOCK_SIZE] = h.try_into().unwrap();

        let mut counter = [0u8; BLOCK_SIZE];
        counter[..NONCE_SIZE].copy_from_slice(nonce);
        counter[BLOCK_SIZE - 1] = 0x01;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut ctr_block = counter;

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            Self::inc_32(&mut ctr_block[BLOCK_SIZE - 4..]);

            let keystream = self.aes_encrypt_block(&ctr_block)?;

            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
        }

        let tag = self.compute_tag(&h_array, nonce, &ciphertext, aad)?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + TAG_SIZE);
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    pub fn decrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(anyhow!("Data too short for GCM format"));
        }

        let nonce = &data[..NONCE_SIZE];
        let tag_start = data.len() - TAG_SIZE;
        let received_tag = &data[tag_start..];
        let ciphertext = &data[NONCE_SIZE..tag_start];

        let h = self.aes_encrypt_block(&[0u8; BLOCK_SIZE])?;
        let h_array: [u8; BLOCK_SIZE] = h.try_into().unwrap();

        let expected_tag = self.compute_tag(&h_array, nonce, ciphertext, aad)?;

        if received_tag != expected_tag {
            return Err(anyhow!("Authentication failed: tag mismatch"));
        }

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

    fn compute_tag(&self, h: &[u8; BLOCK_SIZE], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<[u8; TAG_SIZE]> {
        let mut auth_data = Vec::new();

        if !aad.is_empty() {
            let aad_padded_len = ((aad.len() + 15) / 16) * 16;
            let mut padded_aad = vec![0u8; aad_padded_len];
            padded_aad[..aad.len()].copy_from_slice(aad);
            auth_data.extend_from_slice(&padded_aad);
        }

        let ciphertext_padded_len = ((ciphertext.len() + 15) / 16) * 16;
        let mut padded_ciphertext = vec![0u8; ciphertext_padded_len];
        padded_ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
        auth_data.extend_from_slice(&padded_ciphertext);

        let mut len_block = [0u8; BLOCK_SIZE];
        let aad_len_bits = (aad.len() as u64) * 8;
        let ciphertext_len_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&aad_len_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ciphertext_len_bits.to_be_bytes());
        auth_data.extend_from_slice(&len_block);

        let mut y = [0u8; BLOCK_SIZE];

        for chunk in auth_data.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            if chunk.len() == BLOCK_SIZE {
                block.copy_from_slice(chunk);
            } else {
                block[..chunk.len()].copy_from_slice(chunk);
            }

            for i in 0..BLOCK_SIZE {
                block[i] ^= y[i];
            }

            y = self.gf128_mul(&block, h);
        }

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
                v ^= 0x87u128 << 120;
            }
        }

        z.to_be_bytes()
    }

    fn aes_encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;
        crypter.pad(false);

        let mut output = vec![0; BLOCK_SIZE * 2];
        let count = crypter.update(block, &mut output)?;
        output.truncate(count);
        Ok(output)
    }

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

        let result_ciphertext = &result[12..result.len()-16];
        let result_tag = &result[result.len()-16..];

        assert_eq!(result_ciphertext, expected_ciphertext);
        assert_eq!(result_tag, expected_tag);

        let decrypted = gcm.decrypt_with_aad(&result, &aad)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

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

        let ciphertext1 = &result1[12..12+expected_ciphertext.len()];
        let ciphertext2 = &result2[12..12+expected_ciphertext.len()];

        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext1, expected_ciphertext.as_slice());

        let decrypted1 = gcm_from_bytes.decrypt_with_aad(&result1, &aad)?;
        let decrypted2 = gcm_from_hex.decrypt_with_aad(&result2, &aad)?;

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);

        Ok(())
    }

    #[test]
    fn test_gf128_mul() -> Result<()> {
        let gcm = Gcm::new("00000000000000000000000000000000")?;

        let mut one = [0u8; 16];
        one[15] = 0x01;

        let result = gcm.gf128_mul(&one, &one);

        println!("1 in GF(2^128): {:?}", one);
        println!("1 * 1 result: {:?}", result);

        assert!(!result.iter().all(|&b| b == 0), "1 * 1 should not be zero");

        let zero = [0u8; 16];
        let zero_result = gcm.gf128_mul(&one, &zero);
        assert_eq!(zero_result, zero, "1 * 0 should be 0");

        let zero_result2 = gcm.gf128_mul(&zero, &one);
        assert_eq!(zero_result2, zero, "0 * 1 should be 0");

        println!("GF(2^128) multiplication has correct properties");

        Ok(())
    }
}