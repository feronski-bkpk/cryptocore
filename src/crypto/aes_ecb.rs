use openssl::symm::{Cipher, Crypter, Mode};
use anyhow::{Result, anyhow};

const KEY_SIZE: usize = 16;

pub struct AesEcb {
    key: [u8; KEY_SIZE],
}

impl AesEcb {
    pub fn new(key_hex: &str) -> Result<Self> {
        let key = parse_hex_key(key_hex)?;
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, None)?;

        crypter.pad(true);

        let mut output = vec![0; plaintext.len() + KEY_SIZE];
        let mut count = crypter.update(plaintext, &mut output)?;
        count += crypter.finalize(&mut output[count..])?;
        output.truncate(count);

        Ok(output)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &self.key, None)?;

        crypter.pad(true);

        let mut output = vec![0; ciphertext.len() + KEY_SIZE];
        let mut count = crypter.update(ciphertext, &mut output)?;
        count += crypter.finalize(&mut output[count..])?;
        output.truncate(count);

        Ok(output)
    }
}

fn parse_hex_key(key_hex: &str) -> Result<[u8; KEY_SIZE]> {
    let key_str = key_hex.trim_start_matches('@');
    if key_str.len() != KEY_SIZE * 2 {
        return Err(anyhow!("Key must be {} hex characters", KEY_SIZE * 2));
    }

    let key_bytes = hex::decode(key_str)?;
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ecb_round_trip() {
        let key = "00112233445566778899aabbccddeeff";
        let aes = AesEcb::new(key).unwrap();
        let plaintext = b"Hello, CryptoCore! This is a test message.";

        let ciphertext = aes.encrypt(plaintext).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_parse_hex_key() {
        let key = "00112233445566778899aabbccddeeff";
        let result = parse_hex_key(key);
        assert!(result.is_ok());

        let key_array = result.unwrap();
        assert_eq!(key_array.len(), KEY_SIZE);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = "001122";
        let result = parse_hex_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex() {
        let key = "00112233445566778899aabbccddeefg";
        let result = parse_hex_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data() {
        let key = "00112233445566778899aabbccddeeff";
        let aes = AesEcb::new(key).unwrap();

        let empty_data = b"";
        let ciphertext = aes.encrypt(empty_data).unwrap();
        let decrypted = aes.decrypt(&ciphertext).unwrap();

        assert_eq!(empty_data, &decrypted[..]);
    }

    #[test]
    fn test_different_data_sizes() {
        let key = "00112233445566778899aabbccddeeff";
        let aes = AesEcb::new(key).unwrap();

        let test_cases = [
            b"A".to_vec(),
            b"Short".to_vec(),
            b"Medium length text".to_vec(),
            b"This is a longer test message that should work properly".to_vec(),
        ];

        for original in test_cases {
            let ciphertext = aes.encrypt(&original).unwrap();
            let decrypted = aes.decrypt(&ciphertext).unwrap();
            assert_eq!(original, decrypted);
        }
    }
}