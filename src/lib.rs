pub mod cli;
pub mod crypto;
pub mod file;
pub mod csprng;
pub mod hash;
pub mod mac;
pub mod kdf;

pub use cli::{Cli, Mode, Operation, Algorithm};
pub use crypto::modes::{BlockMode, FromKeyBytes, Cbc, Cfb, Ofb, Ctr, Ecb, Gcm};
pub use crypto::aead::EncryptThenMac;
pub use mac::hmac;
pub use kdf::{pbkdf2_hmac_sha256, derive_key};
pub use csprng::Csprng;

pub const BLOCK_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;
pub const KEY_SIZE: usize = 16;

pub fn hex_to_key(hex_str: &str) -> Result<[u8; KEY_SIZE], anyhow::Error> {
    use hex;
    let key_str = hex_str.trim_start_matches('@');
    if key_str.len() != KEY_SIZE * 2 {
        return Err(anyhow::anyhow!("Key must be {} hex characters", KEY_SIZE * 2));
    }

    let key_bytes = hex::decode(key_str)?;
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&key_bytes);

    Ok(key)
}

pub fn key_to_hex(key: &[u8; KEY_SIZE]) -> String {
    use hex;
    hex::encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecb_creation() {
        let result = Ecb::new("00112233445566778899aabbccddeeff");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_key() {
        let result = Ecb::new("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_enum_values() {
        let _mode = Mode::Ecb;
        let _mode = Mode::Cbc;
        let _op = Operation::Encrypt;
        let _op = Operation::Decrypt;
    }

    #[test]
    fn test_hex_key_conversion() {
        let hex_key = "00112233445566778899aabbccddeeff";
        let key_bytes = hex_to_key(hex_key).unwrap();
        let hex_again = key_to_hex(&key_bytes);

        assert_eq!(hex_key, hex_again);
    }

    #[test]
    fn test_hex_key_with_prefix() {
        let hex_key = "@00112233445566778899aabbccddeeff";
        let key_bytes = hex_to_key(hex_key).unwrap();
        let hex_again = key_to_hex(&key_bytes);

        assert_eq!("00112233445566778899aabbccddeeff", hex_again);
    }
}