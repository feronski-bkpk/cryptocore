pub mod cli;
pub mod crypto;
pub mod file;

pub use cli::{Cli, Algorithm, Mode, Operation}; 
pub use crypto::AesEcb;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_creation() {
        let result = AesEcb::new("00112233445566778899aabbccddeeff");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_key() {
        let result = AesEcb::new("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_enum_values() {
        let _algo = Algorithm::Aes;
        let _mode = Mode::Ecb;
        let _op = Operation::Encrypt;
        let _op = Operation::Decrypt;
    }
}