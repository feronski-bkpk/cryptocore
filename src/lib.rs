pub mod cli;
pub mod crypto;
pub mod file;
pub mod csprng;
pub mod hash;
pub mod mac;

pub use cli::{Cli, Mode, Operation};
pub use crypto::{BlockMode, Cbc, Cfb, Ofb, Ctr, Ecb};
pub use mac::HMAC;

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
}