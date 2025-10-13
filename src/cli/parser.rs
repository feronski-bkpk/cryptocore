use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Algorithm {
    Aes,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Mode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.3.0",
    about = "CryptoCore - AES-128 encryption/decryption tool with multiple modes",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 encryption and decryption with multiple modes.

Supported modes: ECB, CBC, CFB, OFB, CTR

Key Generation:
  - For encryption, --key is now optional
  - If --key is omitted, a secure random 128-bit key will be generated
  - Generated keys are printed to stdout in hexadecimal format

Examples:
  Encryption with automatic key generation:
    cryptocore --algorithm aes --mode cbc --operation encrypt --input plain.txt --output cipher.bin

  Encryption with provided key:
    cryptocore --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input plain.txt --output cipher.bin

  Decryption (key always required):
    cryptocore --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --input cipher.bin --output decrypted.txt
"#
)]
pub struct Cli {
    #[arg(
        long,
        value_enum,
        help = "Encryption algorithm",
        long_help = "Specifies the cipher algorithm. Currently only 'aes' is supported."
    )]
    pub algorithm: Algorithm,

    #[arg(
        long,
        value_enum,
        help = "Mode of operation",
        long_help = "Specifies the mode of operation: ecb, cbc, cfb, ofb, ctr"
    )]
    pub mode: Mode,

    #[arg(
        long,
        value_enum,
        help = "Operation to perform",
        long_help = "Specifies whether to encrypt or decrypt the input file."
    )]
    pub operation: Operation,

    #[arg(
        long,
        help = "Encryption key as hexadecimal string (optional for encryption)",
        long_help = "16-byte key provided as 32-character hexadecimal string. Optional for encryption (will generate random key). Required for decryption. Prefix with '@' is optional."
    )]
    pub key: Option<String>,

    #[arg(
        long,
        help = "Input file path",
        long_help = "Path to the input file to be encrypted or decrypted."
    )]
    pub input: PathBuf,

    #[arg(
        long,
        help = "Output file path",
        long_help = "Path where the output will be written. If not provided, a default name will be generated."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long,
        help = "Initialization Vector as hexadecimal string (for decryption)",
        long_help = "16-byte IV provided as 32-character hexadecimal string. Required for decryption, ignored for encryption."
    )]
    pub iv: Option<String>,
}

impl Cli {
    pub fn validate(&self) -> Result<(), String> {
        // Validate key (if provided)
        if let Some(key) = &self.key {
            let key_str = key.trim_start_matches('@');
            if key_str.len() != 32 {
                return Err(format!("Key must be 32 hex characters, got {}", key_str.len()));
            }

            if hex::decode(key_str).is_err() {
                return Err("Key must be a valid hexadecimal string".to_string());
            }

            // Check for weak keys and warn (but don't fail)
            if Self::is_weak_key(key_str) {
                eprintln!("[WARNING] The provided key appears to be weak. Consider using a stronger key.");
            }
        } else if self.operation == Operation::Decrypt {
            return Err("Key is required for decryption".to_string());
        }

        // Validate IV (if provided)
        if let Some(iv) = &self.iv {
            let iv_str = iv.trim_start_matches('@');
            if iv_str.len() != 32 {
                return Err(format!("IV must be 32 hex characters, got {}", iv_str.len()));
            }

            if hex::decode(iv_str).is_err() {
                return Err("IV must be a valid hexadecimal string".to_string());
            }

            if self.operation == Operation::Encrypt {
                return Err("IV should not be provided for encryption".to_string());
            }
        }

        // Validate input file exists
        if !self.input.exists() {
            return Err(format!("Input file does not exist: {}", self.input.display()));
        }

        Ok(())
    }

    pub fn get_output_path(&self) -> PathBuf {
        self.output.clone().unwrap_or_else(|| {
            let default_name = match self.operation {
                Operation::Encrypt => format!("{}.enc", self.input.display()),
                Operation::Decrypt => format!("{}.dec", self.input.display()),
            };
            PathBuf::from(default_name)
        })
    }

    /// Checks if a key is weak (all zeros, sequential bytes, etc.)
    pub fn is_weak_key(key_hex: &str) -> bool {
        let key_str = key_hex.trim_start_matches('@');
        if let Ok(key_bytes) = hex::decode(key_str) {
            // Check for all zeros
            if key_bytes.iter().all(|&b| b == 0) {
                return true;
            }

            // Check for all same bytes
            if key_bytes.windows(2).all(|window| window[0] == window[1]) {
                return true;
            }

            // Check for sequential bytes (increasing)
            let is_sequential_inc = key_bytes.windows(2)
                .all(|window| window[1] == window[0].wrapping_add(1));

            // Check for sequential bytes (decreasing)
            let is_sequential_dec = key_bytes.windows(2)
                .all(|window| window[1] == window[0].wrapping_sub(1));

            if is_sequential_inc || is_sequential_dec {
                return true;
            }

            // Check for common weak patterns
            let common_weak = [
                "00000000000000000000000000000000",
                "ffffffffffffffffffffffffffffffff",
                "0123456789abcdef0123456789abcdef",
                "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
            ];

            if common_weak.contains(&key_str.to_lowercase().as_str()) {
                return true;
            }
        }
        false
    }
}