use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]  // Добавь PartialEq здесь
pub enum Algorithm {
    Aes,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]  // Добавь PartialEq здесь
pub enum Mode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]  // Добавь PartialEq здесь
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.2.0",
    about = "CryptoCore - AES-128 encryption/decryption tool with multiple modes",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 encryption and decryption with multiple modes.

Supported modes: ECB, CBC, CFB, OFB, CTR

Examples:
  Encryption (generates random IV):
    cryptocore --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input plain.txt --output cipher.bin

  Decryption (IV must be provided):
    cryptocore --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv AABBCCDDEEFF00112233445566778899 --input cipher.bin --output decrypted.txt
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
        help = "Encryption key as hexadecimal string",
        long_help = "16-byte key provided as 32-character hexadecimal string. Prefix with '@' is optional."
    )]
    pub key: String,

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
        let key_str = self.key.trim_start_matches('@');
        if key_str.len() != 32 {
            return Err(format!("Key must be 32 hex characters, got {}", key_str.len()));
        }

        if hex::decode(key_str).is_err() {
            return Err("Key must be a valid hexadecimal string".to_string());
        }
        
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
}