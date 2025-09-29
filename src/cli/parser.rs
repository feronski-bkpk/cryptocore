use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Algorithm {
    Aes,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Mode {
    Ecb,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.1.0",
    about = "CryptoCore - AES-128 ECB encryption/decryption tool",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 ECB encryption and decryption.

Examples:
  Encryption:
    cryptocore --algorithm aes --mode ecb --operation encrypt --key 00112233445566778899aabbccddeeff --input plain.txt --output cipher.bin

  Decryption:
    cryptocore --algorithm aes --mode ecb --operation decrypt --key 00112233445566778899aabbccddeeff --input cipher.bin --output decrypted.txt
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
        long_help = "Specifies the mode of operation. Currently only 'ecb' is supported."
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