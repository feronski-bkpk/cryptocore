use clap::{Parser, Subcommand, ValueEnum};
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

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt or decrypt files using AES
    Crypto {
        #[arg(
            long,
            value_enum,
            help = "Encryption algorithm",
            long_help = "Specifies the cipher algorithm. Currently only 'aes' is supported."
        )]
        algorithm: Algorithm,

        #[arg(
            long,
            value_enum,
            help = "Mode of operation",
            long_help = "Specifies the mode of operation: ecb, cbc, cfb, ofb, ctr"
        )]
        mode: Mode,

        #[arg(
            long,
            value_enum,
            help = "Operation to perform",
            long_help = "Specifies whether to encrypt or decrypt the input file."
        )]
        operation: Operation,

        #[arg(
            long,
            help = "Encryption key as hexadecimal string (optional for encryption)",
            long_help = "16-byte key provided as 32-character hexadecimal string. Optional for encryption (will generate random key). Required for decryption. Prefix with '@' is optional."
        )]
        key: Option<String>,

        #[arg(
            long,
            help = "Input file path",
            long_help = "Path to the input file to be encrypted or decrypted."
        )]
        input: PathBuf,

        #[arg(
            long,
            help = "Output file path",
            long_help = "Path where the output will be written. If not provided, a default name will be generated."
        )]
        output: Option<PathBuf>,

        #[arg(
            long,
            help = "Initialization Vector as hexadecimal string (for decryption)",
            long_help = "16-byte IV provided as 32-character hexadecimal string. Required for decryption, ignored for encryption."
        )]
        iv: Option<String>,
    },

    /// Compute message digests (hash) of files
    Dgst {
        #[arg(
            long,
            help = "Hash algorithm to use",
            long_help = "Specifies the hash algorithm: sha256, sha3-256"
        )]
        algorithm: String,

        #[arg(
            long,
            help = "Input file path",
            long_help = "Path to the input file to be hashed. Use '-' for standard input."
        )]
        input: PathBuf,

        #[arg(
            long,
            help = "Output file path (optional)",
            long_help = "Path where the hash output will be written. If not provided, output goes to stdout."
        )]
        output: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.4.0",
    about = "CryptoCore - Encryption/decryption and hashing tool",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 encryption/decryption and hash computation.

Encryption/Decryption:
  Supported modes: ECB, CBC, CFB, OFB, CTR
  For encryption, --key is optional (random key will be generated)

Hashing:
  Supported algorithms: SHA-256, SHA3-256
  Output format: HASH_VALUE INPUT_FILE_PATH (compatible with *sum tools)

Examples:
  Encryption with automatic key generation:
    cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input plain.txt --output cipher.bin

  Compute SHA-256 hash:
    cryptocore dgst --algorithm sha256 --input document.pdf

  Compute SHA3-256 hash with output to file:
    cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
"#
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn validate(&self) -> Result<(), String> {
        match &self.command {
            Command::Crypto {
                algorithm: _,
                mode: _,
                operation,
                key,
                input,
                output: _,
                iv
            } => {
                // Validate key (if provided)
                if let Some(key) = key {
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
                } else if *operation == Operation::Decrypt {
                    return Err("Key is required for decryption".to_string());
                }

                // Validate IV (if provided)
                if let Some(iv) = iv {
                    let iv_str = iv.trim_start_matches('@');
                    if iv_str.len() != 32 {
                        return Err(format!("IV must be 32 hex characters, got {}", iv_str.len()));
                    }

                    if hex::decode(iv_str).is_err() {
                        return Err("IV must be a valid hexadecimal string".to_string());
                    }

                    if *operation == Operation::Encrypt {
                        return Err("IV should not be provided for encryption".to_string());
                    }
                }

                // Validate input file exists
                if !input.exists() && input.to_str() != Some("-") {
                    return Err(format!("Input file does not exist: {}", input.display()));
                }
            }
            Command::Dgst { algorithm, input, output: _ } => {
                // Validate hash algorithm
                if crate::hash::HashType::from_str(algorithm).is_none() {
                    return Err(format!("Unsupported hash algorithm: {}. Supported: sha256, sha3-256", algorithm));
                }

                // Validate input file exists (unless it's stdin)
                if !input.exists() && input.to_str() != Some("-") {
                    return Err(format!("Input file does not exist: {}", input.display()));
                }
            }
        }

        Ok(())
    }

    pub fn get_output_path(&self) -> Option<PathBuf> {
        match &self.command {
            Command::Crypto { input, output, operation, .. } => {
                output.clone().or_else(|| {
                    let default_name = match operation {
                        Operation::Encrypt => format!("{}.enc", input.display()),
                        Operation::Decrypt => format!("{}.dec", input.display()),
                    };
                    Some(PathBuf::from(default_name))
                })
            }
            Command::Dgst { output, .. } => {
                output.clone()
            }
        }
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