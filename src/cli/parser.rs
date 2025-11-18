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

        #[arg(
            long,
            help = "Enable HMAC mode",
            long_help = "Enables HMAC (Hash-based Message Authentication Code) mode. Requires --key."
        )]
        hmac: bool,

        #[arg(
            long,
            help = "Key for HMAC as hexadecimal string",
            long_help = "Key for HMAC provided as hexadecimal string. Can be of arbitrary length. Required when --hmac is specified."
        )]
        key: Option<String>,

        #[arg(
            long,
            help = "Verify HMAC against expected value from file",
            long_help = "File containing expected HMAC value for verification. Format: HMAC_VALUE FILENAME"
        )]
        verify: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.5.0",
    about = "CryptoCore - Encryption/decryption, hashing and HMAC tool",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 encryption/decryption, hash computation and HMAC.

Encryption/Decryption:
  Supported modes: ECB, CBC, CFB, OFB, CTR
  For encryption, --key is optional (random key will be generated)

Hashing:
  Supported algorithms: SHA-256, SHA3-256
  Output format: HASH_VALUE INPUT_FILE_PATH (compatible with *sum tools)

HMAC:
  New in v0.5.0: HMAC-SHA256 support with --hmac and --key flags
  Verification support with --verify flag

Examples:
  Encryption with automatic key generation:
    cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input plain.txt --output cipher.bin

  Compute SHA-256 hash:
    cryptocore dgst --algorithm sha256 --input document.pdf

  Compute HMAC-SHA256:
    cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt

  Verify HMAC:
    cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected_hmac.txt
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
                if let Some(key) = key {
                    let key_str = key.trim_start_matches('@');
                    if key_str.len() != 32 {
                        return Err(format!("Key must be 32 hex characters, got {}", key_str.len()));
                    }

                    if hex::decode(key_str).is_err() {
                        return Err("Key must be a valid hexadecimal string".to_string());
                    }

                    if Self::is_weak_key(key_str) {
                        eprintln!("[WARNING] The provided key appears to be weak. Consider using a stronger key.");
                    }
                } else if *operation == Operation::Decrypt {
                    return Err("Key is required for decryption".to_string());
                }

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

                if !input.exists() && input.to_str() != Some("-") {
                    return Err(format!("Input file does not exist: {}", input.display()));
                }
            }
            Command::Dgst {
                algorithm,
                input,
                output: _,
                hmac,
                key,
                verify
            } => {
                if crate::hash::HashType::from_str(algorithm).is_none() {
                    return Err(format!("Unsupported hash algorithm: {}. Supported: sha256, sha3-256", algorithm));
                }

                if *hmac {
                    if key.is_none() {
                        return Err("Key is required when --hmac is specified".to_string());
                    }

                    if let Some(key_hex) = key {
                        let key_str = key_hex.trim_start_matches('@');
                        if hex::decode(key_str).is_err() {
                            return Err("HMAC key must be a valid hexadecimal string".to_string());
                        }
                    }
                } else {
                    if key.is_some() {
                        return Err("Key should only be provided with --hmac flag".to_string());
                    }
                    if verify.is_some() {
                        return Err("--verify should only be used with --hmac flag".to_string());
                    }
                }

                if !input.exists() && input.to_str() != Some("-") {
                    return Err(format!("Input file does not exist: {}", input.display()));
                }

                if let Some(verify_path) = verify {
                    if !verify_path.exists() {
                        return Err(format!("Verify file does not exist: {}", verify_path.display()));
                    }
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
            if key_bytes.iter().all(|&b| b == 0) {
                return true;
            }

            if key_bytes.windows(2).all(|window| window[0] == window[1]) {
                return true;
            }

            let is_sequential_inc = key_bytes.windows(2)
                .all(|window| window[1] == window[0].wrapping_add(1));

            let is_sequential_dec = key_bytes.windows(2)
                .all(|window| window[1] == window[0].wrapping_sub(1));

            if is_sequential_inc || is_sequential_dec {
                return true;
            }

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