//! Command-line argument parser for cryptocore.
//!
//! This module defines the CLI structure using the `clap` crate.
//! It includes argument parsing, validation, and help text generation
//! for all supported cryptocore operations.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Supported encryption algorithms.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Algorithm {
    /// AES-128 block cipher
    Aes,
}

/// Supported encryption modes of operation.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Mode {
    /// Electronic Codebook mode (unauthenticated)
    Ecb,
    /// Cipher Block Chaining mode (unauthenticated)
    Cbc,
    /// Cipher Feedback mode (unauthenticated)
    Cfb,
    /// Output Feedback mode (unauthenticated)
    Ofb,
    /// Counter mode (unauthenticated)
    Ctr,
    /// Galois/Counter Mode (authenticated)
    Gcm,
    /// Encrypt-then-MAC mode (authenticated)
    Etm,
}

/// Supported key derivation function algorithms.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum KdfAlgorithm {
    /// PBKDF2 (Password-Based Key Derivation Function 2)
    Pbkdf2,
}

/// Supported cryptographic operations.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum Operation {
    /// Encrypt data
    Encrypt,
    /// Decrypt data
    Decrypt,
}

/// Arguments for key derivation operations.
#[derive(Args, Debug)]
pub struct DeriveArgs {
    /// Password string for key derivation.
    ///
    /// The password from which to derive the cryptographic key.
    /// If containing special characters, quote properly in shell.
    #[arg(
        long,
        help = "Password string",
        long_help = "Password for key derivation. If containing special characters, quote properly in shell."
    )]
    pub password: String,

    /// Salt as hexadecimal string (optional).
    ///
    /// Salt for key derivation as hexadecimal string.
    /// If not provided, a random 16-byte salt will be generated.
    #[arg(
        long,
        help = "Salt as hexadecimal string (optional)",
        long_help = "Salt for key derivation as hexadecimal string. If not provided, a random 16-byte salt will be generated."
    )]
    pub salt: Option<String>,

    /// Iteration count for key derivation function.
    ///
    /// Number of iterations for the key derivation function.
    /// Higher values increase security but slow down derivation.
    #[arg(
        long,
        help = "Iteration count",
        long_help = "Number of iterations for key derivation function.",
        default_value_t = 100000
    )]
    pub iterations: u32,

    /// Desired length of derived key in bytes.
    ///
    /// Length in bytes for the derived key.
    /// For AES-128, use 16; for AES-256, use 32.
    #[arg(
        long,
        help = "Key length in bytes",
        long_help = "Desired length of derived key in bytes.",
        default_value_t = 32
    )]
    pub length: usize,

    /// Key derivation function algorithm.
    ///
    /// Algorithm to use for key derivation.
    #[arg(
        long,
        value_enum,
        help = "KDF algorithm",
        long_help = "Key derivation function algorithm.",
        default_value = "pbkdf2"
    )]
    pub algorithm: KdfAlgorithm,

    /// Output file path for derived key (optional).
    ///
    /// Path where derived key will be written.
    /// If not provided, output goes to stdout.
    #[arg(
        long,
        help = "Output file path (optional)",
        long_help = "Path where derived key will be written. If not provided, output goes to stdout."
    )]
    pub output: Option<PathBuf>,
}

/// Main command enumeration for cryptocore.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt or decrypt files using AES
    Crypto {
        /// Encryption algorithm to use.
        ///
        /// Specifies the cipher algorithm.
        /// Currently only 'aes' is supported.
        #[arg(
            long,
            value_enum,
            help = "Encryption algorithm",
            long_help = "Specifies the cipher algorithm. Currently only 'aes' is supported."
        )]
        algorithm: Algorithm,

        /// Mode of operation.
        ///
        /// Specifies the mode of operation: ecb, cbc, cfb, ofb, ctr, gcm, etm
        ///
        /// ETM (Encrypt-then-MAC) mode combines any block cipher mode with HMAC-SHA256.
        /// For ETM mode, specify base mode with --base-mode (default: cbc).
        #[arg(
            long,
            value_enum,
            help = "Mode of operation",
            long_help = "Specifies the mode of operation: ecb, cbc, cfb, ofb, ctr, gcm, etm\n\n\
                        ETM (Encrypt-then-MAC) mode combines any block cipher mode with HMAC-SHA256.\n\
                        For ETM mode, specify base mode with --base-mode (default: cbc)."
        )]
        mode: Mode,

        /// Operation to perform.
        ///
        /// Specifies whether to encrypt or decrypt the input file.
        #[arg(
            long,
            value_enum,
            help = "Operation to perform",
            long_help = "Specifies whether to encrypt or decrypt the input file."
        )]
        operation: Operation,

        /// Encryption key as hexadecimal string (optional for encryption).
        ///
        /// 16-byte key provided as 32-character hexadecimal string.
        /// Optional for encryption (will generate random key).
        /// Required for decryption.
        /// Prefix with '@' is optional.
        #[arg(
            long,
            help = "Encryption key as hexadecimal string (optional for encryption)",
            long_help = "16-byte key provided as 32-character hexadecimal string. Optional for encryption (will generate random key). Required for decryption. Prefix with '@' is optional."
        )]
        key: Option<String>,

        /// Input file path.
        ///
        /// Path to the input file to be encrypted or decrypted.
        #[arg(
            long,
            help = "Input file path",
            long_help = "Path to the input file to be encrypted or decrypted."
        )]
        input: PathBuf,

        /// Output file path.
        ///
        /// Path where the output will be written.
        /// If not provided, a default name will be generated.
        #[arg(
            long,
            help = "Output file path",
            long_help = "Path where the output will be written. If not provided, a default name will be generated."
        )]
        output: Option<PathBuf>,

        /// Initialization Vector as hexadecimal string (for decryption).
        ///
        /// 16-byte IV provided as 32-character hexadecimal string.
        /// Required for decryption in ECB/CBC/CFB/OFB/CTR modes, ignored for encryption.
        /// For GCM mode, use --nonce.
        #[arg(
            long,
            help = "Initialization Vector as hexadecimal string (for decryption)",
            long_help = "16-byte IV provided as 32-character hexadecimal string. Required for decryption in ECB/CBC/CFB/OFB/CTR modes, ignored for encryption. For GCM mode, use --nonce."
        )]
        iv: Option<String>,

        /// Nonce for GCM mode (12 bytes as hex).
        ///
        /// 12-byte nonce provided as 24-character hexadecimal string.
        /// For GCM encryption, if not provided, random nonce will be generated.
        /// For GCM decryption, can be read from file or provided here.
        #[arg(
            long,
            help = "Nonce for GCM mode (12 bytes as hex)",
            long_help = "12-byte nonce provided as 24-character hexadecimal string. For GCM encryption, if not provided, random nonce will be generated. For GCM decryption, can be read from file or provided here."
        )]
        nonce: Option<String>,

        /// Associated Authenticated Data for authenticated modes (hex string).
        ///
        /// Additional authenticated data (AAD) for GCM and ETM modes as hexadecimal string.
        /// Optional, treated as empty if not provided.
        #[arg(
            long,
            help = "Associated Authenticated Data for authenticated modes (hex string)",
            long_help = "Additional authenticated data (AAD) for GCM and ETM modes as hexadecimal string. Optional, treated as empty if not provided."
        )]
        aad: Option<String>,

        /// Base mode for ETM (Encrypt-then-MAC).
        ///
        /// Specifies the base encryption mode when using ETM mode.
        /// Only used when --mode is set to 'etm'.
        /// Options: ecb, cbc, cfb, ofb, ctr
        #[arg(
            long,
            value_enum,
            help = "Base mode for ETM (Encrypt-then-MAC)",
            long_help = "Specifies the base encryption mode when using ETM mode.\n\
                        Only used when --mode is set to 'etm'.\n\
                        Options: ecb, cbc, cfb, ofb, ctr",
        )]
        base_mode: Option<Mode>,
    },

    /// Compute message digests (hash) of files
    Dgst {
        /// Hash algorithm to use.
        ///
        /// Specifies the hash algorithm: sha256, sha3-256
        #[arg(
            long,
            help = "Hash algorithm to use",
            long_help = "Specifies the hash algorithm: sha256, sha3-256"
        )]
        algorithm: String,

        /// Input file path.
        ///
        /// Path to the input file to be hashed.
        /// Use '-' for standard input.
        #[arg(
            long,
            help = "Input file path",
            long_help = "Path to the input file to be hashed. Use '-' for standard input."
        )]
        input: PathBuf,

        /// Output file path (optional).
        ///
        /// Path where the hash output will be written.
        /// If not provided, output goes to stdout.
        #[arg(
            long,
            help = "Output file path (optional)",
            long_help = "Path where the hash output will be written. If not provided, output goes to stdout."
        )]
        output: Option<PathBuf>,

        /// Enable HMAC mode.
        ///
        /// Enables HMAC (Hash-based Message Authentication Code) mode.
        /// Requires --key.
        #[arg(
            long,
            help = "Enable HMAC mode",
            long_help = "Enables HMAC (Hash-based Message Authentication Code) mode. Requires --key."
        )]
        hmac: bool,

        /// Key for HMAC as hexadecimal string.
        ///
        /// Key for HMAC provided as hexadecimal string.
        /// Can be of arbitrary length.
        /// Required when --hmac is specified.
        #[arg(
            long,
            help = "Key for HMAC as hexadecimal string",
            long_help = "Key for HMAC provided as hexadecimal string. Can be of arbitrary length. Required when --hmac is specified."
        )]
        key: Option<String>,

        /// Verify HMAC against expected value from file.
        ///
        /// File containing expected HMAC value for verification.
        /// Format: HMAC_VALUE FILENAME
        #[arg(
            long,
            help = "Verify HMAC against expected value from file",
            long_help = "File containing expected HMAC value for verification. Format: HMAC_VALUE FILENAME"
        )]
        verify: Option<PathBuf>,
    },

    /// Derive cryptographic keys from passwords
    Derive {
        /// Key derivation arguments
        #[command(flatten)]
        args: DeriveArgs,
    },
}

/// Main command-line interface structure for cryptocore.
#[derive(Parser, Debug)]
#[command(
    name = "cryptocore",
    version = "0.7.0",
    about = "CryptoCore - Encryption/decryption, hashing, HMAC and key derivation tool",
    long_about = r#"
CryptoCore: A command-line tool for AES-128 encryption/decryption, hash computation, HMAC, authenticated encryption and key derivation.

Encryption/Decryption:
  Supported modes: ECB, CBC, CFB, OFB, CTR, GCM, ETM
  For encryption, --key is optional (random key will be generated)

Authenticated Encryption:
  GCM mode with AAD support (--aad flag)
  ETM (Encrypt-then-MAC) mode combining any block mode with HMAC-SHA256
    Use --base-mode to specify underlying encryption mode (default: cbc)

Hashing:
  Supported algorithms: SHA-256, SHA3-256
  Output format: HASH_VALUE INPUT_FILE_PATH (compatible with *sum tools)

HMAC:
  HMAC-SHA256 support with --hmac and --key flags
  Verification support with --verify flag

Key Derivation (NEW in v0.7.0):
  PBKDF2-HMAC-SHA256 for deriving keys from passwords
  Key hierarchy function for deriving multiple keys from master key

Examples:
  Key Derivation with PBKDF2:
    cryptocore derive --password "MySecurePassword" --salt a1b2c3d4 --iterations 100000 --length 32

  GCM Encryption with AAD:
    cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key KEY --input plain.txt --output cipher.bin --aad AABBCC

  GCM Decryption with AAD:
    cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key KEY --input cipher.bin --output decrypted.txt --aad AABBCC

  ETM Encryption with CBC as base mode:
    cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt --key KEY --input plain.txt --output cipher.bin --aad AABBCC

  Encryption with automatic key generation:
    cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input plain.txt --output cipher.bin

  Compute SHA-256 hash:
    cryptocore dgst --algorithm sha256 --input document.pdf

  Compute HMAC-SHA256:
    cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
"#
)]
pub struct Cli {
    /// The command to execute
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Validates the command-line arguments for correctness and consistency.
    ///
    /// Performs various checks including:
    /// - Key format and length validation
    /// - Mode-specific parameter validation
    /// - File existence checks
    /// - Weak key detection
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all arguments are valid
    /// * `Err(String)` - If any validation fails, with an error message
    pub fn validate(&self) -> Result<(), String> {
        match &self.command {
            Command::Crypto {
                algorithm: _,
                mode,
                operation,
                key,
                input,
                output: _,
                iv,
                nonce,
                aad,
                base_mode,
            } => {
                // Key validation
                if let Some(key) = key {
                    let key_str = key.trim_start_matches('@');
                    if key_str.len() != 32 {
                        return Err(format!(
                            "Key must be 32 hex characters, got {}",
                            key_str.len()
                        ));
                    }

                    if hex::decode(key_str).is_err() {
                        return Err("Key must be a valid hexadecimal string".to_string());
                    }

                    if Self::is_weak_key(key_str) {
                        eprintln!(
                            "[WARNING] The provided key appears to be weak. Consider using a stronger key."
                        );
                    }
                } else if *operation == Operation::Decrypt {
                    return Err("Key is required for decryption".to_string());
                }

                // ETM mode validation
                if *mode == Mode::Etm {
                    if let Some(bm) = base_mode {
                        match bm {
                            Mode::Gcm | Mode::Etm => {
                                return Err("ETM base mode cannot be GCM or ETM".to_string());
                            }
                            _ => {}
                        }
                    }
                } else {
                    if base_mode.is_some() {
                        return Err("--base-mode should only be used with --mode etm".to_string());
                    }
                }

                // Mode-specific validation
                match mode {
                    Mode::Gcm => {
                        if let Some(nonce_val) = nonce {
                            let nonce_str = nonce_val.trim_start_matches('@');
                            if nonce_str.len() != 24 {
                                return Err(format!(
                                    "Nonce must be 24 hex characters (12 bytes) for GCM, got {}",
                                    nonce_str.len()
                                ));
                            }
                            if hex::decode(nonce_str).is_err() {
                                return Err("Nonce must be a valid hexadecimal string".to_string());
                            }
                        }
                        if iv.is_some() {
                            eprintln!("[WARNING] --iv is deprecated for GCM mode, use --nonce instead");
                        }
                    }
                    Mode::Etm => {
                        if let Some(iv_val) = iv {
                            let iv_str = iv_val.trim_start_matches('@');
                            if iv_str.len() != 32 {
                                return Err(format!(
                                    "IV must be 32 hex characters, got {}",
                                    iv_str.len()
                                ));
                            }
                            if hex::decode(iv_str).is_err() {
                                return Err("IV must be a valid hexadecimal string".to_string());
                            }
                            if *operation == Operation::Encrypt {
                                return Err("IV should not be provided for encryption in ETM mode"
                                    .to_string());
                            }
                        }
                    }
                    _ => {
                        if let Some(iv_val) = iv {
                            let iv_str = iv_val.trim_start_matches('@');
                            if iv_str.len() != 32 {
                                return Err(format!(
                                    "IV must be 32 hex characters, got {}",
                                    iv_str.len()
                                ));
                            }
                            if hex::decode(iv_str).is_err() {
                                return Err("IV must be a valid hexadecimal string".to_string());
                            }
                            if *operation == Operation::Encrypt {
                                return Err(
                                    "IV should not be provided for encryption".to_string()
                                );
                            }
                        }
                    }
                }

                // AAD validation
                if let Some(aad_val) = aad {
                    let aad_str = aad_val.trim_start_matches('@');
                    if hex::decode(aad_str).is_err() {
                        return Err("AAD must be a valid hexadecimal string".to_string());
                    }
                }

                // Input file validation
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
                verify,
            } => {
                // Algorithm validation
                if crate::hash::HashType::from_str(algorithm).is_none() {
                    return Err(format!(
                        "Unsupported hash algorithm: {}. Supported: sha256, sha3-256",
                        algorithm
                    ));
                }

                // HMAC validation
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

                // Input file validation
                if !input.exists() && input.to_str() != Some("-") {
                    return Err(format!("Input file does not exist: {}", input.display()));
                }

                // Verify file validation
                if let Some(verify_path) = verify {
                    if !verify_path.exists() {
                        return Err(format!("Verify file does not exist: {}", verify_path.display()));
                    }
                }
            }
            Command::Derive { args } => {
                // Password validation
                if args.password.is_empty() {
                    return Err("Password cannot be empty".to_string());
                }

                // Key length validation
                if args.length == 0 {
                    return Err("Key length must be greater than 0".to_string());
                }

                // Iteration count validation
                if args.iterations == 0 {
                    return Err("Iteration count must be greater than 0".to_string());
                }

                // Salt validation
                if let Some(salt) = &args.salt {
                    if salt.is_empty() {
                        return Err("Salt cannot be empty".to_string());
                    }
                }
            }
        }

        Ok(())
    }

    /// Gets the output file path for the current command.
    ///
    /// Returns the explicitly provided output path, or generates a default
    /// based on input filename and operation type.
    ///
    /// # Returns
    ///
    /// * `Some(PathBuf)` - Output file path
    /// * `None` - If output should go to stdout
    #[allow(dead_code)]
    pub fn get_output_path(&self) -> Option<PathBuf> {
        match &self.command {
            Command::Crypto {
                input,
                output,
                operation,
                ..
            } => output.clone().or_else(|| {
                let default_name = match operation {
                    Operation::Encrypt => format!("{}.enc", input.display()),
                    Operation::Decrypt => format!("{}.dec", input.display()),
                };
                Some(PathBuf::from(default_name))
            }),
            Command::Dgst { output, .. } => output.clone(),
            Command::Derive { args } => args.output.clone(),
        }
    }

    /// Detects if a key appears to be weak.
    ///
    /// Checks for common weak key patterns:
    /// - All zeros
    /// - All same bytes
    /// - Sequential bytes (increasing or decreasing)
    /// - Common weak key patterns
    ///
    /// # Arguments
    ///
    /// * `key_hex` - Key in hexadecimal string format
    ///
    /// # Returns
    ///
    /// `true` if the key appears weak, `false` otherwise
    ///
    /// # Note
    ///
    /// This is a heuristic check and not a comprehensive security analysis.
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

            // Check for sequential bytes
            let is_sequential_inc = key_bytes
                .windows(2)
                .all(|window| window[1] == window[0].wrapping_add(1));

            let is_sequential_dec = key_bytes
                .windows(2)
                .all(|window| window[1] == window[0].wrapping_sub(1));

            if is_sequential_inc || is_sequential_dec {
                return true;
            }

            // Check common weak keys
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