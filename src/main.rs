use clap::Parser;
use anyhow::Result;

mod cli;
mod crypto;
mod file;
mod csprng;

use crate::cli::{Cli, Operation, Mode};
use crate::crypto::{BlockMode, Cbc, Cfb, Ofb, Ctr, Ecb};
use crate::file::{read_file, write_file, extract_iv_from_file, prepend_iv_to_data};
use crate::csprng::Csprng;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = cli.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Handle key generation or validation
    let (key_hex, is_key_generated) = match (&cli.operation, &cli.key) {
        (Operation::Encrypt, None) => {
            // Generate random key
            let key_bytes = Csprng::generate_key()?;
            let key_hex = hex::encode(key_bytes);
            println!("[INFO] Generated random key: {}", key_hex);
            (key_hex, true)
        }
        (Operation::Encrypt, Some(key)) => {
            (key.clone(), false)
        }
        (Operation::Decrypt, None) => {
            return Err(anyhow::anyhow!("Key is required for decryption"));
        }
        (Operation::Decrypt, Some(key)) => {
            (key.clone(), false)
        }
    };

    let output_path = cli.get_output_path();
    let input_data = read_file(&cli.input)?;

    let output_data = match (cli.operation, cli.mode) {
        (Operation::Encrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&key_hex)?;
            ecb.encrypt(&input_data, &[])?
        }
        (Operation::Decrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&key_hex)?;
            ecb.decrypt(&input_data, &[])?
        }

        (Operation::Encrypt, mode) => {
            // Generate IV using CSPRNG
            let iv = Csprng::generate_iv()?;
            let ciphertext = encrypt_with_mode(&key_hex, mode, &input_data, &iv)?;
            prepend_iv_to_data(&iv, &ciphertext)
        }

        (Operation::Decrypt, mode) => {
            match mode {
                Mode::Ecb => {
                    decrypt_with_mode(&key_hex, mode, &input_data, &[])?
                }
                _ => {
                    if let Some(iv_hex) = &cli.iv {
                        let iv_bytes = hex::decode(iv_hex.trim_start_matches('@'))?;
                        let mut iv = [0u8; 16];
                        iv.copy_from_slice(&iv_bytes);
                        decrypt_with_mode(&key_hex, mode, &input_data, &iv)?
                    } else {
                        let (iv, ciphertext) = extract_iv_from_file(&input_data)?;
                        decrypt_with_mode(&key_hex, mode, ciphertext, &iv)?
                    }
                }
            }
        }
    };

    write_file(&output_path, &output_data)?;

    if is_key_generated {
        println!("[INFO] Remember to save the generated key for decryption!");
    }

    println!("Operation completed successfully!");
    println!("Output: {}", output_path.display());

    Ok(())
}

fn encrypt_with_mode(key: &str, mode: Mode, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::Ecb => {
            let ecb = Ecb::new(key)?;
            ecb.encrypt(plaintext, iv)
        }
        Mode::Cbc => {
            let cbc = Cbc::new(key)?;
            cbc.encrypt(plaintext, iv)
        }
        Mode::Cfb => {
            let cfb = Cfb::new(key)?;
            cfb.encrypt(plaintext, iv)
        }
        Mode::Ofb => {
            let ofb = Ofb::new(key)?;
            ofb.encrypt(plaintext, iv)
        }
        Mode::Ctr => {
            let ctr = Ctr::new(key)?;
            ctr.encrypt(plaintext, iv)
        }
    }
}

fn decrypt_with_mode(key: &str, mode: Mode, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::Ecb => {
            let ecb = Ecb::new(key)?;
            ecb.decrypt(ciphertext, iv)
        }
        Mode::Cbc => {
            let cbc = Cbc::new(key)?;
            cbc.decrypt(ciphertext, iv)
        }
        Mode::Cfb => {
            let cfb = Cfb::new(key)?;
            cfb.decrypt(ciphertext, iv)
        }
        Mode::Ofb => {
            let ofb = Ofb::new(key)?;
            ofb.decrypt(ciphertext, iv)
        }
        Mode::Ctr => {
            let ctr = Ctr::new(key)?;
            ctr.decrypt(ciphertext, iv)
        }
    }
}