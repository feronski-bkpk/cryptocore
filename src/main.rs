use clap::Parser;
use anyhow::Result;

mod cli;
mod crypto;
mod file;

use crate::cli::{Cli, Operation, Mode};
use crate::crypto::{BlockMode, Cbc, Cfb, Ofb, Ctr, Ecb};
use crate::file::{read_file, write_file, generate_iv, extract_iv_from_file, prepend_iv_to_data};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = cli.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let output_path = cli.get_output_path();
    let input_data = read_file(&cli.input)?;

    let output_data = match (cli.operation, cli.mode) {
        (Operation::Encrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&cli.key)?;
            ecb.encrypt(&input_data, &[])?
        }
        (Operation::Decrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&cli.key)?;
            ecb.decrypt(&input_data, &[])?
        }
        
        (Operation::Encrypt, mode) => {
            let iv = generate_iv();
            let ciphertext = encrypt_with_mode(&cli.key, mode, &input_data, &iv)?;
            prepend_iv_to_data(&iv, &ciphertext)
        }

        (Operation::Decrypt, mode) => {
            match mode {
                Mode::Ecb => {
                    println!("DEBUG: ECB decryption, no IV needed");
                    decrypt_with_mode(&cli.key, mode, &input_data, &[])?
                }
                _ => {
                    if let Some(iv_hex) = &cli.iv {
                        println!("DEBUG: Using provided IV: {}", iv_hex);
                        let iv_bytes = hex::decode(iv_hex.trim_start_matches('@'))?;
                        let mut iv = [0u8; 16];
                        iv.copy_from_slice(&iv_bytes);
                        decrypt_with_mode(&cli.key, mode, &input_data, &iv)?
                    } else {
                        println!("DEBUG: Reading IV from file, file size: {}", input_data.len());
                        let (iv, ciphertext) = extract_iv_from_file(&input_data)?;
                        println!("DEBUG: Extracted IV, ciphertext size: {}", ciphertext.len());
                        decrypt_with_mode(&cli.key, mode, ciphertext, &iv)?
                    }
                }
            }
        }
    };

    write_file(&output_path, &output_data)?;

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