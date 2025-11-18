use clap::Parser;
use anyhow::Result;

mod cli;
mod crypto;
mod file;
mod csprng;
mod hash;
mod mac;

use crate::cli::parser::{Cli, Command, Operation, Mode};
use crate::crypto::{BlockMode, Cbc, Cfb, Ofb, Ctr, Ecb};
use crate::file::{read_file, write_file, extract_iv_from_file, prepend_iv_to_data};
use crate::csprng::Csprng;
use crate::hash::HashType;
use crate::mac::HMAC;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = cli.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    match &cli.command {
        Command::Crypto {
            algorithm: _,
            mode,
            operation,
            key,
            input,
            output: _,
            iv
        } => {
            handle_crypto_command(*mode, *operation, key.clone(), input.clone(), iv.clone(), &cli)
        }
        Command::Dgst {
            algorithm,
            input,
            output,
            hmac,
            key,
            verify
        } => {
            handle_dgst_command(algorithm, input.clone(), output.clone(), *hmac, key.clone(), verify.clone())
        }
    }
}

fn handle_crypto_command(
    mode: Mode,
    operation: Operation,
    key: Option<String>,
    input: std::path::PathBuf,
    iv: Option<String>,
    cli: &Cli
) -> Result<()> {
    let (key_hex, is_key_generated) = match (&operation, &key) {
        (Operation::Encrypt, None) => {
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

    let output_path = cli.get_output_path().unwrap();
    let input_data = read_file(&input)?;

    let output_data = match (operation, mode) {
        (Operation::Encrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&key_hex)?;
            ecb.encrypt(&input_data, &[])?
        }
        (Operation::Decrypt, Mode::Ecb) => {
            let ecb = Ecb::new(&key_hex)?;
            ecb.decrypt(&input_data, &[])?
        }

        (Operation::Encrypt, mode) => {
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
                    if let Some(iv_hex) = &iv {
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

fn handle_dgst_command(
    algorithm: &str,
    input: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
    hmac: bool,
    key: Option<String>,
    verify: Option<std::path::PathBuf>
) -> Result<()> {
    let hash_type = HashType::from_str(algorithm)
        .ok_or_else(|| anyhow::anyhow!("Unsupported hash algorithm: {}", algorithm))?;

    if hmac {
        let key_bytes = hex::decode(key.unwrap().trim_start_matches('@'))?;
        let hmac = HMAC::new(&key_bytes, hash_type);

        if let Some(verify_path) = verify {
            verify_hmac(&hmac, &input, &verify_path)?
        } else {
            generate_hmac(&hmac, &input, output)?
        }
    } else {
        let hasher = hash_type.create_hasher();
        let hash_value = hasher.hash_file(&input)?;

        let input_display = if input.to_str() == Some("-") {
            "-".to_string()
        } else {
            input.display().to_string()
        };

        let output_line = format!("{}  {}", hash_value, input_display);

        match output {
            Some(output_path) => {
                std::fs::write(&output_path, &output_line)?;
                println!("Hash written to: {}", output_path.display());
            }
            None => {
                println!("{}", output_line);
            }
        }
    }

    Ok(())
}

fn generate_hmac(
    hmac: &HMAC,
    input: &std::path::Path,
    output: Option<std::path::PathBuf>
) -> Result<()> {
    let hmac_value = hmac.compute_file(input)?;

    let input_display = if input.to_str() == Some("-") {
        "-".to_string()
    } else {
        input.display().to_string()
    };

    let output_line = format!("{}  {}", hmac_value, input_display);

    match output {
        Some(output_path) => {
            std::fs::write(&output_path, &output_line)?;
            println!("HMAC written to: {}", output_path.display());
        }
        None => {
            println!("{}", output_line);
        }
    }

    Ok(())
}

fn verify_hmac(
    hmac: &HMAC,
    input: &std::path::Path,
    verify_path: &std::path::Path
) -> Result<()> {
    let computed_hmac = hmac.compute_file(input)?;

    let expected_content = std::fs::read_to_string(verify_path)?;
    let expected_hmac = parse_hmac_file(&expected_content, input)
        .ok_or_else(|| anyhow::anyhow!("Invalid HMAC file format"))?;

    if computed_hmac == expected_hmac {
        println!("[OK] HMAC verification successful");
        std::process::exit(0);
    } else {
        eprintln!("[ERROR] HMAC verification failed");
        eprintln!("Expected: {}", expected_hmac);
        eprintln!("Computed: {}", computed_hmac);
        std::process::exit(1);
    }
}

fn parse_hmac_file(file_content: &str, _input_file: &std::path::Path) -> Option<String> {
    for line in file_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        for part in parts {
            if part.len() == 64 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(part.to_lowercase());
            }
        }
    }
    None
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