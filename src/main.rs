mod cli;
mod crypto;
mod csprng;
mod file;
mod hash;
mod mac;
mod kdf;

use clap::Parser;
use cli::{Cli, Command, Algorithm, Mode, Operation};
use crypto::{BlockMode, Cbc, Cfb, Ofb, Ctr, Ecb, Gcm};
use crypto::aead::EncryptThenMac;
use csprng::Csprng;
use file::{read_file, write_file, extract_iv_from_file, prepend_iv_to_data};
use hash::HashType;
use kdf::pbkdf2_hmac_sha256;
use anyhow::{Result, anyhow};
use std::path::PathBuf;
use hex;
use std::io::Read;
use crate::hash::HashAlgorithm;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = cli.validate() {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }

    match cli.command {
        Command::Crypto {
            algorithm,
            mode,
            operation,
            key,
            input,
            iv,
            nonce,
            aad,
            base_mode,
            output,
        } => {
            if algorithm != Algorithm::Aes {
                eprintln!("[ERROR] Only AES algorithm is currently supported");
                std::process::exit(1);
            }

            let output_path = output.or_else(|| {
                let default_name = match input.to_str() {
                    Some("-") => match operation {
                        Operation::Encrypt => "output.enc".to_string(),
                        Operation::Decrypt => "output.dec".to_string(),
                    },
                    Some(name) => match operation {
                        Operation::Encrypt => format!("{}.enc", name),
                        Operation::Decrypt => format!("{}.dec", name),
                    },
                    None => "output".to_string(),
                };
                Some(PathBuf::from(default_name))
            });

            match operation {
                Operation::Encrypt => handle_encryption(&mode, key, &input, output_path.as_ref(), iv, nonce, aad, base_mode)?,
                Operation::Decrypt => handle_decryption(&mode, key, &input, output_path.as_ref(), iv, nonce, aad, base_mode)?,
            }
        }
        Command::Dgst {
            algorithm,
            input,
            output,
            hmac,
            key,
            verify,
        } => {
            let hash_type = HashType::from_str(&algorithm)
                .ok_or_else(|| anyhow!("Unsupported hash algorithm: {}", algorithm))?;

            if hmac {
                handle_hmac(hash_type, key, &input, output, verify)?;
            } else {
                handle_hashing(hash_type, &input, output)?;
            }
        }
        Command::Derive { args } => {
            handle_key_derivation(args)?;
        }
    }

    Ok(())
}

fn handle_key_derivation(args: cli::DeriveArgs) -> Result<()> {
    println!("[INFO] Deriving key using PBKDF2-HMAC-SHA256");
    println!("[INFO] Password length: {} characters", args.password.len());
    println!("[INFO] Iterations: {}", args.iterations);
    println!("[INFO] Key length: {} bytes", args.length);

    let password_bytes = args.password.as_bytes();

    let salt_bytes = if let Some(salt_hex) = &args.salt {
        let salt = hex::decode(salt_hex)?;
        println!("[INFO] Using provided salt: {}", salt_hex);
        salt
    } else {
        let random_salt = Csprng::generate_salt()?;
        println!("[INFO] Generated random salt (hex): {}", hex::encode(&random_salt));
        random_salt.to_vec()
    };

    let derived_key = pbkdf2_hmac_sha256(password_bytes, &salt_bytes, args.iterations, args.length)?;
    let key_hex = hex::encode(&derived_key);

    if let Some(output_path) = &args.output {
        write_file(output_path, &derived_key)?;
        println!("[SUCCESS] Key derivation completed successfully");
        println!("[INFO] Derived key saved to: {}", output_path.display());
        println!("[INFO] Key (hex): {}", key_hex);
        println!("[INFO] Salt (hex): {}", hex::encode(salt_bytes));
    } else {
        eprintln!("[INFO] Deriving key using PBKDF2-HMAC-SHA256");
        eprintln!("[INFO] Password length: {} characters", args.password.len());
        eprintln!("[INFO] Iterations: {}", args.iterations);
        eprintln!("[INFO] Key length: {} bytes", args.length);
        if let Some(salt_hex) = &args.salt {
            eprintln!("[INFO] Using provided salt: {}", salt_hex);
        } else {
            eprintln!("[INFO] Generated random salt (hex): {}", hex::encode(&salt_bytes));
        }
        eprintln!("[SUCCESS] Key derivation completed successfully");

        println!("{} {}", key_hex, hex::encode(salt_bytes));
    }

    Ok(())
}

fn handle_encryption(
    mode: &Mode,
    key: Option<String>,
    input_path: &PathBuf,
    output_path: Option<&PathBuf>,
    iv: Option<String>,
    nonce: Option<String>,
    aad: Option<String>,
    base_mode: Option<Mode>,
) -> Result<()> {
    if iv.is_some() && *mode != Mode::Gcm && *mode != Mode::Etm {
        eprintln!("[WARNING] IV should not be provided for encryption - it will be generated automatically");
    }

    let output_path = match output_path {
        Some(path) => path.clone(),
        None => {
            let default_name = match input_path.to_str() {
                Some("-") => "output.enc".to_string(),
                Some(name) => format!("{}.enc", name),
                None => "output.enc".to_string(),
            };
            PathBuf::from(default_name)
        }
    };

    let plaintext = if input_path.to_str() == Some("-") {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        buffer
    } else {
        read_file(input_path)?
    };

    let key_hex = match key {
        Some(k) => {
            println!("[INFO] Using provided key");
            k.trim_start_matches('@').to_string()
        }
        None => {
            let random_key = Csprng::generate_key()?;
            let key_hex = hex::encode(random_key);
            println!("[INFO] Generated random key: {}", key_hex);
            println!("[INFO] Remember to save the generated key for decryption!");
            key_hex
        }
    };

    match mode {
        Mode::Ecb => {
            let ecb = Ecb::new(&key_hex)?;
            let ciphertext = ecb.encrypt(&plaintext, &[])?;
            write_file(&output_path, &ciphertext)?;
            println!("[SUCCESS] ECB encryption completed successfully");
        }
        Mode::Cbc => {
            let cbc = Cbc::new(&key_hex)?;
            let iv_bytes = Csprng::generate_iv()?;
            let ciphertext = cbc.encrypt(&plaintext, &iv_bytes)?;
            let output_data = prepend_iv_to_data(&iv_bytes, &ciphertext);
            write_file(&output_path, &output_data)?;
            println!("[SUCCESS] CBC encryption completed successfully");
            println!("[INFO] IV (hex): {}", hex::encode(iv_bytes));
        }
        Mode::Cfb => {
            let cfb = Cfb::new(&key_hex)?;
            let iv_bytes = Csprng::generate_iv()?;
            let ciphertext = cfb.encrypt(&plaintext, &iv_bytes)?;
            let output_data = prepend_iv_to_data(&iv_bytes, &ciphertext);
            write_file(&output_path, &output_data)?;
            println!("[SUCCESS] CFB encryption completed successfully");
            println!("[INFO] IV (hex): {}", hex::encode(iv_bytes));
        }
        Mode::Ofb => {
            let ofb = Ofb::new(&key_hex)?;
            let iv_bytes = Csprng::generate_iv()?;
            let ciphertext = ofb.encrypt(&plaintext, &iv_bytes)?;
            let output_data = prepend_iv_to_data(&iv_bytes, &ciphertext);
            write_file(&output_path, &output_data)?;
            println!("[SUCCESS] OFB encryption completed successfully");
            println!("[INFO] IV (hex): {}", hex::encode(iv_bytes));
        }
        Mode::Ctr => {
            let ctr = Ctr::new(&key_hex)?;
            let iv_bytes = Csprng::generate_iv()?;
            let ciphertext = ctr.encrypt(&plaintext, &iv_bytes)?;
            let output_data = prepend_iv_to_data(&iv_bytes, &ciphertext);
            write_file(&output_path, &output_data)?;
            println!("[SUCCESS] CTR encryption completed successfully");
            println!("[INFO] IV (hex): {}", hex::encode(iv_bytes));
        }
        Mode::Gcm => {
            let gcm = Gcm::new(&key_hex)?;

            let nonce_bytes = if let Some(nonce_hex) = nonce {
                let nonce_str = nonce_hex.trim_start_matches('@');
                hex::decode(nonce_str)?
            } else {
                let nonce = Gcm::generate_nonce();
                println!("[INFO] Generated random nonce (hex): {}", hex::encode(nonce));
                nonce.to_vec()
            };

            if nonce_bytes.len() != 12 {
                return Err(anyhow!("Nonce must be 12 bytes for GCM"));
            }

            let aad_bytes = if let Some(aad_hex) = aad {
                let aad_str = aad_hex.trim_start_matches('@');
                hex::decode(aad_str)?
            } else {
                Vec::new()
            };

            if !aad_bytes.is_empty() {
                println!("[INFO] AAD provided ({} bytes)", aad_bytes.len());
            }

            let ciphertext = gcm.encrypt_with_aad(&plaintext, &nonce_bytes, &aad_bytes)?;
            write_file(&output_path, &ciphertext)?;
            println!("[SUCCESS] GCM encryption completed successfully");
        }
        Mode::Etm => {
            let base_mode = base_mode.unwrap_or(Mode::Cbc);

            println!("[INFO] Using Encrypt-then-MAC mode with {:?} as base mode", base_mode);

            let aead = EncryptThenMac::new(&key_hex)?;

            let iv_bytes = if let Some(iv_hex) = iv {
                let iv_str = iv_hex.trim_start_matches('@');
                hex::decode(iv_str)?
            } else {
                Csprng::generate_iv()?.to_vec()
            };

            let aad_bytes = if let Some(aad_hex) = aad {
                let aad_str = aad_hex.trim_start_matches('@');
                hex::decode(aad_str)?
            } else {
                Vec::new()
            };

            if !aad_bytes.is_empty() {
                println!("[INFO] AAD provided ({} bytes)", aad_bytes.len());
            }

            match base_mode {
                Mode::Cbc => {
                    let ciphertext = aead.encrypt::<Cbc>(&plaintext, &iv_bytes, &aad_bytes)?;
                    write_file(&output_path, &ciphertext)?;
                }
                Mode::Ctr => {
                    let ciphertext = aead.encrypt::<Ctr>(&plaintext, &iv_bytes, &aad_bytes)?;
                    write_file(&output_path, &ciphertext)?;
                }
                Mode::Cfb => {
                    let ciphertext = aead.encrypt::<Cfb>(&plaintext, &iv_bytes, &aad_bytes)?;
                    write_file(&output_path, &ciphertext)?;
                }
                Mode::Ofb => {
                    let ciphertext = aead.encrypt::<Ofb>(&plaintext, &iv_bytes, &aad_bytes)?;
                    write_file(&output_path, &ciphertext)?;
                }
                Mode::Ecb => {
                    let ciphertext = aead.encrypt::<Ecb>(&plaintext, &[], &aad_bytes)?;
                    write_file(&output_path, &ciphertext)?;
                }
                _ => {
                    return Err(anyhow!("Invalid base mode for ETM: {:?}", base_mode));
                }
            }

            println!("[SUCCESS] ETM encryption completed successfully");
        }
    }

    println!("[INFO] Output written to: {}", output_path.display());
    Ok(())
}

fn handle_decryption(
    mode: &Mode,
    key: Option<String>,
    input_path: &PathBuf,
    output_path: Option<&PathBuf>,
    iv: Option<String>,
    _nonce: Option<String>,
    aad: Option<String>,
    base_mode: Option<Mode>,
) -> Result<()> {
    let key_hex = key.ok_or_else(|| anyhow!("Key is required for decryption"))?
        .trim_start_matches('@')
        .to_string();

    let output_path = match output_path {
        Some(path) => path.clone(),
        None => {
            let default_name = match input_path.to_str() {
                Some("-") => "output.dec".to_string(),
                Some(name) => format!("{}.dec", name),
                None => "output.dec".to_string(),
            };
            PathBuf::from(default_name)
        }
    };

    let input_data = if input_path.to_str() == Some("-") {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        buffer
    } else {
        read_file(input_path)?
    };

    match mode {
        Mode::Ecb => {
            let ecb = Ecb::new(&key_hex)?;
            let plaintext = ecb.decrypt(&input_data, &[])?;
            write_file(&output_path, &plaintext)?;
            println!("[SUCCESS] ECB decryption completed successfully");
        }
        Mode::Cbc | Mode::Cfb | Mode::Ofb | Mode::Ctr => {
            let (iv_from_file, ciphertext) = if let Some(iv_hex) = iv {
                let iv_str = iv_hex.trim_start_matches('@');
                let iv_bytes = hex::decode(iv_str)?;
                (iv_bytes, input_data)
            } else {
                if input_data.len() < 16 {
                    return Err(anyhow!("Input file too short to contain IV"));
                }
                let (iv_array, ciphertext_slice) = extract_iv_from_file(&input_data)?;
                (iv_array.to_vec(), ciphertext_slice.to_vec())
            };

            let plaintext = match mode {
                Mode::Cbc => {
                    let cbc = Cbc::new(&key_hex)?;
                    cbc.decrypt(&ciphertext, &iv_from_file)?
                }
                Mode::Cfb => {
                    let cfb = Cfb::new(&key_hex)?;
                    cfb.decrypt(&ciphertext, &iv_from_file)?
                }
                Mode::Ofb => {
                    let ofb = Ofb::new(&key_hex)?;
                    ofb.decrypt(&ciphertext, &iv_from_file)?
                }
                Mode::Ctr => {
                    let ctr = Ctr::new(&key_hex)?;
                    ctr.decrypt(&ciphertext, &iv_from_file)?
                }
                _ => unreachable!(),
            };

            write_file(&output_path, &plaintext)?;
            println!("[SUCCESS] {:?} decryption completed successfully", mode);
        }
        Mode::Gcm => {
            let gcm = Gcm::new(&key_hex)?;

            if input_data.len() < 12 + 16 {
                return Err(anyhow!("Input file too short for GCM format"));
            }

            let aad_bytes = if let Some(aad_hex) = &aad {
                let aad_str = aad_hex.trim_start_matches('@');
                hex::decode(aad_str)?
            } else {
                Vec::new()
            };

            if !aad_bytes.is_empty() {
                println!("[INFO] AAD provided ({} bytes)", aad_bytes.len());
            }

            match gcm.decrypt_with_aad(&input_data, &aad_bytes) {
                Ok(plaintext) => {
                    write_file(&output_path, &plaintext)?;
                    println!("[SUCCESS] GCM decryption completed successfully");
                }
                Err(e) => {
                    if e.to_string().contains("Authentication failed") {
                        if output_path.exists() {
                            std::fs::remove_file(&output_path)
                                .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                        }

                        eprintln!("[ERROR] Authentication failed: tag mismatch or ciphertext tampered");
                        eprintln!("[ERROR] No plaintext output will be produced");
                        std::process::exit(1);
                    } else {
                        if output_path.exists() {
                            std::fs::remove_file(&output_path)
                                .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                        }
                        return Err(e);
                    }
                }
            }
        }
        Mode::Etm => {
            let base_mode = base_mode.unwrap_or(Mode::Cbc);

            println!("[INFO] Using Encrypt-then-MAC mode with {:?} as base mode", base_mode);

            let aead = EncryptThenMac::new(&key_hex)?;

            let aad_bytes = if let Some(aad_hex) = &aad {
                let aad_str = aad_hex.trim_start_matches('@');
                hex::decode(aad_str)?
            } else {
                Vec::new()
            };

            if !aad_bytes.is_empty() {
                println!("[INFO] AAD provided ({} bytes)", aad_bytes.len());
            }

            match base_mode {
                Mode::Cbc => {
                    match aead.decrypt::<Cbc>(&input_data, &aad_bytes) {
                        Ok(plaintext) => {
                            write_file(&output_path, &plaintext)?;
                            println!("[SUCCESS] ETM decryption completed successfully");
                        }
                        Err(e) if e.to_string().contains("Authentication failed") => {
                            if output_path.exists() {
                                std::fs::remove_file(&output_path)
                                    .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                            }
                            eprintln!("[ERROR] Authentication failed: MAC mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Mode::Ctr => {
                    match aead.decrypt::<Ctr>(&input_data, &aad_bytes) {
                        Ok(plaintext) => {
                            write_file(&output_path, &plaintext)?;
                            println!("[SUCCESS] ETM decryption completed successfully");
                        }
                        Err(e) if e.to_string().contains("Authentication failed") => {
                            if output_path.exists() {
                                std::fs::remove_file(&output_path)
                                    .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                            }
                            eprintln!("[ERROR] Authentication failed: MAC mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Mode::Cfb => {
                    match aead.decrypt::<Cfb>(&input_data, &aad_bytes) {
                        Ok(plaintext) => {
                            write_file(&output_path, &plaintext)?;
                            println!("[SUCCESS] ETM decryption completed successfully");
                        }
                        Err(e) if e.to_string().contains("Authentication failed") => {
                            if output_path.exists() {
                                std::fs::remove_file(&output_path)
                                    .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                            }
                            eprintln!("[ERROR] Authentication failed: MAC mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Mode::Ofb => {
                    match aead.decrypt::<Ofb>(&input_data, &aad_bytes) {
                        Ok(plaintext) => {
                            write_file(&output_path, &plaintext)?;
                            println!("[SUCCESS] ETM decryption completed successfully");
                        }
                        Err(e) if e.to_string().contains("Authentication failed") => {
                            if output_path.exists() {
                                std::fs::remove_file(&output_path)
                                    .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                            }
                            eprintln!("[ERROR] Authentication failed: MAC mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Mode::Ecb => {
                    match aead.decrypt::<Ecb>(&input_data, &aad_bytes) {
                        Ok(plaintext) => {
                            write_file(&output_path, &plaintext)?;
                            println!("[SUCCESS] ETM decryption completed successfully");
                        }
                        Err(e) if e.to_string().contains("Authentication failed") => {
                            if output_path.exists() {
                                std::fs::remove_file(&output_path)
                                    .unwrap_or_else(|_| eprintln!("[WARNING] Failed to delete output file"));
                            }
                            eprintln!("[ERROR] Authentication failed: MAC mismatch");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                _ => {
                    return Err(anyhow!("Invalid base mode for ETM: {:?}", base_mode));
                }
            }
        }
    }

    println!("[INFO] Output written to: {}", output_path.display());
    Ok(())
}

fn handle_hashing(hash_type: HashType, input_path: &PathBuf, output: Option<PathBuf>) -> Result<()> {
    let data = if input_path.to_str() == Some("-") {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        buffer
    } else {
        read_file(input_path)?
    };

    let hash_hex = match hash_type {
        HashType::Sha256 => {
            let hasher = crate::hash::sha256::Sha256::new();
            hasher.hash_data(&data)?
        }
        HashType::Sha3_256 => {
            let hasher = crate::hash::sha3_256::Sha3_256::new();
            hasher.hash_data(&data)?
        }
    };

    if let Some(output_path) = output {
        let output_str = format!("{}  {}\n", hash_hex,
                                 if input_path.to_str() == Some("-") { "-" } else { input_path.to_str().unwrap() });
        write_file(&output_path, output_str.as_bytes())?;
        println!("[INFO] Hash saved to: {}", output_path.display());
    } else {
        println!("{}  {}", hash_hex,
                 if input_path.to_str() == Some("-") { "-" } else { input_path.to_str().unwrap() });
    }

    Ok(())
}

fn handle_hmac(
    _hash_type: HashType,
    key: Option<String>,
    input_path: &PathBuf,
    output: Option<PathBuf>,
    verify: Option<PathBuf>,
) -> Result<()> {
    let key_hex = key.ok_or_else(|| anyhow!("Key is required for HMAC"))?
        .trim_start_matches('@')
        .to_string();

    let data = if input_path.to_str() == Some("-") {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        buffer
    } else {
        read_file(input_path)?
    };

    use crate::mac::hmac::HMAC;
    let key_bytes = hex::decode(&key_hex)?;
    let hmac = HMAC::new(&key_bytes, HashType::Sha256);
    let hmac_hex = hmac.compute(&data)?;

    if let Some(verify_path) = verify {
        let expected = std::fs::read_to_string(&verify_path)?
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("Invalid verify file format"))?
            .to_string();

        if hmac_hex == expected {
            println!("[OK] HMAC verification successful");
        } else {
            eprintln!("[ERROR] HMAC verification failed");
            eprintln!("  Expected: {}", expected);
            eprintln!("  Got:      {}", hmac_hex);
            std::process::exit(1);
        }
    } else if let Some(output_path) = output {
        let output_str = format!("{}  {}\n", hmac_hex,
                                 if input_path.to_str() == Some("-") { "-" } else { input_path.to_str().unwrap() });
        write_file(&output_path, output_str.as_bytes())?;
        println!("[INFO] HMAC saved to: {}", output_path.display());
    } else {
        println!("{}  {}", hmac_hex,
                 if input_path.to_str() == Some("-") { "-" } else { input_path.to_str().unwrap() });
    }

    Ok(())
}