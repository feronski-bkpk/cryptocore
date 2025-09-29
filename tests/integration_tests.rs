use std::process::Command;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_ecb_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let key = "00112233445566778899aabbccddeeff";
    let test_content = "Hello, CryptoCore ECB Test!";

    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }

    let input_file = NamedTempFile::new()?;
    fs::write(&input_file, test_content)?;

    let encrypted_file = NamedTempFile::new()?;
    let decrypted_file = NamedTempFile::new()?;
    
    let encrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "encrypt",
            "--key", key,
            "--input", input_file.path().to_str().unwrap(),
            "--output", encrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !encrypt_output.status.success() {
        eprintln!("ECB Encryption failed: {}", String::from_utf8_lossy(&encrypt_output.stderr));
        return Err("ECB Encryption failed".into());
    }

    // Decrypt
    let decrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "decrypt",
            "--key", key,
            "--input", encrypted_file.path().to_str().unwrap(),
            "--output", decrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !decrypt_output.status.success() {
        eprintln!("ECB Decryption failed: {}", String::from_utf8_lossy(&decrypt_output.stderr));
        return Err("ECB Decryption failed".into());
    }
    
    let original_bytes = fs::read(input_file.path())?;
    let decrypted_bytes = fs::read(decrypted_file.path())?;
    assert_eq!(original_bytes, decrypted_bytes);

    Ok(())
}

#[test]
fn test_cbc_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let key = "00112233445566778899aabbccddeeff";
    let test_content = "Hello, CryptoCore CBC Test!";

    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }

    let input_file = NamedTempFile::new()?;
    fs::write(&input_file, test_content)?;

    let encrypted_file = NamedTempFile::new()?;
    let decrypted_file = NamedTempFile::new()?;
    
    let encrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "encrypt",
            "--key", key,
            "--input", input_file.path().to_str().unwrap(),
            "--output", encrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !encrypt_output.status.success() {
        eprintln!("CBC Encryption failed: {}", String::from_utf8_lossy(&encrypt_output.stderr));
        return Err("CBC Encryption failed".into());
    }
    
    let encrypted_data = fs::read(encrypted_file.path())?;
    println!("Encrypted file size: {} bytes", encrypted_data.len());
    assert!(encrypted_data.len() >= 16, "Encrypted file should contain IV, but size is {}", encrypted_data.len());
    
    let decrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "decrypt",
            "--key", key,
            "--input", encrypted_file.path().to_str().unwrap(),
            "--output", decrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !decrypt_output.status.success() {
        eprintln!("CBC Decryption failed. Stderr: {}", String::from_utf8_lossy(&decrypt_output.stderr));
        eprintln!("Stdout: {}", String::from_utf8_lossy(&decrypt_output.stdout));
        return Err("CBC Decryption failed".into());
    }

    // Compare as bytes
    let original_bytes = fs::read(input_file.path())?;
    let decrypted_bytes = fs::read(decrypted_file.path())?;
    assert_eq!(original_bytes, decrypted_bytes);

    Ok(())
}

#[test]
fn test_stream_modes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let key = "00112233445566778899aabbccddeeff";
    let test_content = "Hello, CryptoCore Stream Modes Test!";

    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }

    let modes = ["cfb", "ofb", "ctr"];

    for mode in modes {
        println!("Testing {} mode...", mode);

        let input_file = NamedTempFile::new()?;
        fs::write(&input_file, test_content)?;

        let encrypted_file = NamedTempFile::new()?;
        let decrypted_file = NamedTempFile::new()?;
        
        let encrypt_output = Command::new("./target/debug/cryptocore")
            .args([
                "--algorithm", "aes",
                "--mode", mode,
                "--operation", "encrypt",
                "--key", key,
                "--input", input_file.path().to_str().unwrap(),
                "--output", encrypted_file.path().to_str().unwrap(),
            ])
            .output()?;

        if !encrypt_output.status.success() {
            eprintln!("{} Encryption failed: {}", mode.to_uppercase(), String::from_utf8_lossy(&encrypt_output.stderr));
            return Err(format!("{} Encryption failed", mode.to_uppercase()).into());
        }
        
        let encrypted_data = fs::read(encrypted_file.path())?;
        println!("{} encrypted file size: {} bytes", mode.to_uppercase(), encrypted_data.len());
        assert!(encrypted_data.len() >= 16, "{} encrypted file should contain IV, but size is {}", mode.to_uppercase(), encrypted_data.len());
        
        let decrypt_output = Command::new("./target/debug/cryptocore")
            .args([
                "--algorithm", "aes",
                "--mode", mode,
                "--operation", "decrypt",
                "--key", key,
                "--input", encrypted_file.path().to_str().unwrap(),
                "--output", decrypted_file.path().to_str().unwrap(),
            ])
            .output()?;

        if !decrypt_output.status.success() {
            eprintln!("{} Decryption failed. Stderr: {}", mode.to_uppercase(), String::from_utf8_lossy(&decrypt_output.stderr));
            eprintln!("Stdout: {}", String::from_utf8_lossy(&decrypt_output.stdout));
            return Err(format!("{} Decryption failed", mode.to_uppercase()).into());
        }
        
        let original_bytes = fs::read(input_file.path())?;
        let decrypted_bytes = fs::read(decrypted_file.path())?;
        assert_eq!(original_bytes, decrypted_bytes, "{} mode round-trip failed", mode.to_uppercase());

        println!("{} mode test passed!", mode.to_uppercase());
    }

    Ok(())
}

#[test]
fn test_validation_errors() -> Result<(), Box<dyn std::error::Error>> {
    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }
    
    let test_file = NamedTempFile::new()?;
    fs::write(&test_file, "test content")?;
    
    let output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "encrypt",
            "--key", "invalid_key_123",
            "--input", test_file.path().to_str().unwrap(),
            "--output", "test.enc",
        ])
        .output()?;

    assert!(!output.status.success());
    
    let output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "encrypt",
            "--key", "00112233445566778899aabbccddeeff",
            "--iv", "000102030405060708090A0B0C0D0E0F",
            "--input", test_file.path().to_str().unwrap(),
            "--output", "test.enc",
        ])
        .output()?;

    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_iv_required_for_decryption() -> Result<(), Box<dyn std::error::Error>> {
    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }
    
    let test_file = NamedTempFile::new()?;
    fs::write(&test_file, "just ciphertext data without IV")?;
    
    let output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "decrypt",
            "--key", "00112233445566778899aabbccddeeff",
            "--input", test_file.path().to_str().unwrap(),
            "--output", "test.dec",
        ])
        .output()?;

    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_decryption_with_provided_iv() -> Result<(), Box<dyn std::error::Error>> {
    let key = "00112233445566778899aabbccddeeff";
    let test_content = "Test with provided IV";

    let build_status = Command::new("cargo")
        .args(["build"])
        .status()?;

    if !build_status.success() {
        return Err("Build failed".into());
    }

    let input_file = NamedTempFile::new()?;
    fs::write(&input_file, test_content)?;

    let encrypted_file = NamedTempFile::new()?;
    let decrypted_file = NamedTempFile::new()?;
    
    let encrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "encrypt",
            "--key", key,
            "--input", input_file.path().to_str().unwrap(),
            "--output", encrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !encrypt_output.status.success() {
        eprintln!("Encryption failed: {}", String::from_utf8_lossy(&encrypt_output.stderr));
        return Err("Encryption failed".into());
    }
    
    let encrypted_data = fs::read(encrypted_file.path())?;
    let actual_iv = &encrypted_data[..16];
    let actual_iv_hex = hex::encode(actual_iv);

    println!("Extracted IV: {}", actual_iv_hex);
    
    let ciphertext_only_file = NamedTempFile::new()?;
    fs::write(ciphertext_only_file.path(), &encrypted_data[16..])?;
    
    let decrypt_output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "cbc",
            "--operation", "decrypt",
            "--key", key,
            "--iv", &actual_iv_hex,
            "--input", ciphertext_only_file.path().to_str().unwrap(),
            "--output", decrypted_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !decrypt_output.status.success() {
        eprintln!("Decryption with provided IV failed: {}", String::from_utf8_lossy(&decrypt_output.stderr));
        return Err("Decryption with provided IV failed".into());
    }
    
    let original_bytes = fs::read(input_file.path())?;
    let decrypted_bytes = fs::read(decrypted_file.path())?;
    assert_eq!(original_bytes, decrypted_bytes);

    Ok(())
}