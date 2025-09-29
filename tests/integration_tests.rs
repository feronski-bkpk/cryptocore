use std::process::Command;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_encrypt_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let key = "00112233445566778899aabbccddeeff";
    let test_content = "Hello, CryptoCore Integration Test!";
    
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
    
    let encrypt_status = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "encrypt",
            "--key", key,
            "--input", input_file.path().to_str().unwrap(),
            "--output", encrypted_file.path().to_str().unwrap(),
        ])
        .status()?;

    if !encrypt_status.success() {
        return Err("Encryption failed".into());
    }
    
    let decrypt_status = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "decrypt",
            "--key", key,
            "--input", encrypted_file.path().to_str().unwrap(),
            "--output", decrypted_file.path().to_str().unwrap(),
        ])
        .status()?;

    if !decrypt_status.success() {
        return Err("Decryption failed".into());
    }
    
    let decrypted_content = fs::read_to_string(decrypted_file.path())?;
    assert_eq!(test_content, decrypted_content);

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
    
    let output = Command::new("./target/debug/cryptocore")
        .args([
            "--algorithm", "aes",
            "--mode", "ecb",
            "--operation", "encrypt",
            "--key", "invalid_key_123", // Слишком короткий ключ
            "--input", "test.txt",
            "--output", "test.enc",
        ])
        .output()?;
    
    assert!(!output.status.success());

    Ok(())
}