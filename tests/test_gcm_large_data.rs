use anyhow::Result;
use cryptocore::crypto::Gcm;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_gcm_large_aad() -> Result<()> {
    let large_aad: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    let key = "00112233445566778899aabbccddeeff";
    let plaintext = b"Small plaintext with large AAD";

    let gcm = Gcm::new(key)?;
    let nonce = [0x01; 12];

    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, &large_aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, &large_aad)?;
    assert_eq!(plaintext, &decrypted[..]);

    let wrong_aad = vec![0xFF; large_aad.len()];
    let result = gcm.decrypt_with_aad(&ciphertext, &wrong_aad);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Authentication failed"));

    println!("Large AAD test passed ({} bytes)", large_aad.len());
    Ok(())
}

#[test]
fn test_gcm_large_plaintext() -> Result<()> {
    let large_plaintext: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    let key = "00112233445566778899aabbccddeeff";
    let aad = b"Normal size AAD";

    let gcm = Gcm::new(key)?;
    let nonce = [0x02; 12];

    let ciphertext = gcm.encrypt_with_aad(&large_plaintext, &nonce, aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(large_plaintext, decrypted);

    println!("Large plaintext test passed ({} bytes)", large_plaintext.len());
    Ok(())
}

#[test]
fn test_gcm_large_aad_and_plaintext() -> Result<()> {
    let large_aad: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
    let large_plaintext: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    let key = "00112233445566778899aabbccddeeff";
    let gcm = Gcm::new(key)?;
    let nonce = [0x03; 12];

    let ciphertext = gcm.encrypt_with_aad(&large_plaintext, &nonce, &large_aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, &large_aad)?;
    assert_eq!(large_plaintext, decrypted);

    println!("Large AAD and plaintext test passed");
    println!("  AAD: {} MB, Plaintext: {} MB",
             large_aad.len() / 1024 / 1024,
             large_plaintext.len() / 1024 / 1024);
    Ok(())
}

#[test]
fn test_gcm_chunked_processing() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let gcm = Gcm::new(key)?;
    let nonce = [0x04; 12];

    let huge_aad: Vec<u8> = (0..50 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    let plaintext = b"Small message with huge AAD";
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, &huge_aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, &huge_aad)?;
    assert_eq!(plaintext, &decrypted[..]);

    println!("Chunked processing test passed (50MB AAD)");
    Ok(())
}

#[test]
fn test_gcm_file_based_large_data() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let gcm = Gcm::new(key)?;
    let nonce = [0x05; 12];

    let mut temp_file = NamedTempFile::new()?;
    let file_data: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
    temp_file.write_all(&file_data)?;

    let ciphertext = gcm.encrypt_with_aad(&file_data, &nonce, b"file_aad")?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, b"file_aad")?;
    assert_eq!(file_data, decrypted);

    println!("File-based large data test passed (10MB)");
    Ok(())
}