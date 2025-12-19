use anyhow::Result;
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::{Gcm, Cbc, Ctr, Cfb, Ofb, Ecb};
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;
use hex;

fn test_gcm_case(description: &str, plaintext: &[u8], aad_hex: &str) -> Result<()> {
    println!("\nTesting: {}", description);

    let key = "00112233445566778899aabbccddeeff";
    let aad = hex::decode(aad_hex)?;

    let mut plaintext_file = NamedTempFile::new()?;
    plaintext_file.write_all(plaintext)?;

    let mut ciphertext_file = NamedTempFile::new()?;
    let _decrypted_file = NamedTempFile::new()?;

    let gcm = Gcm::new(key)?;
    let nonce = Gcm::generate_nonce();

    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, &aad)?;

    ciphertext_file.write_all(&ciphertext)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, &aad)?;

    assert_eq!(plaintext, &decrypted[..], "GCM decryption failed for: {}", description);

    let wrong_aad = if aad.is_empty() {
        vec![0x01]
    } else {
        aad.iter().map(|b| b ^ 0xFF).collect()
    };

    let wrong_result = gcm.decrypt_with_aad(&ciphertext, &wrong_aad);
    assert!(wrong_result.is_err(), "GCM should fail with wrong AAD for: {}", description);
    assert!(wrong_result.unwrap_err().to_string().contains("Authentication failed"));

    println!("  GCM test passed");
    Ok(())
}

fn test_etm_case(description: &str, base_mode: &str, plaintext: &[u8], aad_hex: &str) -> Result<()> {
    println!("\nTesting ETM with {} base mode: {}", base_mode, description);

    let key = "00112233445566778899aabbccddeeff";
    let aad = hex::decode(aad_hex)?;
    let iv = [0x00; 16];

    let mut plaintext_file = NamedTempFile::new()?;
    plaintext_file.write_all(plaintext)?;

    let mut ciphertext_file = NamedTempFile::new()?;
    let _decrypted_file = NamedTempFile::new()?;

    let aead = EncryptThenMac::new(key)?;

    let ciphertext = match base_mode {
        "CBC" => aead.encrypt::<Cbc>(plaintext, &iv, &aad)?,
        "CTR" => aead.encrypt::<Ctr>(plaintext, &iv, &aad)?,
        "CFB" => aead.encrypt::<Cfb>(plaintext, &iv, &aad)?,
        "OFB" => aead.encrypt::<Ofb>(plaintext, &iv, &aad)?,
        "ECB" => aead.encrypt::<Ecb>(plaintext, &[], &aad)?,
        _ => return Err(anyhow::anyhow!("Unknown base mode: {}", base_mode)),
    };

    ciphertext_file.write_all(&ciphertext)?;

    let decrypted = match base_mode {
        "CBC" => aead.decrypt::<Cbc>(&ciphertext, &aad)?,
        "CTR" => aead.decrypt::<Ctr>(&ciphertext, &aad)?,
        "CFB" => aead.decrypt::<Cfb>(&ciphertext, &aad)?,
        "OFB" => aead.decrypt::<Ofb>(&ciphertext, &aad)?,
        "ECB" => aead.decrypt::<Ecb>(&ciphertext, &aad)?,
        _ => return Err(anyhow::anyhow!("Unknown base mode: {}", base_mode)),
    };

    assert_eq!(plaintext, &decrypted[..], "ETM decryption failed for {} with base mode {}", description, base_mode);

    let wrong_aad = if aad.is_empty() {
        vec![0x01]
    } else {
        aad.iter().map(|b| b ^ 0xFF).collect()
    };

    let wrong_result = match base_mode {
        "CBC" => aead.decrypt::<Cbc>(&ciphertext, &wrong_aad),
        "CTR" => aead.decrypt::<Ctr>(&ciphertext, &wrong_aad),
        "CFB" => aead.decrypt::<Cfb>(&ciphertext, &wrong_aad),
        "OFB" => aead.decrypt::<Ofb>(&ciphertext, &wrong_aad),
        "ECB" => aead.decrypt::<Ecb>(&ciphertext, &wrong_aad),
        _ => return Err(anyhow::anyhow!("Unknown base mode: {}", base_mode)),
    };

    assert!(wrong_result.is_err(), "ETM should fail with wrong AAD for {} with base mode {}", description, base_mode);
    assert!(wrong_result.unwrap_err().to_string().contains("Authentication failed"));

    let mut tampered_ciphertext = ciphertext.clone();
    if tampered_ciphertext.len() > 50 {
        tampered_ciphertext[30] ^= 0x01;

        let tampered_result = match base_mode {
            "CBC" => aead.decrypt::<Cbc>(&tampered_ciphertext, &aad),
            "CTR" => aead.decrypt::<Ctr>(&tampered_ciphertext, &aad),
            "CFB" => aead.decrypt::<Cfb>(&tampered_ciphertext, &aad),
            "OFB" => aead.decrypt::<Ofb>(&tampered_ciphertext, &aad),
            "ECB" => aead.decrypt::<Ecb>(&tampered_ciphertext, &aad),
            _ => return Err(anyhow::anyhow!("Unknown base mode: {}", base_mode)),
        };

        assert!(tampered_result.is_err(), "ETM should fail with tampered ciphertext for {} with base mode {}", description, base_mode);
    }

    println!("  ETM test passed with {} base mode", base_mode);
    Ok(())
}

#[test]
fn test_gcm_integration() -> Result<()> {
    println!("=== GCM Integration Test ===");

    let test_cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("Short message", "", b"Hello GCM!".to_vec()),
        ("Empty plaintext", "aabbcc", b"".to_vec()),
        ("Message with AAD", "deadbeefcafe1234", b"Secret message with AAD".to_vec()),
        ("Longer message", "001122334455", b"This is a longer test message for GCM mode integration testing.".to_vec()),
    ];

    for (description, aad_hex, plaintext) in test_cases {
        test_gcm_case(description, &plaintext, aad_hex)?;
    }

    println!("\nAll GCM integration tests passed!");
    Ok(())
}

#[test]
fn test_aead_catastrophic_failure() -> Result<()> {
    println!("=== AEAD Catastrophic Failure Test ===");

    let key = "00112233445566778899aabbccddeeff";
    let plaintext = b"Secret message that should not be revealed";
    let correct_aad = hex::decode("aabbccddeeff")?;
    let wrong_aad = hex::decode("deadbeefcafe")?;

    println!("Testing GCM catastrophic failure...");
    {
        let gcm = Gcm::new(key)?;
        let nonce = Gcm::generate_nonce();

        let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, &correct_aad)?;

        let result = gcm.decrypt_with_aad(&ciphertext, &wrong_aad);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Authentication failed") || error_msg.contains("tag mismatch"));

        println!("  GCM correctly rejects wrong AAD");
    }

    println!("Testing ETM catastrophic failure...");
    {
        let aead = EncryptThenMac::new(key)?;
        let iv = [0x00; 16];

        let ciphertext = aead.encrypt::<Cbc>(plaintext, &iv, &correct_aad)?;

        let result = aead.decrypt::<Cbc>(&ciphertext, &wrong_aad);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Authentication failed") || error_msg.contains("MAC mismatch"));

        println!("  ETM correctly rejects wrong AAD");
    }

    println!("All catastrophic failure tests passed!");
    Ok(())
}

#[test]
fn test_aead_file_operations() -> Result<()> {
    println!("=== AEAD File Operations Test ===");

    let key = "00112233445566778899aabbccddeeff";
    let aad_hex = "aabbccddeeff001122334455";

    let mut test_file = NamedTempFile::new()?;
    let file_content = b"Test file for AEAD operations.\n\
                        This file contains multiple lines.\n\
                        Line 3: Some special characters: !@#$%^&*()\n\
                        Line 4: Binary data: \x00\x01\x02\x03\xFF\xFE\xFD";

    test_file.write_all(file_content)?;
    let test_path = test_file.path();

    println!("Testing with file: {:?}", test_path);

    println!("Testing GCM file operations...");
    {
        let gcm = Gcm::new(key)?;
        let nonce = Gcm::generate_nonce();
        let aad = hex::decode(aad_hex)?;

        let file_data = fs::read(test_path)?;

        let encrypted = gcm.encrypt_with_aad(&file_data, &nonce, &aad)?;

        let mut encrypted_file = NamedTempFile::new()?;
        encrypted_file.write_all(&encrypted)?;

        let decrypted = gcm.decrypt_with_aad(&encrypted, &aad)?;

        assert_eq!(file_data, decrypted, "GCM file decryption failed");
        println!("  GCM file operations passed");
    }

    println!("Testing ETM file operations...");
    {
        let aead = EncryptThenMac::new(key)?;
        let iv = [0x00; 16];
        let aad = hex::decode(aad_hex)?;

        let file_data = fs::read(test_path)?;

        let encrypted = aead.encrypt::<Cbc>(&file_data, &iv, &aad)?;

        let mut encrypted_file = NamedTempFile::new()?;
        encrypted_file.write_all(&encrypted)?;

        let decrypted = aead.decrypt::<Cbc>(&encrypted, &aad)?;

        assert_eq!(file_data, decrypted, "ETM file decryption failed");
        println!("  ETM file operations passed");
    }

    println!("All file operations tests passed!");
    Ok(())
}