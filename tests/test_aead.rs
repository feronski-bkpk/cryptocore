use anyhow::Result;
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::Cbc;

#[test]
fn test_encrypt_then_mac_basic() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x00; 16];
    let plaintext = b"Test message for Encrypt-then-MAC";
    let aad_bytes = b"Associated data";

    let encrypted = aead.encrypt::<Cbc>(plaintext, &iv, aad_bytes)?;
    let decrypted = aead.decrypt::<Cbc>(&encrypted, aad_bytes)?;

    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}

#[test]
fn test_encrypt_then_mac_auth_failure() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x00; 16];
    let plaintext = b"Secret message";
    let correct_aad = b"Correct AAD";
    let wrong_aad = b"Wrong AAD";

    let encrypted = aead.encrypt::<Cbc>(plaintext, &iv, correct_aad)?;

    let result = aead.decrypt::<Cbc>(&encrypted, wrong_aad);
    assert!(result.is_err());

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Authentication failed") ||
                error_msg.contains("MAC mismatch"),
            "Should be authentication error, got: {}", error_msg);

    Ok(())
}

#[test]
fn test_encrypt_then_mac_tampered_ciphertext() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x00; 16];
    let plaintext = b"Important data";
    let aad_bytes = b"Metadata";

    let mut encrypted = aead.encrypt::<Cbc>(plaintext, &iv, aad_bytes)?;

    if encrypted.len() > 50 {
        encrypted[30] ^= 0xFF;
    }

    let result = aead.decrypt::<Cbc>(&encrypted, aad_bytes);
    assert!(result.is_err());

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Authentication failed") ||
                error_msg.contains("MAC mismatch"),
            "Should be authentication error, got: {}", error_msg);

    Ok(())
}

#[test]
fn test_encrypt_then_mac_empty_data() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x00; 16];

    let empty_plaintext = b"";
    let aad_bytes = b"AAD";

    let encrypted = aead.encrypt::<Cbc>(empty_plaintext, &iv, aad_bytes)?;
    let decrypted = aead.decrypt::<Cbc>(&encrypted, aad_bytes)?;

    assert_eq!(empty_plaintext, &decrypted[..]);

    let plaintext = b"Some data";
    let empty_aad = b"";

    let encrypted = aead.encrypt::<Cbc>(plaintext, &iv, empty_aad)?;
    let decrypted = aead.decrypt::<Cbc>(&encrypted, empty_aad)?;

    assert_eq!(plaintext, &decrypted[..]);

    let encrypted = aead.encrypt::<Cbc>(b"", &iv, b"")?;
    let decrypted = aead.decrypt::<Cbc>(&encrypted, b"")?;

    assert_eq!(b"", &decrypted[..]);

    Ok(())
}

#[test]
fn test_encrypt_then_mac_key_separation() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead1 = EncryptThenMac::new(key)?;
    let aead2 = EncryptThenMac::new(key)?;

    assert_eq!(aead1.get_encryption_key(), aead2.get_encryption_key());
    assert_eq!(aead1.get_mac_key(), aead2.get_mac_key());

    let iv = [0x01; 16];
    let plaintext = b"Test deterministic key derivation";
    let aad_bytes = b"AAD";

    let encrypted1 = aead1.encrypt::<Cbc>(plaintext, &iv, aad_bytes)?;
    let encrypted2 = aead2.encrypt::<Cbc>(plaintext, &iv, aad_bytes)?;

    assert_eq!(encrypted1, encrypted2);

    Ok(())
}