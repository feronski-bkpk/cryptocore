use anyhow::Result;
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::{Cbc};

#[test]
fn test_encrypt_then_mac_basic() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;
    let cbc = Cbc::new(key)?;

    let iv = [0x00; 16];
    let plaintext = b"Test message for Encrypt-then-MAC";
    let aad_bytes = b"Associated data";

    let encrypted = aead.encrypt(&cbc, plaintext, &iv, aad_bytes)?;
    let decrypted = aead.decrypt(&cbc, &encrypted, aad_bytes)?;

    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}

#[test]
fn test_encrypt_then_mac_auth_failure() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;
    let cbc = Cbc::new(key)?;

    let iv = [0x00; 16];
    let plaintext = b"Secret message";
    let correct_aad = b"Correct AAD";
    let wrong_aad = b"Wrong AAD";

    let encrypted = aead.encrypt(&cbc, plaintext, &iv, correct_aad)?;

    let result = aead.decrypt(&cbc, &encrypted, wrong_aad);
    assert!(result.is_err());

    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Authentication failed") ||
                error_msg.contains("MAC mismatch"),
            "Should be authentication error, got: {}", error_msg);

    Ok(())
}