use anyhow::Result;
use cryptocore::crypto::modes::Gcm;

#[test]
fn test_gcm_basic_encryption_decryption() -> Result<()> {
    let key = "00000000000000000000000000000000";
    let nonce = [0x00; 12];
    let plaintext = b"Hello, GCM World!";
    let aad = b"";

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;

    assert!(ciphertext.len() >= 12 + plaintext.len() + 16);

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}

#[test]
fn test_gcm_with_aad() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let nonce = [0x01; 12];
    let plaintext = b"Secret message with AAD";
    let aad = b"Additional authenticated data";

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);

    let wrong_aad = b"Wrong AAD";
    let result = gcm.decrypt_with_aad(&ciphertext, wrong_aad);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Authentication failed"));

    Ok(())
}

#[test]
fn test_gcm_empty_plaintext_with_aad() -> Result<()> {
    let key = "00000000000000000000000000000000";
    let nonce = [0x02; 12];
    let plaintext = b"";
    let aad = b"Non-empty AAD";

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;

    assert!(ciphertext.len() >= 12 + 16);

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}

#[test]
fn test_gcm_empty_aad() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let nonce = [0x03; 12];
    let plaintext = b"Message with empty AAD";
    let aad = b"";

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}

#[test]
fn test_gcm_different_nonce_produces_different_ciphertext() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let plaintext = b"Same plaintext";
    let aad = b"Same AAD";

    let gcm = Gcm::new(key)?;

    let nonce1 = [0x04; 12];
    let nonce2 = [0x05; 12];

    let ciphertext1 = gcm.encrypt_with_aad(plaintext, &nonce1, aad)?;
    let ciphertext2 = gcm.encrypt_with_aad(plaintext, &nonce2, aad)?;

    assert_ne!(ciphertext1, ciphertext2);

    Ok(())
}

#[test]
fn test_gcm_tampered_ciphertext() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let nonce = [0x06; 12];
    let plaintext = b"Important message";
    let aad = b"Authentication data";

    let gcm = Gcm::new(key)?;
    let mut ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;

    let ciphertext_start = 12;
    if ciphertext.len() > ciphertext_start + 10 {
        ciphertext[ciphertext_start + 10] ^= 0x01;

        let result = gcm.decrypt_with_aad(&ciphertext, aad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }

    Ok(())
}

#[test]
fn test_gcm_nonce_generation() {
    let nonce1 = Gcm::generate_nonce();
    let nonce2 = Gcm::generate_nonce();

    assert_ne!(nonce1, nonce2);

    assert_eq!(nonce1.len(), 12);
    assert_eq!(nonce2.len(), 12);
}

#[test]
fn test_gcm_long_aad() -> Result<()> {
    let key = "00000000000000000000000000000000";
    let nonce = [0x07; 12];
    let plaintext = b"Short message";

    let mut long_aad = Vec::new();
    for i in 0..100 {
        long_aad.push((i % 256) as u8);
    }

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, &long_aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, &long_aad)?;
    assert_eq!(plaintext, &decrypted[..]);

    Ok(())
}

#[test]
fn test_gcm_long_plaintext() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let nonce = [0x08; 12];
    let aad = b"Test AAD";

    let mut long_plaintext = Vec::new();
    for i in 0..1000 {
        long_plaintext.push((i % 256) as u8);
    }

    let gcm = Gcm::new(key)?;
    let ciphertext = gcm.encrypt_with_aad(&long_plaintext, &nonce, aad)?;

    let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
    assert_eq!(long_plaintext, decrypted);

    Ok(())
}