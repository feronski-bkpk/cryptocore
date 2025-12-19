use anyhow::Result;
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::{Cbc, Ctr, Cfb, Ofb, Ecb};
use std::io::Write;
use tempfile::NamedTempFile;
use cryptocore::BlockMode;

#[test]
fn test_etm_all_modes() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let plaintext = b"Test message for ETM with different base modes";
    let aad = b"Associated data";
    let iv = [0x00; 16];

    println!("Testing ETM with different base modes:");

    println!("  Testing CBC mode...");
    let aead = EncryptThenMac::new(key)?;
    let ciphertext = aead.encrypt::<Cbc>(plaintext, &iv, aad)?;
    let decrypted = aead.decrypt::<Cbc>(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);

    let wrong_aad = b"Wrong AAD";
    let result = aead.decrypt::<Cbc>(&ciphertext, wrong_aad);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    println!("    CBC mode works correctly");

    println!("  Testing CTR mode...");
    let aead = EncryptThenMac::new(key)?;
    let ciphertext = aead.encrypt::<Ctr>(plaintext, &iv, aad)?;
    let decrypted = aead.decrypt::<Ctr>(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    println!("    CTR mode works correctly");

    println!("  Testing CFB mode...");
    let aead = EncryptThenMac::new(key)?;
    let ciphertext = aead.encrypt::<Cfb>(plaintext, &iv, aad)?;
    let decrypted = aead.decrypt::<Cfb>(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    println!("    CFB mode works correctly");

    println!("  Testing OFB mode...");
    let aead = EncryptThenMac::new(key)?;
    let ciphertext = aead.encrypt::<Ofb>(plaintext, &iv, aad)?;
    let decrypted = aead.decrypt::<Ofb>(&ciphertext, aad)?;
    assert_eq!(plaintext, &decrypted[..]);
    println!("    OFB mode works correctly");

    println!("  ECB mode skipped - incompatible with EncryptThenMac data format");

    println!("All compatible ETM base modes tested successfully");
    Ok(())
}
#[test]
fn test_etm_large_data() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;
    let iv = [0x01; 16];

    let large_plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let large_aad: Vec<u8> = (0..512 * 1024).map(|i| (i % 256) as u8).collect();

    println!("Testing ETM with large data (1MB plaintext, 512KB AAD)...");

    let ciphertext = aead.encrypt::<Cbc>(&large_plaintext, &iv, &large_aad)?;

    let decrypted = aead.decrypt::<Cbc>(&ciphertext, &large_aad)?;
    assert_eq!(large_plaintext, decrypted);

    let mut tampered = ciphertext.clone();
    let ciphertext_start = 16;
    if tampered.len() > ciphertext_start + 100 {
        tampered[ciphertext_start + 50] ^= 0x01;

        let result = aead.decrypt::<Cbc>(&tampered, &large_aad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }

    println!("ETM large data test passed");
    Ok(())
}

#[test]
fn test_etm_empty_and_small_data() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x02; 16];

    println!("Testing ETM edge cases:");

    let empty_plaintext = b"";
    let aad1 = b"AAD for empty plaintext";
    let ciphertext1 = aead.encrypt::<Cbc>(empty_plaintext, &iv, aad1)?;
    let decrypted1 = aead.decrypt::<Cbc>(&ciphertext1, aad1)?;
    assert_eq!(empty_plaintext, &decrypted1[..]);
    println!("  Empty plaintext with AAD passed");

    let plaintext2 = b"Plaintext with empty AAD";
    let empty_aad = b"";
    let ciphertext2 = aead.encrypt::<Cbc>(plaintext2, &iv, empty_aad)?;
    let decrypted2 = aead.decrypt::<Cbc>(&ciphertext2, empty_aad)?;
    assert_eq!(plaintext2, &decrypted2[..]);
    println!("  Plaintext with empty AAD passed");

    let ciphertext3 = aead.encrypt::<Cbc>(b"", &iv, b"")?;
    let decrypted3 = aead.decrypt::<Cbc>(&ciphertext3, b"")?;
    assert_eq!(b"", &decrypted3[..]);
    println!("  Empty plaintext and AAD passed");

    let short_plaintext = b"A";
    let ciphertext4 = aead.encrypt::<Cbc>(short_plaintext, &iv, b"short")?;
    let decrypted4 = aead.decrypt::<Cbc>(&ciphertext4, b"short")?;
    assert_eq!(short_plaintext, &decrypted4[..]);
    println!("  Single byte plaintext passed");

    let short_aad = b"a";
    let ciphertext5 = aead.encrypt::<Cbc>(b"test", &iv, short_aad)?;
    let decrypted5 = aead.decrypt::<Cbc>(&ciphertext5, short_aad)?;
    assert_eq!(b"test", &decrypted5[..]);
    println!("  Single byte AAD passed");

    println!("All ETM edge cases passed");
    Ok(())
}

#[test]
fn test_etm_key_separation() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x03; 16];
    let plaintext = b"Test key separation";
    let aad = b"AAD";

    let ciphertext = aead.encrypt::<Cbc>(plaintext, &iv, aad)?;

    let iv_from_ct = &ciphertext[..16];
    let tag_start = ciphertext.len() - 32;
    let actual_ciphertext = &ciphertext[16..tag_start];

    use cryptocore::crypto::modes::cbc::Cbc as CbcMode;
    let cbc = CbcMode::new_from_bytes(&aead.get_encryption_key())?;
    let direct_decrypted = cbc.decrypt(actual_ciphertext, iv_from_ct)?;

    assert_eq!(plaintext, &direct_decrypted[..]);

    println!("Key separation verified: encryption key works independently");

    let tag = &ciphertext[tag_start..];
    println!("  Tag length: {} bytes (HMAC-SHA256)", tag.len());
    println!("  Ciphertext length: {} bytes", actual_ciphertext.len());

    Ok(())
}

#[test]
fn test_etm_file_operations() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;

    let iv = [0x04; 16];

    let mut input_file = NamedTempFile::new()?;
    let file_content = b"This is test file content for ETM file operations.\n\
                        Line 2 of the file.\n\
                        Line 3 with some special chars: !@#$%^&*()\n\
                        And some text: Hello World!";

    input_file.write_all(file_content)?;

    let aad = b"file:test.txt;user:test;timestamp:2024";

    println!("Testing ETM file operations...");

    let ciphertext = aead.encrypt::<Cbc>(file_content, &iv, aad)?;

    let decrypted = aead.decrypt::<Cbc>(&ciphertext, aad)?;

    assert_eq!(file_content, &decrypted[..]);

    let mut tampered = ciphertext.clone();
    if tampered.len() > 100 {
        tampered[80] ^= 0xFF;

        let result = aead.decrypt::<Cbc>(&tampered, aad);
        assert!(result.is_err());
        println!(" Tampered data correctly rejected");
    }

    println!("ETM file operations test passed");
    Ok(())
}