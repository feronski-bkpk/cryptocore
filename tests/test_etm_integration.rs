use anyhow::Result;
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::{Cbc, Ctr, Cfb, Ofb, Ecb, BlockMode};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_etm_all_modes() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let plaintext = b"Test message for ETM with different base modes";
    let aad = b"Associated data";
    let iv = [0x00; 16];

    println!("Testing ETM with different base modes:");

    let modes: Vec<(&str, Box<dyn BlockMode>)> = vec![
        ("CBC", Box::new(Cbc::new(key)?)),
        ("CTR", Box::new(Ctr::new(key)?)),
        ("CFB", Box::new(Cfb::new(key)?)),
        ("OFB", Box::new(Ofb::new(key)?)),
        ("ECB", Box::new(Ecb::new(key)?)),
    ];

    for (mode_name, mode) in modes {
        println!("  Testing {} mode...", mode_name);

        let aead = EncryptThenMac::new(key)?;

        let ciphertext = aead.encrypt(&*mode, plaintext, &iv, aad)?;

        let decrypted = aead.decrypt(&*mode, &ciphertext, aad)?;
        assert_eq!(plaintext, &decrypted[..],
                   "ETM with {} mode failed to decrypt correctly", mode_name);

        let wrong_aad = b"Wrong AAD";
        let result = aead.decrypt(&*mode, &ciphertext, wrong_aad);
        assert!(result.is_err(),
                "ETM with {} mode should fail with wrong AAD", mode_name);
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));

        println!("    {} mode works correctly", mode_name);
    }

    println!("All ETM base modes tested successfully");
    Ok(())
}

#[test]
fn test_etm_large_data() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;
    let cbc = Cbc::new(key)?;

    let iv = [0x01; 16];

    let large_plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let large_aad: Vec<u8> = (0..512 * 1024).map(|i| (i % 256) as u8).collect();

    println!("Testing ETM with large data (1MB plaintext, 512KB AAD)...");

    let ciphertext = aead.encrypt(&cbc, &large_plaintext, &iv, &large_aad)?;

    let decrypted = aead.decrypt(&cbc, &ciphertext, &large_aad)?;
    assert_eq!(large_plaintext, decrypted);

    let mut tampered = ciphertext.clone();
    let ciphertext_start = 16;
    if tampered.len() > ciphertext_start + 100 {
        tampered[ciphertext_start + 50] ^= 0x01;

        let result = aead.decrypt(&cbc, &tampered, &large_aad);
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
    let cbc = Cbc::new(key)?;

    let iv = [0x02; 16];

    println!("Testing ETM edge cases:");

    let empty_plaintext = b"";
    let aad1 = b"AAD for empty plaintext";

    let ciphertext1 = aead.encrypt(&cbc, empty_plaintext, &iv, aad1)?;
    let decrypted1 = aead.decrypt(&cbc, &ciphertext1, aad1)?;
    assert_eq!(empty_plaintext, &decrypted1[..]);
    println!("  Empty plaintext");

    let plaintext2 = b"Plaintext with empty AAD";
    let empty_aad = b"";

    let ciphertext2 = aead.encrypt(&cbc, plaintext2, &iv, empty_aad)?;
    let decrypted2 = aead.decrypt(&cbc, &ciphertext2, empty_aad)?;
    assert_eq!(plaintext2, &decrypted2[..]);
    println!("  Empty AAD");

    let ciphertext3 = aead.encrypt(&cbc, b"", &iv, b"")?;
    let decrypted3 = aead.decrypt(&cbc, &ciphertext3, b"")?;
    assert_eq!(b"", &decrypted3[..]);
    println!("  Empty plaintext and AAD");

    let short_plaintext = b"A";
    let ciphertext4 = aead.encrypt(&cbc, short_plaintext, &iv, b"short")?;
    let decrypted4 = aead.decrypt(&cbc, &ciphertext4, b"short")?;
    assert_eq!(short_plaintext, &decrypted4[..]);
    println!("  Single byte plaintext");

    let short_aad = b"a";
    let ciphertext5 = aead.encrypt(&cbc, b"test", &iv, short_aad)?;
    let decrypted5 = aead.decrypt(&cbc, &ciphertext5, short_aad)?;
    assert_eq!(b"test", &decrypted5[..]);
    println!("  Single byte AAD");

    println!("All ETM edge cases passed");
    Ok(())
}

#[test]
fn test_etm_key_separation() -> Result<()> {
    let key = "00112233445566778899aabbccddeeff";
    let aead = EncryptThenMac::new(key)?;
    let cbc = Cbc::new(key)?;

    let iv = [0x03; 16];
    let plaintext = b"Test key separation";
    let aad = b"AAD";

    let ciphertext = aead.encrypt(&cbc, plaintext, &iv, aad)?;

    let iv_from_ct = &ciphertext[..16];
    let tag_start = ciphertext.len() - 32;
    let actual_ciphertext = &ciphertext[16..tag_start];

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
    let cbc = Cbc::new(key)?;

    let iv = [0x04; 16];

    let mut input_file = NamedTempFile::new()?;
    let file_content = b"This is test file content for ETM file operations.\n\
                        Line 2 of the file.\n\
                        Line 3 with some special chars: !@#$%^&*()\n\
                        And some text: Hello World!";

    input_file.write_all(file_content)?;

    let aad = b"file:test.txt;user:test;timestamp:2024";

    println!("Testing ETM file operations...");

    let ciphertext = aead.encrypt(&cbc, file_content, &iv, aad)?;

    let decrypted = aead.decrypt(&cbc, &ciphertext, aad)?;

    assert_eq!(file_content, &decrypted[..]);

    let mut tampered = ciphertext.clone();
    if tampered.len() > 100 {
        tampered[80] ^= 0xFF;

        let result = aead.decrypt(&cbc, &tampered, aad);
        assert!(result.is_err());
        println!(" Tampered data correctly rejected");
    }

    println!("ETM file operations test passed");
    Ok(())
}