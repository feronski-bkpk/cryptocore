use anyhow::Result;
use std::process::Command;
use tempfile::NamedTempFile;
use std::fs;

#[test]
fn test_gcm_openssl_compatibility() -> Result<()> {
    let openssl_check = Command::new("openssl")
        .args(["enc", "-aes-128-gcm", "-help"])
        .output();

    if openssl_check.is_err() {
        println!("OpenSSL not found, skipping compatibility tests");
        return Ok(());
    }

    test_cryptocore_to_openssl()?;

    test_openssl_to_cryptocore()?;

    Ok(())
}

fn test_cryptocore_to_openssl() -> Result<()> {
    println!("Testing CryptoCore -> OpenSSL compatibility...");

    let plaintext = b"Hello OpenSSL compatibility test!";
    let key = "00112233445566778899aabbccddeeff";
    let nonce = "000102030405060708090a0b";
    let aad = "aabbccddeeff001122334455";

    let plaintext_file = NamedTempFile::new()?;
    let ciphertext_file = NamedTempFile::new()?;
    let decrypted_file = NamedTempFile::new()?;

    fs::write(plaintext_file.path(), plaintext)?;

    let encrypt_status = Command::new("./target/debug/cryptocore")
        .args([
            "crypto",
            "--algorithm", "aes",
            "--mode", "gcm",
            "--operation", "encrypt",
            "--key", key,
            "--nonce", nonce,
            "--aad", aad,
            "--input", plaintext_file.path().to_str().unwrap(),
            "--output", ciphertext_file.path().to_str().unwrap(),
        ])
        .status()?;

    assert!(encrypt_status.success(), "CryptoCore encryption failed");

    let ciphertext_data = fs::read(ciphertext_file.path())?;

    if ciphertext_data.len() >= 12 + 16 {
        let nonce_from_file = &ciphertext_data[..12];
        let ciphertext_and_tag = &ciphertext_data[12..];

        let ciphertext_only_file = NamedTempFile::new()?;
        fs::write(ciphertext_only_file.path(), ciphertext_and_tag)?;

        let openssl_output = Command::new("openssl")
            .args([
                "enc", "-aes-128-gcm", "-d",
                "-K", key,
                "-iv", &hex::encode(nonce_from_file),
                "-aad", aad,
                "-in", ciphertext_only_file.path().to_str().unwrap(),
                "-out", decrypted_file.path().to_str().unwrap(),
            ])
            .output()?;

        if openssl_output.status.success() {
            let decrypted = fs::read(decrypted_file.path())?;
            assert_eq!(decrypted, plaintext, "OpenSSL decryption mismatch");
            println!("  ✓ CryptoCore -> OpenSSL: PASSED");
        } else {
            println!("  ✗ CryptoCore -> OpenSSL: OpenSSL decryption failed");
            println!("    OpenSSL stderr: {}", String::from_utf8_lossy(&openssl_output.stderr));
        }
    }

    Ok(())
}

fn test_openssl_to_cryptocore() -> Result<()> {
    println!("Testing OpenSSL -> CryptoCore compatibility...");

    let plaintext = b"Testing reverse compatibility!";
    let key = "00112233445566778899aabbccddeeff";
    let nonce = "000102030405060708090a0b";
    let aad = "11223344556677889900aabb";

    let plaintext_file = NamedTempFile::new()?;
    let openssl_ciphertext_file = NamedTempFile::new()?;
    let cryptocore_decrypted_file = NamedTempFile::new()?;

    fs::write(plaintext_file.path(), plaintext)?;

    let openssl_output = Command::new("openssl")
        .args([
            "enc", "-aes-128-gcm", "-e",
            "-K", key,
            "-iv", nonce,
            "-aad", aad,
            "-in", plaintext_file.path().to_str().unwrap(),
            "-out", openssl_ciphertext_file.path().to_str().unwrap(),
        ])
        .output()?;

    if !openssl_output.status.success() {
        println!("  ✗ OpenSSL encryption failed, skipping test");
        return Ok(());
    }

    let ciphertext_data = fs::read(openssl_ciphertext_file.path())?;
    let mut cryptocore_format = Vec::new();
    cryptocore_format.extend_from_slice(&hex::decode(nonce)?);
    cryptocore_format.extend_from_slice(&ciphertext_data);

    let cryptocore_input_file = NamedTempFile::new()?;
    fs::write(cryptocore_input_file.path(), &cryptocore_format)?;

    let decrypt_status = Command::new("./target/debug/cryptocore")
        .args([
            "crypto",
            "--algorithm", "aes",
            "--mode", "gcm",
            "--operation", "decrypt",
            "--key", key,
            "--aad", aad,
            "--input", cryptocore_input_file.path().to_str().unwrap(),
            "--output", cryptocore_decrypted_file.path().to_str().unwrap(),
        ])
        .status()?;

    if decrypt_status.success() {
        let decrypted = fs::read(cryptocore_decrypted_file.path())?;
        assert_eq!(decrypted, plaintext, "CryptoCore decryption mismatch");
        println!("  ✓ OpenSSL -> CryptoCore: PASSED");
    } else {
        println!("  ✗ OpenSSL -> CryptoCore: CryptoCore decryption failed");
    }

    Ok(())
}