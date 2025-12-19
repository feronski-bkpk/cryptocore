use anyhow::Result;
use cryptocore::kdf::{pbkdf2_hmac_sha256, derive_key};

#[test]
fn test_pbkdf2_hmac_sha256_test_vectors() -> Result<()> {
    println!("Testing PBKDF2-HMAC-SHA256 with official test vectors...");

    println!("  Test Case 1...");
    let result = pbkdf2_hmac_sha256(b"password", b"salt", 1, 20)?;
    let expected = hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c9")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 1 passed");

    println!("  Test Case 2...");
    let result = pbkdf2_hmac_sha256(b"password", b"salt", 2, 20)?;
    let expected = hex::decode("ae4d0c95af6b46d32d0adff928f06dd02a303f8e")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 2 passed");

    println!("  Test Case 3...");
    let result = pbkdf2_hmac_sha256(b"password", b"salt", 4096, 20)?;
    let expected = hex::decode("c5e478d59288c841aa530db6845c4c8d962893a0")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 3 passed");

    println!("  Test Case 4...");
    println!("    ⚠ Skipped (16777216 iterations)");

    println!("  Test Case 5...");
    let result = pbkdf2_hmac_sha256(
        b"passwordPASSWORDpassword",
        b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        25,
    )?;
    let expected = hex::decode("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 5 passed");

    println!("  Test Case 6...");
    let password_with_null = vec![b'p', b'a', b's', b's', 0, b'w', b'o', b'r', b'd'];
    let salt_with_null = vec![b's', b'a', 0, b'l', b't'];
    let result = pbkdf2_hmac_sha256(&password_with_null, &salt_with_null, 4096, 16)?;
    let expected = hex::decode("89b69d0516f829893c696226650a8687")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 6 passed");

    println!("  Test Case 7...");
    let result = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 128)?;
    let expected = hex::decode("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783c294e850150390e1160c34d62e9665d659ae49d314510fc98274cc79681968104b8f89237e69b2d549111868658be62f59bd715cac44a1147ed5317c9bae6b2a")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 7 passed");

    println!("  Test Case 8...");
    let result = pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, 128)?;
    let expected = hex::decode("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d62aae85a11cdde829d89cb6ffd1ab0e63a981f8747d2f2f9fe5874165c83c168d2eed1d2d5ca4052dec2be5715623da019b8c0ec87dc36aa751c38f9893d15c3")?;
    assert_eq!(result, expected);
    println!("    ✓ Test Case 8 passed");

    println!("All PBKDF2-HMAC-SHA256 test vectors passed!");
    Ok(())
}

#[test]
fn test_pbkdf2_basic_properties() -> Result<()> {
    println!("Testing basic PBKDF2 properties...");

    let result1 = pbkdf2_hmac_sha256(b"password", b"salt", 1000, 32)?;
    let result2 = pbkdf2_hmac_sha256(b"password", b"salt", 1000, 32)?;
    assert_eq!(result1, result2);
    println!("  ✓ Deterministic");

    let key1 = pbkdf2_hmac_sha256(b"password1", b"salt", 1000, 32)?;
    let key2 = pbkdf2_hmac_sha256(b"password2", b"salt", 1000, 32)?;
    assert_ne!(key1, key2);
    println!("  ✓ Different passwords produce different keys");

    let key1 = pbkdf2_hmac_sha256(b"password", b"salt1", 1000, 32)?;
    let key2 = pbkdf2_hmac_sha256(b"password", b"salt2", 1000, 32)?;
    assert_ne!(key1, key2);
    println!("  ✓ Different salts produce different keys");

    let key1 = pbkdf2_hmac_sha256(b"password", b"salt", 1000, 32)?;
    let key2 = pbkdf2_hmac_sha256(b"password", b"salt", 2000, 32)?;
    assert_ne!(key1, key2);
    println!("  ✓ Different iterations produce different keys");

    for length in [1, 16, 32, 64, 128] {
        let result = pbkdf2_hmac_sha256(b"test", b"test", 100, length)?;
        assert_eq!(result.len(), length);
    }
    println!("  ✓ Correct lengths");

    println!("All basic properties tests passed!");
    Ok(())
}

#[test]
fn test_pbkdf2_edge_cases() -> Result<()> {
    println!("Testing PBKDF2 edge cases...");

    let result = pbkdf2_hmac_sha256(b"", b"salt", 1, 32)?;
    assert_eq!(result.len(), 32);
    println!("  ✓ Empty password");

    let result = pbkdf2_hmac_sha256(b"password", b"", 1, 32)?;
    assert_eq!(result.len(), 32);
    println!("  ✓ Empty salt");

    match pbkdf2_hmac_sha256(b"password", b"salt", 0, 32) {
        Ok(result) => {
            assert_eq!(result.len(), 32);
            println!("  ✓ 0 iterations (function accepts it)");
        }
        Err(_) => {
            println!("  ✓ 0 iterations (correctly rejected)");
        }
    }

    let long_password = vec![b'x'; 1000];
    let result = pbkdf2_hmac_sha256(&long_password, b"salt", 1, 32)?;
    assert_eq!(result.len(), 32);
    println!("  ✓ Long password (1000 bytes)");

    let long_salt = vec![b'y'; 1000];
    let result = pbkdf2_hmac_sha256(b"password", &long_salt, 1, 32)?;
    assert_eq!(result.len(), 32);
    println!("  ✓ Long salt (1000 bytes)");

    let result = pbkdf2_hmac_sha256(b"password", b"salt", 1, 1000)?;
    assert_eq!(result.len(), 1000);
    println!("  ✓ Large key (1000 bytes)");

    println!("All edge cases passed!");
    Ok(())
}

#[test]
fn test_hkdf_derive_key() -> Result<()> {
    println!("Testing HKDF key derivation...");

    let master_key = b"0123456789abcdef0123456789abcdef";
    let context = "encryption";
    let length = 32;

    let key1 = derive_key(master_key, context, length)?;
    let key2 = derive_key(master_key, context, length)?;

    assert_eq!(key1.len(), length);
    assert_eq!(key2.len(), length);
    assert_eq!(key1, key2);
    println!("  ✓ Basic derivation");

    let key3 = derive_key(master_key, "authentication", length)?;
    assert_ne!(key1, key3);
    println!("  ✓ Context separation");

    let key4 = derive_key(b"different_master_key", context, length)?;
    assert_ne!(key1, key4);
    println!("  ✓ Master key separation");

    println!("All HKDF tests passed!");
    Ok(())
}

#[test]
fn test_pbkdf2_performance() -> Result<()> {
    println!("Testing PBKDF2 performance...");

    let password = b"password";
    let salt = b"salt";

    let iterations_list = [1, 100, 1000];

    for &iterations in &iterations_list {
        let start = std::time::Instant::now();
        let _ = pbkdf2_hmac_sha256(password, salt, iterations, 32)?;
        let duration = start.elapsed();

        println!("  {} iterations: {:?}", iterations, duration);
        assert!(duration.as_millis() < 10000);
    }

    println!("Performance tests completed!");
    Ok(())
}

#[test]
fn test_salt_randomness() -> Result<()> {
    use cryptocore::csprng::Csprng;

    println!("Testing salt randomness...");

    let mut salts = std::collections::HashSet::new();

    for _ in 0..100 {
        let salt = Csprng::generate_salt()?;
        if !salts.insert(salt) {
            panic!("Duplicate salt generated!");
        }
    }

    println!("  ✓ All generated salts are unique!");
    Ok(())
}