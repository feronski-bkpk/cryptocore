use cryptocore::hash::HashType;
use cryptocore::mac::HMAC;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_hmac_rfc_4231_case_1() {
    // Test Case 1 from RFC 4231
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(); // 20 bytes of 0x0b
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 1 failed");
}

#[test]
fn test_hmac_rfc_4231_case_2() {
    // Test Case 2 from RFC 4231
    let key = b"Jefe"; // "Jefe" as bytes
    let data = b"what do ya want for nothing?";
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    let hmac = HMAC::new(key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 2 failed");
}

#[test]
fn test_hmac_rfc_4231_case_3() {
    // Test Case 3 from RFC 4231
    let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(); // 20 bytes of 0xaa
    let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap(); // 50 bytes of 0xdd
    let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(&data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 3 failed");
}

#[test]
fn test_hmac_key_shorter_than_block() {
    // Key shorter than block size (64 bytes)
    let key = hex::decode("00112233445566778899aabbccddeeff").unwrap(); // 16 bytes
    let data = b"Test message for short key";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    // Just ensure it computes without error and produces a valid hash
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hmac_key_longer_than_block() {
    // Key longer than block size (64 bytes)
    let key = vec![0x42u8; 100]; // 100 bytes
    let data = b"Test message for long key";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    // Just ensure it computes without error and produces a valid hash
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hmac_empty_message() {
    let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let data = b"";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hmac_file_processing() {
    let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let test_data = b"Hello, this is a test file for HMAC!";

    // Create temporary file
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(test_data).unwrap();

    let hmac = HMAC::new(&key, HashType::Sha256);

    // Compute HMAC from file
    let file_result = hmac.compute_file(file.path()).unwrap();

    // Compute HMAC directly from data
    let direct_result = hmac.compute(test_data).unwrap();

    // They should be equal
    assert_eq!(file_result, direct_result);
}

#[test]
fn test_hmac_tamper_detection() {
    let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let original_data = b"Original message";
    let tampered_data = b"Tampered message";

    let hmac = HMAC::new(&key, HashType::Sha256);

    let original_hmac = hmac.compute(original_data).unwrap();
    let tampered_hmac = hmac.compute(tampered_data).unwrap();

    // HMAC should be different for different messages
    assert_ne!(original_hmac, tampered_hmac);
}

#[test]
fn test_hmac_different_keys() {
    let data = b"Same message";
    let key1 = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let key2 = hex::decode("ffeeddccbbaa99887766554433221100").unwrap();

    let hmac1 = HMAC::new(&key1, HashType::Sha256);
    let hmac2 = HMAC::new(&key2, HashType::Sha256);

    let result1 = hmac1.compute(data).unwrap();
    let result2 = hmac2.compute(data).unwrap();

    // HMAC should be different for different keys
    assert_ne!(result1, result2);
}