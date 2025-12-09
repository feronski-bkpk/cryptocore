use cryptocore::hash::HashType;
use cryptocore::mac::hmac;
use std::io::Write;
use tempfile::NamedTempFile;
use crate::hmac::HMAC;

#[test]
fn test_hmac_rfc_4231_case_1() {
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(); // 20 bytes of 0x0b
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 1 failed");
}

#[test]
fn test_hmac_rfc_4231_case_2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    let hmac = HMAC::new(key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 2 failed");
}

#[test]
fn test_hmac_rfc_4231_case_3() {
    let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
    let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(&data).unwrap();

    assert_eq!(result, expected, "RFC 4231 Test Case 3 failed");
}

#[test]
fn test_hmac_key_shorter_than_block() {
    let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let data = b"Test message for short key";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_hmac_key_longer_than_block() {
    let key = vec![0x42u8; 100];
    let data = b"Test message for long key";

    let hmac = HMAC::new(&key, HashType::Sha256);
    let result = hmac.compute(data).unwrap();

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

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(test_data).unwrap();

    let hmac = HMAC::new(&key, HashType::Sha256);

    let file_result = hmac.compute_file(file.path()).unwrap();

    let direct_result = hmac.compute(test_data).unwrap();

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

    assert_ne!(result1, result2);
}