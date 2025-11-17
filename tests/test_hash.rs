use cryptocore::hash::{HashType};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_sha256_known_vectors() {
    let sha256 = HashType::Sha256.create_hasher();

    let test_cases = [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ),
    ];

    for (input, expected) in test_cases {
        let hash = sha256.hash_data(input.as_bytes()).unwrap();
        assert_eq!(hash, expected, "Failed for input: '{}'", input);
    }
}

#[test]
fn test_sha3_256_known_vectors() {
    let sha3_256 = HashType::Sha3_256.create_hasher();

    let test_cases = [
        (
            "",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ),
        (
            "abc",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        ),
    ];

    for (input, expected) in test_cases {
        let hash = sha3_256.hash_data(input.as_bytes()).unwrap();
        assert_eq!(hash, expected, "Failed for input: '{}'", input);
    }
}

#[test]
fn test_hash_file() {
    let sha256 = HashType::Sha256.create_hasher();

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"Hello, CryptoCore!").unwrap();

    let hash = sha256.hash_file(file.path()).unwrap();

    let computed_hash = sha256.hash_data(b"Hello, CryptoCore!").unwrap();
    assert_eq!(hash, computed_hash);
}

#[test]
fn test_avalanche_effect() {
    let sha256 = HashType::Sha256.create_hasher();

    let original_data = b"Hello, world!";
    let modified_data = b"Hello, world?";

    let hash1 = sha256.hash_data(original_data).unwrap();
    let hash2 = sha256.hash_data(modified_data).unwrap();

    let bin1 = hex_to_binary(&hash1);
    let bin2 = hex_to_binary(&hash2);

    let diff_count = bin1.chars().zip(bin2.chars())
        .filter(|(a, b)| a != b)
        .count();

    println!("Bits changed: {}/256", diff_count);
    assert!(diff_count > 100 && diff_count < 156,
            "Avalanche effect weak: only {} bits changed", diff_count);
}

fn hex_to_binary(hex: &str) -> String {
    hex.chars()
        .map(|c| {
            let val = u8::from_str_radix(&c.to_string(), 16).unwrap();
            format!("{:04b}", val)
        })
        .collect()
}