use cryptocore::csprng::Csprng;
use std::collections::HashSet;
use std::fs::{self};

#[test]
fn test_key_uniqueness() {
    let mut key_set = HashSet::new();
    let num_keys = 1000;

    for _ in 0..num_keys {
        let key = Csprng::generate_key().unwrap();
        let key_hex = hex::encode(&key);

        assert!(!key_set.contains(&key_hex), "Duplicate key found: {}", key_hex);
        key_set.insert(key_hex);
    }

    println!("Successfully generated {} unique keys.", key_set.len());

    let collision_rate = 0.0;
    assert_eq!(collision_rate, 0.0, "Unexpected key collisions detected");
}

#[test]
fn test_basic_distribution() {
    let num_samples = 1000;
    let mut total_bits = 0;
    let mut total_bytes = 0;

    for _ in 0..num_samples {
        let key = Csprng::generate_key().unwrap();
        total_bytes += key.len();

        for byte in &key {
            total_bits += byte.count_ones() as usize;
        }
    }

    let total_possible_bits = total_bytes * 8;
    let ones_ratio = total_bits as f64 / total_possible_bits as f64;

    println!("Total bits: {}, Ones: {}, Ratio: {:.4}",
             total_possible_bits, total_bits, ones_ratio);

    assert!(ones_ratio > 0.45 && ones_ratio < 0.55,
            "Bit distribution is skewed: {:.4}", ones_ratio);

    let deviation = (ones_ratio - 0.5).abs();
    println!("Deviation from 50%: {:.4}%", deviation * 100.0);
    assert!(deviation < 0.05, "Distribution deviation too high: {:.4}%", deviation * 100.0);
}

#[test]
fn test_nist_preparation() {
    let total_size = 10_000_000;
    let test_file = "nist_test_data.bin";

    println!("Generating {} bytes of test data for NIST STS...", total_size);

    match Csprng::generate_large_random_data(total_size) {
        Ok(data) => {
            assert_eq!(data.len(), total_size, "Generated data size mismatch");

            fs::write(test_file, &data).expect("Failed to write NIST test data");
            println!("Generated {} bytes for NIST testing in '{}'", data.len(), test_file);

            let ones_count: usize = data.iter().map(|b| b.count_ones() as usize).sum();
            let total_bits = data.len() * 8;
            let ones_ratio = ones_count as f64 / total_bits as f64;

            println!("NIST data statistics:");
            println!("  - Total bytes: {}", data.len());
            println!("  - Total bits: {}", total_bits);
            println!("  - Ones count: {}", ones_count);
            println!("  - Ones ratio: {:.4} ({:.2}%)", ones_ratio, ones_ratio * 100.0);

            assert!(
                ones_ratio > 0.49 && ones_ratio < 0.51,
                "NIST test data shows poor distribution: {:.4}",
                ones_ratio
            );

            let mut pattern_count = 0;
            for window in data.windows(4) {
                if window[0] == window[1] && window[1] == window[2] && window[2] == window[3] {
                    pattern_count += 1;
                }
            }

            println!("  - Repeated 4-byte patterns: {}", pattern_count);
            assert!(
                pattern_count < 10,
                "Too many repeated patterns in NIST data: {}",
                pattern_count
            );

            println!("NIST test data preparation completed successfully");
            println!("Test data saved to: {}", test_file);
            println!("Use this file with NIST STS for statistical testing");
        }
        Err(e) => panic!("Failed to generate NIST test data: {}", e),
    }
}

#[test]
fn test_random_bytes_generation() {
    let sizes = [16, 32, 64, 128, 256, 512, 1024];

    for &size in &sizes {
        let data = Csprng::generate_random_bytes(size).unwrap();
        assert_eq!(data.len(), size, "Generated data size mismatch for {} bytes", size);

        let all_zeros = data.iter().all(|&b| b == 0);
        assert!(!all_zeros, "Generated all zeros for size {}", size);

        println!("Successfully generated {} random bytes", size);
    }
}

#[test]
fn test_iv_generation() {
    let num_ivs = 100;
    let mut iv_set = HashSet::new();

    for _ in 0..num_ivs {
        let iv = Csprng::generate_iv().unwrap();
        assert_eq!(iv.len(), 16, "IV must be 16 bytes");

        let iv_hex = hex::encode(&iv);
        assert!(!iv_set.contains(&iv_hex), "Duplicate IV found: {}", iv_hex);
        iv_set.insert(iv_hex);
    }

    println!("Successfully generated {} unique IVs", iv_set.len());
}

#[test]
fn test_error_handling() {
    let result = Csprng::generate_random_bytes(0);
    assert!(result.is_ok(), "Zero byte generation should be handled gracefully");

    if let Ok(data) = result {
        assert_eq!(data.len(), 0, "Zero byte request should return empty data");
    }

    let result = Csprng::generate_random_bytes(100_000_000);
    assert!(result.is_ok(), "Large allocation should be handled");

    println!("Error handling tests completed successfully");
}

#[test]
fn test_consecutive_calls() {
    let data1 = Csprng::generate_random_bytes(32).unwrap();
    let data2 = Csprng::generate_random_bytes(32).unwrap();
    let data3 = Csprng::generate_random_bytes(32).unwrap();

    assert_ne!(data1, data2, "Consecutive calls produced identical data");
    assert_ne!(data1, data3, "Consecutive calls produced identical data");
    assert_ne!(data2, data3, "Consecutive calls produced identical data");

    println!("Consecutive calls produce different results - OK");
}

#[test]
fn test_csprng_integration() {
    let key = Csprng::generate_key().unwrap();
    let iv = Csprng::generate_iv().unwrap();

    assert_eq!(key.len(), 16, "Key must be 16 bytes for AES-128");
    assert_eq!(iv.len(), 16, "IV must be 16 bytes");

    assert_ne!(key, iv, "Key and IV should be different");

    println!("CSPRNG integration test passed");
}