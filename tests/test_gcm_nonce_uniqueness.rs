use cryptocore::crypto::Gcm;
use std::collections::HashSet;

#[test]
fn test_gcm_nonce_uniqueness_1000() {
    println!("Generating 1000 nonces...");

    let mut nonces = HashSet::new();
    let mut collisions = 0;

    for i in 0..1000 {
        let nonce = Gcm::generate_nonce();

        if !nonces.insert(nonce) {
            collisions += 1;
            println!("⚠️ Collision detected at iteration {}", i);
        }

        if i % 100 == 0 {
            println!("  Generated {} nonces...", i);
        }
    }

    let unique_count = nonces.len();
    println!("\n=== Nonce Generation Test Results ===");
    println!("Total generated: 1000");
    println!("Unique nonces: {}", unique_count);
    println!("Collisions: {}", collisions);

    assert_eq!(unique_count, 1000,
               "Expected 1000 unique nonces, got {} (collisions: {})",
               unique_count, collisions);

    test_nonce_quality(&nonces);

    println!("All 1000 nonces are unique!");
}

fn test_nonce_quality(nonces: &HashSet<[u8; 12]>) {
    println!("\n=== Nonce Quality Analysis ===");

    let mut bit_counts = [0u32; 12 * 8];

    for nonce in nonces {
        for (byte_idx, &byte) in nonce.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    bit_counts[byte_idx * 8 + bit] += 1;
                }
            }
        }
    }

    let total_nonces = nonces.len() as f64;
    let mut bit_balance_report = String::new();

    for (bit_idx, &count) in bit_counts.iter().enumerate() {
        let percentage = (count as f64 / total_nonces) * 100.0;

        if percentage < 40.0 || percentage > 60.0 {
            bit_balance_report.push_str(&format!(
                "  Bit {}: {:.2}% ones (outside 40-60% range)\n",
                bit_idx, percentage
            ));
        }
    }

    if bit_balance_report.is_empty() {
        println!("All bits are well-balanced (40-60% ones)");
    } else {
        println!("Some bits show imbalance:\n{}", bit_balance_report);
    }

    let mut byte_patterns = std::collections::HashMap::new();
    for nonce in nonces {
        for window in nonce.windows(2) {
            *byte_patterns.entry((window[0], window[1])).or_insert(0) += 1;
        }
    }

    let avg_repetitions: f64 = byte_patterns.values().sum::<usize>() as f64 / byte_patterns.len() as f64;
    let expected_avg = total_nonces * 2.0 / 256.0;

    println!("Byte pattern analysis:");
    println!("  Unique byte pairs: {}", byte_patterns.len());
    println!("  Average repetitions per pair: {:.2}", avg_repetitions);
    println!("  Expected for random data: {:.2}", expected_avg);

    if (avg_repetitions - expected_avg).abs() < expected_avg * 0.5 {
        println!("✅ Byte patterns look random");
    } else {
        println!("⚠️ Byte patterns might not be random enough");
    }

    let mut sequential_count = 0;
    for nonce in nonces {
        for window in nonce.windows(2) {
            if window[1] == window[0].wrapping_add(1) {
                sequential_count += 1;
                break;
            }
        }
    }

    let sequential_percentage = (sequential_count as f64 / total_nonces) * 100.0;
    println!("Sequential bytes check:");
    println!("  Nonces with sequential bytes: {} ({:.2}%)", sequential_count, sequential_percentage);

    if sequential_percentage < 10.0 {
        println!("Sequential bytes are within expected range");
    } else {
        println!("Too many nonces have sequential bytes");
    }
}

#[test]
fn test_gcm_nonce_randomness_statistical() {
    println!("\n=== Statistical Randomness Test ===");

    let sample_size = 100;
    let mut nonces = Vec::with_capacity(sample_size);

    for _ in 0..sample_size {
        nonces.push(Gcm::generate_nonce());
    }

    let mut byte_counts = [0u32; 256];
    for nonce in &nonces {
        for &byte in nonce {
            byte_counts[byte as usize] += 1;
        }
    }

    let total_bytes = sample_size * 12;
    let expected_per_byte = total_bytes as f64 / 256.0;

    println!("Byte frequency test:");
    println!("  Total bytes analyzed: {}", total_bytes);
    println!("  Expected count per byte value: {:.2}", expected_per_byte);

    let max_deviation = byte_counts.iter()
        .map(|&count| (count as f64 - expected_per_byte).abs())
        .fold(0.0f64, f64::max);

    let max_deviation_percent = (max_deviation / expected_per_byte) * 100.0;
    println!("  Maximum deviation: {:.2} ({:.1}%)", max_deviation, max_deviation_percent);

    if max_deviation_percent < 100.0 {
        println!("Byte frequencies look random");
    } else {
        println!("Byte frequencies show significant deviation");
    }

    println!("\nAutocorrelation test (lag=1):");
    let mut autocorrelation_sum = 0.0;
    let mut pairs_count = 0;

    for nonce in &nonces {
        for window in nonce.windows(2) {
            let diff = window[1] as i32 - window[0] as i32;
            autocorrelation_sum += (diff * diff) as f64;
            pairs_count += 1;
        }
    }

    let avg_squared_diff = autocorrelation_sum / pairs_count as f64;
    let expected_avg_diff = 8192.0;
    let diff_ratio = avg_squared_diff / expected_avg_diff;

    println!("  Average squared difference between consecutive bytes: {:.2}", avg_squared_diff);
    println!("  Expected for random data: {:.2}", expected_avg_diff);
    println!("  Ratio: {:.3}", diff_ratio);

    if diff_ratio > 0.5 && diff_ratio < 1.5 {
        println!("Autocorrelation looks random");
    } else {
        println!("Autocorrelation might indicate non-randomness");
    }
}

#[test]
fn test_gcm_nonce_immediate_regeneration() {
    println!("\n=== Immediate Nonce Regeneration Test ===");

    let mut previous_nonce = Gcm::generate_nonce();
    let mut changes = 0;
    let test_runs = 100;

    for i in 0..test_runs {
        let current_nonce = Gcm::generate_nonce();

        let bytes_changed = previous_nonce.iter()
            .zip(current_nonce.iter())
            .filter(|(a, b)| a != b)
            .count();

        if bytes_changed > 0 {
            changes += 1;
        }

        assert_ne!(previous_nonce, current_nonce,
                   "Nonce at iteration {} is identical to previous!", i);

        previous_nonce = current_nonce;
    }

    let change_percentage = (changes as f64 / test_runs as f64) * 100.0;
    println!("Nonces changed in {} of {} runs ({:.1}%)", changes, test_runs, change_percentage);

    assert_eq!(changes, test_runs,
               "Expected all nonces to differ from previous, but {} were identical",
               test_runs - changes);

    println!("All rapid-regeneration nonces are unique");
}