//! Password-Based Key Derivation Function 2 (PBKDF2) implementation.
//!
//! PBKDF2 applies a pseudorandom function (HMAC) to the input password
//! along with a salt value and repeats the process many times to produce
//! a derived key.
//!
//! # Algorithm
//!
//! PBKDF2 is defined in RFC 2898 as:
//!
//! DK = PBKDF2(PRF, Password, Salt, c, dkLen)
//!
//! where:
//! - `PRF` is pseudorandom function (HMAC-SHA256 in this implementation)
//! - `Password` is the master password
//! - `Salt` is a cryptographic salt
//! - `c` is iteration count
//! - `dkLen` is desired length of derived key
//!
//! # Security Properties
//!
//! - Resists brute-force attacks through high iteration counts
//! - Salt prevents rainbow table attacks
//! - Iteration count should be as high as performance allows (≥100,000)
//!
//! # Warning
//!
//! Using weak passwords with PBKDF2 still results in weak keys.
//! Always use strong, randomly generated passwords.
//!
//! # References
//!
//! - RFC 2898: PKCS #5: Password-Based Cryptography Specification Version 2.0
//! - NIST SP 800-132: Recommendation for Password-Based Key Derivation

use anyhow::{anyhow, Result};

use crate::hash::HashType;
use crate::mac::hmac::HMAC;

/// Output size of HMAC-SHA256 in bytes (32 bytes = 256 bits).
const HMAC_SHA256_OUTPUT_SIZE: usize = 32;

/// Derives a cryptographic key from a password using PBKDF2-HMAC-SHA256.
///
/// # Arguments
///
/// * `password` - Password to derive key from
/// * `salt` - Cryptographic salt (should be unique for each password)
/// * `iterations` - Number of iterations (higher = more secure but slower)
/// * `dklen` - Desired length of derived key in bytes
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Derived key of length `dklen`
/// * `Err(anyhow::Error)` - If parameters are invalid or computation fails
///
/// # Examples
///
/// ```
/// use cryptocore::kdf::pbkdf2_hmac_sha256;
///
/// let password = b"my_password";
/// let salt = b"unique_salt";
/// let derived_key = pbkdf2_hmac_sha256(password, salt, 100_000, 32).unwrap();
/// assert_eq!(derived_key.len(), 32);
/// ```
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dklen: usize,
) -> Result<Vec<u8>> {
    // Validate parameters
    if dklen == 0 {
        return Err(anyhow!("Derived key length must be greater than 0"));
    }

    if iterations == 0 {
        return Err(anyhow!("Iteration count must be greater than 0"));
    }

    // Calculate number of HMAC blocks needed
    let blocks_needed = (dklen + HMAC_SHA256_OUTPUT_SIZE - 1) / HMAC_SHA256_OUTPUT_SIZE;
    let mut derived_key = Vec::with_capacity(dklen);

    // Generate each block
    for i in 1..=blocks_needed {
        // Prepare salt with block index
        let mut salt_with_index = salt.to_vec();
        salt_with_index.extend_from_slice(&(i as u32).to_be_bytes());

        // Compute U1 = HMAC(password, salt || i)
        let hmac = HMAC::new(password, HashType::Sha256);
        let mut u_current = hex::decode(hmac.compute(&salt_with_index)?)?;
        let mut block = u_current.clone();

        // Compute subsequent U values and XOR them
        for _ in 2..=iterations {
            let hmac = HMAC::new(password, HashType::Sha256);
            u_current = hex::decode(hmac.compute(&u_current)?)?;

            for (block_byte, u_byte) in block.iter_mut().zip(u_current.iter()) {
                *block_byte ^= u_byte;
            }
        }

        // Append block to derived key
        derived_key.extend_from_slice(&block);
    }

    // Truncate to requested length
    Ok(derived_key[..dklen].to_vec())
}

/// PBKDF2 F function (internal helper).
///
/// Computes a single PBKDF2 block: F(Password, Salt, c, i)
/// where c is iteration count and i is block index.
///
/// # Arguments
///
/// * `password` - Password
/// * `salt` - Salt
/// * `c` - Iteration count
/// * `i` - Block index
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - PBKDF2 block
/// * `Err(anyhow::Error)` - If computation fails
#[allow(dead_code)]
fn f(password: &[u8], salt: &[u8], c: u32, i: u32) -> Result<Vec<u8>> {
    let mut salt_with_index = salt.to_vec();
    salt_with_index.extend_from_slice(&i.to_be_bytes());

    // U1 = HMAC(password, salt || i)
    let hmac = HMAC::new(password, HashType::Sha256);
    let mut u_current = hmac.compute_bytes(&salt_with_index)?;

    let mut f_result = u_current.clone();

    // XOR subsequent U values
    for _ in 2..=c {
        let hmac = HMAC::new(password, HashType::Sha256);
        u_current = hmac.compute_bytes(&u_current)?;

        for (result_byte, u_byte) in f_result.iter_mut().zip(u_current.iter()) {
            *result_byte ^= u_byte;
        }
    }

    Ok(f_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests basic PBKDF2 properties (determinism, parameter sensitivity).
    #[test]
    fn test_pbkdf2_basic_properties() -> Result<()> {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";
        let iterations = 1;
        let dklen = 32;

        let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;

        // Check output length
        assert_eq!(result.len(), dklen);

        // Verify determinism
        let result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
        assert_eq!(result, result2);

        // Verify password sensitivity
        let diff_password_result =
            pbkdf2_hmac_sha256(b"different".as_ref(), salt, iterations, dklen)?;
        assert_ne!(result, diff_password_result);

        // Verify salt sensitivity
        let diff_salt_result =
            pbkdf2_hmac_sha256(password, b"different".as_ref(), iterations, dklen)?;
        assert_ne!(result, diff_salt_result);

        // Verify iteration sensitivity
        let diff_iter_result = pbkdf2_hmac_sha256(password, salt, iterations + 1, dklen)?;
        assert_ne!(result, diff_iter_result);

        Ok(())
    }

    /// Tests PBKDF2 with various output lengths.
    #[test]
    fn test_pbkdf2_length_variations() -> Result<()> {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";
        let iterations = 1000;

        for dklen in [1, 16, 32, 48, 64, 100] {
            let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
            assert_eq!(result.len(), dklen);
        }

        Ok(())
    }

    /// Tests PBKDF2 with empty inputs.
    #[test]
    fn test_pbkdf2_empty_inputs() -> Result<()> {
        // Empty password
        let result1 = pbkdf2_hmac_sha256(b"".as_ref(), b"salt", 1, 32)?;
        assert_eq!(result1.len(), 32);

        // Empty salt
        let result2 = pbkdf2_hmac_sha256(b"password", b"".as_ref(), 1, 32)?;
        assert_eq!(result2.len(), 32);

        // Both empty
        let result3 = pbkdf2_hmac_sha256(b"".as_ref(), b"".as_ref(), 1, 32)?;
        assert_eq!(result3.len(), 32);

        Ok(())
    }

    /// Tests that different iteration counts produce different keys.
    #[test]
    fn test_pbkdf2_large_iterations() -> Result<()> {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";

        let small_iter = pbkdf2_hmac_sha256(password, salt, 1000, 32)?;
        let large_iter = pbkdf2_hmac_sha256(password, salt, 10000, 32)?;

        assert_ne!(small_iter, large_iter);

        Ok(())
    }

    /// Tests PBKDF2 consistency across various parameter combinations.
    #[test]
    fn test_pbkdf2_consistency() -> Result<()> {
        let test_cases: Vec<(&[u8], &[u8], u32, usize)> = vec![
            (b"pass".as_ref(), b"salt".as_ref(), 1, 32),
            (
                b"longer password".as_ref(),
                b"longer salt value".as_ref(),
                100,
                64,
            ),
            (b"p".as_ref(), b"s".as_ref(), 1000, 16),
        ];

        for (password, salt, iterations, dklen) in test_cases {
            let result1 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
            let result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;

            assert_eq!(result1, result2);
            assert_eq!(result1.len(), dklen);
        }

        Ok(())
    }

    /// Helper test for OpenSSL compatibility verification.
    ///
    /// Prints OpenSSL command to verify compatibility.
    #[test]
    fn test_pbkdf2_openssl_compatibility_check() -> Result<()> {
        let password: &[u8] = b"test123";
        let salt: &[u8] = b"mysalt";
        let iterations = 10000;
        let dklen = 32;

        let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;

        println!("Для проверки совместимости с OpenSSL выполните:");
        println!("echo -n 'test123' | openssl kdf -keylen {} \\", dklen);
        println!("  -kdfopt pass:test123 \\");
        println!("  -kdfopt salt:{} \\", hex::encode(salt));
        println!("  -kdfopt iter:{} \\", iterations);
        println!("  PBKDF2");
        println!();
        println!("Ваш результат: {}", hex::encode(&result));
        println!("Результат должен совпадать с выводом OpenSSL");

        assert_eq!(result.len(), dklen);

        Ok(())
    }
}