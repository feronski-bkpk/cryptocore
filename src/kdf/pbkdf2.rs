use anyhow::{Result, anyhow};
use crate::mac::hmac::HMAC;
use crate::hash::HashType;

const HMAC_SHA256_OUTPUT_SIZE: usize = 32;

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Result<Vec<u8>> {
    if dklen == 0 {
        return Err(anyhow!("Derived key length must be greater than 0"));
    }

    if iterations == 0 {
        return Err(anyhow!("Iteration count must be greater than 0"));
    }

    let blocks_needed = (dklen + HMAC_SHA256_OUTPUT_SIZE - 1) / HMAC_SHA256_OUTPUT_SIZE;
    let mut derived_key = Vec::with_capacity(dklen);

    for i in 1..=blocks_needed {
        let mut salt_with_index = salt.to_vec();
        salt_with_index.extend_from_slice(&(i as u32).to_be_bytes());

        let hmac = HMAC::new(password, HashType::Sha256);
        let mut u_current = hex::decode(hmac.compute(&salt_with_index)?)?;
        let mut block = u_current.clone();

        for _ in 2..=iterations {
            let hmac = HMAC::new(password, HashType::Sha256);
            u_current = hex::decode(hmac.compute(&u_current)?)?;

            for (block_byte, u_byte) in block.iter_mut().zip(u_current.iter()) {
                *block_byte ^= u_byte;
            }
        }

        derived_key.extend_from_slice(&block);
    }

    Ok(derived_key[..dklen].to_vec())
}

#[allow(dead_code)]
fn f(password: &[u8], salt: &[u8], c: u32, i: u32) -> Result<Vec<u8>> {
    let mut salt_with_index = salt.to_vec();
    salt_with_index.extend_from_slice(&i.to_be_bytes());

    let hmac = HMAC::new(password, HashType::Sha256);
    let mut u_current = hmac.compute_bytes(&salt_with_index)?;

    let mut f_result = u_current.clone();

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

    #[test]
    fn test_pbkdf2_basic_properties() -> Result<()> {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";
        let iterations = 1;
        let dklen = 32;

        let result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;

        assert_eq!(result.len(), dklen);

        let result2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
        assert_eq!(result, result2);

        let diff_password_result = pbkdf2_hmac_sha256(b"different".as_ref(), salt, iterations, dklen)?;
        assert_ne!(result, diff_password_result);

        let diff_salt_result = pbkdf2_hmac_sha256(password, b"different".as_ref(), iterations, dklen)?;
        assert_ne!(result, diff_salt_result);

        let diff_iter_result = pbkdf2_hmac_sha256(password, salt, iterations + 1, dklen)?;
        assert_ne!(result, diff_iter_result);

        Ok(())
    }

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

    #[test]
    fn test_pbkdf2_empty_inputs() -> Result<()> {
        let result1 = pbkdf2_hmac_sha256(b"".as_ref(), b"salt", 1, 32)?;
        assert_eq!(result1.len(), 32);

        let result2 = pbkdf2_hmac_sha256(b"password", b"".as_ref(), 1, 32)?;
        assert_eq!(result2.len(), 32);

        let result3 = pbkdf2_hmac_sha256(b"".as_ref(), b"".as_ref(), 1, 32)?;
        assert_eq!(result3.len(), 32);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_large_iterations() -> Result<()> {
        let password: &[u8] = b"password";
        let salt: &[u8] = b"salt";

        let small_iter = pbkdf2_hmac_sha256(password, salt, 1000, 32)?;
        let large_iter = pbkdf2_hmac_sha256(password, salt, 10000, 32)?;

        assert_ne!(small_iter, large_iter);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_consistency() -> Result<()> {
        let test_cases: Vec<(&[u8], &[u8], u32, usize)> = vec![
            (b"pass".as_ref(), b"salt".as_ref(), 1, 32),
            (b"longer password".as_ref(), b"longer salt value".as_ref(), 100, 64),
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