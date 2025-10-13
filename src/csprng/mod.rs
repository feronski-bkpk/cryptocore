use anyhow::{Result, anyhow};
use openssl::rand::rand_bytes;

/// Cryptographically Secure Pseudorandom Number Generator
pub struct Csprng;

impl Csprng {
    /// Generates cryptographically secure random bytes
    pub fn generate_random_bytes(num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; num_bytes];
        rand_bytes(&mut buffer)
            .map_err(|e| anyhow!("CSPRNG failure: {}", e))?;
        Ok(buffer)
    }

    /// Generates a 16-byte AES key
    pub fn generate_key() -> Result<[u8; 16]> {
        let bytes = Self::generate_random_bytes(16)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Generates a 16-byte IV
    pub fn generate_iv() -> Result<[u8; 16]> {
        Self::generate_key() // IV тоже 16 байт
    }

    /// Generates a large amount of random data for statistical testing
    /// Эта функция используется в тестах NIST, поэтому оставляем её
    #[allow(dead_code)]
    pub fn generate_large_random_data(size_bytes: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(size_bytes);
        let chunk_size = 4096.min(size_bytes);

        let mut remaining = size_bytes;
        while remaining > 0 {
            let current_chunk_size = chunk_size.min(remaining);
            let chunk = Self::generate_random_bytes(current_chunk_size)?;
            data.extend_from_slice(&chunk);
            remaining -= current_chunk_size;
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = Csprng::generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_generate_key() {
        let key1 = Csprng::generate_key().unwrap();
        let key2 = Csprng::generate_key().unwrap();
        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 16);
        assert_ne!(key1, key2); // Keys should be different
    }

    #[test]
    fn test_generate_iv() {
        let iv1 = Csprng::generate_iv().unwrap();
        let iv2 = Csprng::generate_iv().unwrap();
        assert_eq!(iv1.len(), 16);
        assert_eq!(iv2.len(), 16);
        assert_ne!(iv1, iv2); // IVs should be different
    }

    #[test]
    fn test_generate_large_data() {
        let data = Csprng::generate_large_random_data(1024).unwrap();
        assert_eq!(data.len(), 1024);
    }
}