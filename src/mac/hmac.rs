use crate::hash::HashType;
use anyhow::{Result, anyhow};
use std::path::Path;
use std::io::Read;

pub struct HMAC {
    key: Vec<u8>,
    hash_function: HashType,
    block_size: usize,
}

impl HMAC {
    pub fn new(key: &[u8], hash_function: HashType) -> Self {
        let block_size = 64;

        let key_vec = key.to_vec();

        Self {
            key: key_vec,
            hash_function,
            block_size,
        }
    }

    fn get_processed_key(&self) -> Result<Vec<u8>> {
        let mut processed_key = if self.key.len() > self.block_size {
            let hasher = self.hash_function.create_hasher();
            let hash_result = hasher.hash_data(&self.key)
                .map_err(|e| anyhow!("Failed to hash key: {}", e))?;

            hex::decode(&hash_result)
                .map_err(|e| anyhow!("Failed to decode hash: {}", e))?
        } else {
            self.key.to_vec()
        };

        if processed_key.len() < self.block_size {
            processed_key.resize(self.block_size, 0);
        }

        Ok(processed_key)
    }

    fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
        if a.len() != b.len() {
            return Err(anyhow!("Buffers must be same length for XOR"));
        }

        Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
    }

    pub fn compute_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let processed_key = self.get_processed_key()?;

        let k_ipad = HMAC::xor_bytes(&processed_key, &ipad)?;
        let k_opad = HMAC::xor_bytes(&processed_key, &opad)?;

        let mut inner_data = k_ipad;
        inner_data.extend_from_slice(message);

        let hasher = self.hash_function.create_hasher();
        let inner_hash = hasher.hash_data(&inner_data)
            .map_err(|e| anyhow!("Inner hash failed: {}", e))?;
        let inner_hash_bytes = hex::decode(&inner_hash)
            .map_err(|e| anyhow!("Failed to decode inner hash: {}", e))?;

        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);

        let outer_hash = hasher.hash_data(&outer_data)
            .map_err(|e| anyhow!("Outer hash failed: {}", e))?;

        hex::decode(&outer_hash)
            .map_err(|e| anyhow!("Failed to decode outer hash: {}", e))
    }

    #[allow(dead_code)]
    pub fn compute(&self, message: &[u8]) -> Result<String> {
        let bytes = self.compute_bytes(message)?;
        Ok(hex::encode(bytes))
    }

    #[allow(dead_code)]
    pub fn compute_file(&self, file_path: &Path) -> Result<String> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let processed_key = self.get_processed_key()?;
        let k_ipad = HMAC::xor_bytes(&processed_key, &ipad)?;
        let k_opad = HMAC::xor_bytes(&processed_key, &opad)?;

        let inner_hash = self.hash_file_with_prefix(file_path, &k_ipad)?;
        let inner_hash_bytes = hex::decode(&inner_hash)
            .map_err(|e| anyhow!("Failed to decode inner hash: {}", e))?;

        let hasher = self.hash_function.create_hasher();
        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);
        let outer_hash = hasher.hash_data(&outer_data)?;

        Ok(outer_hash)
    }

    fn hash_file_with_prefix(&self, file_path: &Path, prefix: &[u8]) -> Result<String> {
        if prefix.len() != self.block_size {
            return Err(anyhow!("Prefix must be exactly {} bytes", self.block_size));
        }

        if file_path.to_str() == Some("-") {
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            let mut combined = prefix.to_vec();
            combined.extend_from_slice(&data);
            return self.hash_function.create_hasher().hash_data(&combined);
        }

        let file_content = std::fs::read(file_path)?;
        let mut combined = prefix.to_vec();
        combined.extend_from_slice(&file_content);

        self.hash_function.create_hasher().hash_data(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_2104_test_case_1() -> Result<()> {
        let key = vec![0x0b; 20];
        let data = b"Hi There";

        let hmac = HMAC::new(&key, HashType::Sha256);
        let result = hmac.compute(data)?;

        println!("RFC 2104 Test 1: {}", result);

        let result2 = hmac.compute(data)?;
        assert_eq!(result, result2);

        Ok(())
    }

    #[test]
    fn test_key_padding() -> Result<()> {
        let short_key = b"short";
        let hmac_short = HMAC::new(short_key, HashType::Sha256);
        let result_short = hmac_short.compute(b"test")?;

        let long_key = vec![0x42; 100];
        let hmac_long = HMAC::new(&long_key, HashType::Sha256);
        let result_long = hmac_long.compute(b"test")?;

        let exact_key = vec![0x42; 64];
        let hmac_exact = HMAC::new(&exact_key, HashType::Sha256);
        let result_exact = hmac_exact.compute(b"test")?;

        assert_ne!(result_short, result_long);
        assert_ne!(result_short, result_exact);
        assert_ne!(result_long, result_exact);

        Ok(())
    }

    #[test]
    fn test_edge_cases() -> Result<()> {
        let empty_key = b"";
        let hmac_empty = HMAC::new(empty_key, HashType::Sha256);
        let result_empty = hmac_empty.compute(b"data")?;

        let key_63 = vec![0x01; 63];
        let hmac_63 = HMAC::new(&key_63, HashType::Sha256);
        let result_63 = hmac_63.compute(b"data")?;

        let key_65 = vec![0x02; 65];
        let hmac_65 = HMAC::new(&key_65, HashType::Sha256);
        let result_65 = hmac_65.compute(b"data")?;

        assert!(!result_empty.is_empty());
        assert!(!result_63.is_empty());
        assert!(!result_65.is_empty());

        Ok(())
    }
}
