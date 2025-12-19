use crate::hash::HashType;
use anyhow::Result;
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

        let mut processed_key = if key.len() > block_size {
            let hasher = hash_function.create_hasher();
            let hash_result = hasher.hash_data(key).unwrap_or_default();
            hex::decode(&hash_result).unwrap_or_else(|_| key[..block_size].to_vec())
        } else {
            key.to_vec()
        };

        if processed_key.len() < block_size {
            processed_key.resize(block_size, 0);
        }

        Self {
            key: processed_key,
            hash_function,
            block_size,
        }
    }

    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    pub fn compute_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let k_ipad = HMAC::xor_bytes(&self.key, &ipad);
        let k_opad = HMAC::xor_bytes(&self.key, &opad);

        let mut inner_data = k_ipad;
        inner_data.extend_from_slice(message);

        let hasher = self.hash_function.create_hasher();
        let inner_hash = hasher.hash_data(&inner_data)?;
        let inner_hash_bytes = hex::decode(&inner_hash)?;

        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);

        let outer_hash = hasher.hash_data(&outer_data)?;
        Ok(hex::decode(&outer_hash)?)
    }

    #[allow(dead_code)]
    pub fn compute(&self, message: &[u8]) -> Result<String> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let k_ipad = HMAC::xor_bytes(&self.key, &ipad);
        let k_opad = HMAC::xor_bytes(&self.key, &opad);

        let mut inner_data = k_ipad;
        inner_data.extend_from_slice(message);

        let hasher = self.hash_function.create_hasher();
        let inner_hash = hasher.hash_data(&inner_data)?;
        let inner_hash_bytes = hex::decode(&inner_hash)?;

        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);

        hasher.hash_data(&outer_data)
    }

    #[allow(dead_code)]
    pub fn compute_file(&self, file_path: &Path) -> Result<String> {
        let ipad = vec![0x36; self.block_size];
        let opad = vec![0x5c; self.block_size];

        let k_ipad = HMAC::xor_bytes(&self.key, &ipad);
        let k_opad = HMAC::xor_bytes(&self.key, &opad);

        let inner_hash = self.hash_file_with_prefix(file_path, &k_ipad)?;
        let inner_hash_bytes = hex::decode(&inner_hash)?;

        let hasher = self.hash_function.create_hasher();
        let mut outer_data = k_opad;
        outer_data.extend_from_slice(&inner_hash_bytes);
        let outer_hash = hasher.hash_data(&outer_data)?;

        Ok(outer_hash)
    }

    #[allow(dead_code)]
    fn hash_file_with_prefix(&self, file_path: &Path, prefix: &[u8]) -> Result<String> {
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