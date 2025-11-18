use crate::hash::HashAlgorithm;
use anyhow::Result;
use std::path::Path;
use std::fs::File;
use std::io::{Read, BufReader};
use sha3::{Digest, Sha3_256 as Sha3_256Lib};

pub struct Sha3_256;

impl Sha3_256 {
    pub fn new() -> Self {
        Self
    }
}

impl HashAlgorithm for Sha3_256 {
    fn hash_file(&self, file_path: &Path) -> Result<String> {
        if file_path.to_str() == Some("-") {
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            return self.hash_data(&data);
        }

        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha3_256Lib::new();

        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    fn hash_data(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha3_256Lib::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let sha3 = Sha3_256::new();
        let hash = sha3.hash_data(b"").unwrap();
        assert_eq!(hash, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    #[test]
    fn test_sha3_256_abc() {
        let sha3 = Sha3_256::new();
        let hash = sha3.hash_data(b"abc").unwrap();
        assert_eq!(hash, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }
}