pub mod sha256;
pub mod sha3_256;

use anyhow::Result;
use std::path::Path;

pub trait HashAlgorithm {
    fn hash_file(&self, file_path: &Path) -> Result<String>;
    fn hash_data(&self, data: &[u8]) -> Result<String>;
}

pub enum HashType {
    Sha256,
    Sha3_256,
}

impl HashType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha256" => Some(Self::Sha256),
            "sha3-256" | "sha3_256" => Some(Self::Sha3_256),
            _ => None,
        }
    }

    pub fn create_hasher(&self) -> Box<dyn HashAlgorithm> {
        match self {
            Self::Sha256 => Box::new(sha256::Sha256::new()),
            Self::Sha3_256 => Box::new(sha3_256::Sha3_256::new()),
        }
    }
}