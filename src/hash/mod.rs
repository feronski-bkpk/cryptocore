use anyhow::Result;
use std::path::Path;

pub mod sha256;
pub mod sha3_256;

pub use sha256::Sha256;
pub use sha3_256::Sha3_256;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    Sha256,
    Sha3_256,
}

impl HashType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha256" => Some(Self::Sha256),
            "sha3-256" => Some(Self::Sha3_256),
            _ => None,
        }
    }

    pub fn create_hasher(&self) -> Box<dyn HashAlgorithm> {
        match self {
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha3_256 => Box::new(Sha3_256::new()),
        }
    }
}

pub trait HashAlgorithm {
    #[allow(dead_code)]
    fn hash_file(&self, file_path: &Path) -> Result<String>;
    fn hash_data(&self, data: &[u8]) -> Result<String>;
}