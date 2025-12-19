pub mod cbc;
pub mod cfb;
pub mod ofb;
pub mod ctr;
pub mod ecb;
pub mod gcm;

use anyhow::Result;

pub trait BlockMode {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
}

pub trait FromKeyBytes {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self>
    where
        Self: Sized;
}

pub use cbc::Cbc;
pub use cfb::Cfb;
pub use ofb::Ofb;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::Gcm;

impl FromKeyBytes for Cbc {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Cbc::new_from_bytes(key)
    }
}

impl FromKeyBytes for Cfb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Cfb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ofb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ofb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ctr {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ctr::new_from_bytes(key)
    }
}

impl FromKeyBytes for Ecb {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Ecb::new_from_bytes(key)
    }
}

impl FromKeyBytes for Gcm {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> {
        Gcm::new_from_bytes(key)
    }
}

#[cfg(test)]
pub fn create_mode_from_bytes<M: FromKeyBytes>(key: &[u8; 16]) -> Result<M> {
    M::from_key_bytes(key)
}