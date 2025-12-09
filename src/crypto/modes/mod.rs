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

pub use cbc::Cbc;
pub use cfb::Cfb;
pub use ofb::Ofb;
pub use ctr::Ctr;
pub use ecb::Ecb;
pub use gcm::Gcm;