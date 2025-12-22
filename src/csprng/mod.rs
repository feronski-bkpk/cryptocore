use anyhow::{Result, anyhow};
use openssl::rand;

const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const SALT_SIZE: usize = 16;

pub struct Csprng;

impl Csprng {
    pub fn generate_key() -> Result<[u8; KEY_SIZE]> {
        let mut key = [0u8; KEY_SIZE];
        rand::rand_bytes(&mut key)?;
        Ok(key)
    }

    pub fn generate_iv() -> Result<[u8; IV_SIZE]> {
        let mut iv = [0u8; IV_SIZE];
        rand::rand_bytes(&mut iv)?;
        Ok(iv)
    }

    pub fn generate_salt() -> Result<[u8; SALT_SIZE]> {
        let mut salt = [0u8; SALT_SIZE];
        rand::rand_bytes(&mut salt)?;
        Ok(salt)
    }

    #[allow(dead_code)]
    pub fn generate_nonce(size: usize) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; size];
        rand::rand_bytes(&mut nonce)?;
        Ok(nonce)
    }

    #[allow(dead_code)]
    pub fn generate_random_bytes(size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut bytes = vec![0u8; size];
        rand::rand_bytes(&mut bytes)?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    pub fn generate_large_random_data(size: usize) -> Result<Vec<u8>> {
        Self::generate_random_bytes(size)
    }

    #[allow(dead_code)]
    pub fn test_randomness() -> Result<()> {
        let mut key_set = std::collections::HashSet::new();
        let mut iv_set = std::collections::HashSet::new();
        let mut salt_set = std::collections::HashSet::new();

        for _ in 0..1000 {
            let key = Self::generate_key()?;
            let iv = Self::generate_iv()?;
            let salt = Self::generate_salt()?;

            if !key_set.insert(key) {
                return Err(anyhow!("Duplicate key generated!"));
            }
            if !iv_set.insert(iv) {
                return Err(anyhow!("Duplicate IV generated!"));
            }
            if !salt_set.insert(salt) {
                return Err(anyhow!("Duplicate salt generated!"));
            }
        }

        println!("[SUCCESS] All 1000 keys, IVs, and salts are unique!");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() -> Result<()> {
        let key1 = Csprng::generate_key()?;
        let key2 = Csprng::generate_key()?;

        assert_ne!(key1, key2);
        Ok(())
    }

    #[test]
    fn test_iv_generation() -> Result<()> {
        let iv1 = Csprng::generate_iv()?;
        let iv2 = Csprng::generate_iv()?;

        assert_ne!(iv1, iv2);
        Ok(())
    }

    #[test]
    fn test_salt_generation() -> Result<()> {
        let salt1 = Csprng::generate_salt()?;
        let salt2 = Csprng::generate_salt()?;

        assert_ne!(salt1, salt2);
        Ok(())
    }
}