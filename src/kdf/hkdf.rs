use anyhow::Result;
use crate::mac::hmac::HMAC;
use crate::hash::HashType;
use hex;

pub fn derive_key(master_key: &[u8], context: &str, length: usize) -> Result<Vec<u8>> {
    let context_bytes = context.as_bytes();

    let mut derived = Vec::with_capacity(length);
    let mut counter: u32 = 1;

    while derived.len() < length {
        let mut input = context_bytes.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());

        let hmac = HMAC::new(master_key, HashType::Sha256);
        let block_hex = hmac.compute(&input)?;
        let block = hex::decode(&block_hex)?;

        derived.extend_from_slice(&block);
        counter += 1;
    }

    Ok(derived[..length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_basic() -> Result<()> {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let context = "encryption";
        let length = 32;

        let key1 = derive_key(master_key, context, length)?;
        let key2 = derive_key(master_key, context, length)?;

        assert_eq!(key1.len(), length);
        assert_eq!(key2.len(), length);
        assert_eq!(key1, key2);

        Ok(())
    }

    #[test]
    fn test_context_separation() -> Result<()> {
        let master_key = b"0123456789abcdef0123456789abcdef";

        let key1 = derive_key(master_key, "encryption", 32)?;
        let key2 = derive_key(master_key, "authentication", 32)?;

        assert_ne!(key1, key2);

        Ok(())
    }

    #[test]
    fn test_various_lengths() -> Result<()> {
        let master_key = b"masterkey";

        for length in [1, 16, 32, 48, 64, 100] {
            let key = derive_key(master_key, "test", length)?;
            assert_eq!(key.len(), length);
        }

        Ok(())
    }

    #[test]
    fn test_different_master_keys() -> Result<()> {
        let context = "encryption";
        let length = 32;

        let key1 = derive_key(b"key1", context, length)?;
        let key2 = derive_key(b"key2", context, length)?;

        assert_ne!(key1, key2);

        Ok(())
    }
}