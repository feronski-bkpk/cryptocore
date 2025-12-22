//! File input/output operations.
//!
//! This module contains functions for reading from and writing to files,
//! with special handling for cryptographic data formats that include
//! initialization vectors.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};

/// Size of initialization vectors in bytes.
const IV_SIZE: usize = 16;

/// Reads the entire contents of a file into a byte vector.
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - File contents as byte vector
/// * `Err(anyhow::Error)` - If file cannot be read
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        anyhow!("Failed to read input file '{}': {}", path.display(), e)
    })
}

/// Writes data to a file, creating parent directories if needed.
///
/// # Arguments
///
/// * `path` - Path where to write the file
/// * `data` - Data to write
///
/// # Returns
///
/// * `Ok(())` - If file was written successfully
/// * `Err(anyhow::Error)` - If file cannot be written
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use cryptocore::file::write_file;
///
/// write_file(Path::new("output.txt"), b"Hello, world!").unwrap();
/// ```
pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!(
                "Failed to create output directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    fs::write(path, data).map_err(|e| {
        anyhow!("Failed to write output file '{}': {}", path.display(), e)
    })
}

/// Extracts the initialization vector from encrypted file data.
///
/// Assumes the file format: first 16 bytes are IV, remaining bytes are ciphertext.
///
/// # Arguments
///
/// * `data` - Complete file data (IV + ciphertext)
///
/// # Returns
///
/// * `Ok(([u8; IV_SIZE], &[u8]))` - Tuple of (IV array, ciphertext slice)
/// * `Err(anyhow::Error)` - If data is too short to contain an IV
///
/// # Examples
///
/// ```
/// use cryptocore::file::extract_iv_from_file;
///
/// let mut data = vec![0u8; 32];
/// data[0..16].copy_from_slice(&[0x01; 16]); // IV
/// data[16..].copy_from_slice(&[0x42; 16]);  // Ciphertext
///
/// let (iv, ciphertext) = extract_iv_from_file(&data).unwrap();
/// assert_eq!(iv.len(), 16);
/// assert_eq!(ciphertext.len(), 16);
/// ```
pub fn extract_iv_from_file(data: &[u8]) -> Result<([u8; IV_SIZE], &[u8])> {
    if data.len() < IV_SIZE {
        return Err(anyhow!("File too short to contain IV"));
    }

    let mut iv = [0u8; IV_SIZE];
    iv.copy_from_slice(&data[..IV_SIZE]);
    let ciphertext = &data[IV_SIZE..];

    Ok((iv, ciphertext))
}

/// Prepends an initialization vector to data.
///
/// Creates a new vector with the format: IV || data
///
/// # Arguments
///
/// * `iv` - Initialization vector bytes
/// * `data` - Data to prepend IV to
///
/// # Returns
///
/// New vector containing IV followed by data
///
/// # Examples
///
/// ```
/// use cryptocore::file::prepend_iv_to_data;
///
/// let iv = [0x01; 16];
/// let data = b"ciphertext";
/// let result = prepend_iv_to_data(&iv, data);
///
/// assert_eq!(result.len(), 16 + data.len());
/// assert_eq!(&result[0..16], &iv);
/// assert_eq!(&result[16..], data);
/// ```
pub fn prepend_iv_to_data(iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(iv.len() + data.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(data);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Tests basic file read and write operations.
    #[test]
    fn test_read_write_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, CryptoCore!";

        write_file(temp_file.path(), test_data).unwrap();

        let read_data = read_file(temp_file.path()).unwrap();
        assert_eq!(test_data, &read_data[..]);
    }

    /// Tests reading a non-existent file returns an error.
    #[test]
    fn test_read_nonexistent_file() {
        let result = read_file(Path::new("/nonexistent/file_that_does_not_exist_12345.txt"));
        assert!(result.is_err());
    }

    /// Tests extraction of IV from file data.
    #[test]
    fn test_extract_iv_from_file() {
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let data = b"ciphertext data";

        let mut full_data = Vec::new();
        full_data.extend_from_slice(&iv);
        full_data.extend_from_slice(data);

        let (extracted_iv, extracted_data) = extract_iv_from_file(&full_data).unwrap();

        assert_eq!(iv, extracted_iv);
        assert_eq!(data, extracted_data);
    }

    /// Tests that extracting IV from too-short data fails.
    #[test]
    fn test_extract_iv_from_short_file() {
        let short_data = b"short";
        let result = extract_iv_from_file(short_data);
        assert!(result.is_err());
    }

    /// Tests prepending IV to data.
    #[test]
    fn test_prepend_iv_to_data() {
        let iv = [0xFF; 16];
        let data = b"test data";

        let result = prepend_iv_to_data(&iv, data);

        assert_eq!(result.len(), iv.len() + data.len());
        assert_eq!(&result[..16], &iv);
        assert_eq!(&result[16..], data);
    }
}