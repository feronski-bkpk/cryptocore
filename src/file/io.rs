use std::fs;
use std::path::Path;
use anyhow::{Result, anyhow};

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        anyhow!("Failed to read input file '{}': {}", path.display(), e)
    })
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow!("Failed to create output directory '{}': {}", parent.display(), e)
        })?;
    }

    fs::write(path, data).map_err(|e| {
        anyhow!("Failed to write output file '{}': {}", path.display(), e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_write_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, CryptoCore!";
        
        write_file(temp_file.path(), test_data).unwrap();
        
        let read_data = read_file(temp_file.path()).unwrap();
        assert_eq!(test_data, &read_data[..]);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let result = read_file(Path::new("/nonexistent/file_that_does_not_exist_12345.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_write_to_nonexistent_directory() {
        let path = Path::new("C:/nonexistent_test_directory_12345/test.txt");
        let result = write_file(path, b"test");
        let _ = result; 
    }
}