//! File I/O operations for cryptographic data.
//!
//! This module provides functions for reading and writing files,
//! as well as utilities for handling initialization vectors (IVs)
//! in cryptographic file formats.
//!
//! # File Format
//!
//! For modes that use IVs (CBC, CFB, OFB, CTR), the file format is:
//! - First 16 bytes: Initialization Vector (IV)
//! - Remaining bytes: Ciphertext
//!
//! For GCM mode, the format is different and handled by the GCM implementation.

pub mod io;

pub use io::{extract_iv_from_file, prepend_iv_to_data, read_file, write_file};