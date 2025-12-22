//! Key Derivation Functions (KDF) implementations.
//!
//! This module provides implementations of cryptographic key derivation
//! functions for deriving cryptographic keys from passwords or other keys.
//!
//! # Available Algorithms
//!
//! - [`pbkdf2`] - Password-Based Key Derivation Function 2 (PBKDF2)
//! - [`hkdf`] - HMAC-based Key Derivation Function (HKDF)
//!
//! # Security Recommendations
//!
//! - Use **PBKDF2** when deriving keys from passwords (with high iteration count)
//! - Use **HKDF** when expanding/deriving keys from existing cryptographic keys
//! - Always use unique salts for PBKDF2

pub mod hkdf;
pub mod pbkdf2;

#[allow(unused_imports)]
pub use hkdf::derive_key;
pub use pbkdf2::pbkdf2_hmac_sha256;