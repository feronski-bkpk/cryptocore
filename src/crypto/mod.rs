//! Core cryptographic operations module.
//!
//! This module provides the main cryptographic functionality including:
//! - Symmetric encryption with various modes of operation
//! - Authenticated encryption with associated data (AEAD)
//!
//! # Structure
//!
//! - [`modes`] - Block cipher modes of operation (ECB, CBC, CFB, OFB, CTR, GCM)
//! - [`aead`] - Authenticated encryption implementations (Encrypt-then-MAC)
//!
//! # Security Notes
//!
//! - ECB mode is not recommended for most applications due to lack of diffusion
//! - CBC, CFB, OFB, and CTR modes provide confidentiality but not integrity
//! - GCM and ETM modes provide both confidentiality and integrity

pub mod aead;
pub mod modes;

#[allow(unused_imports)]
pub use aead::EncryptThenMac;
#[allow(unused_imports)]
pub use modes::{BlockMode, Cbc, Cfb, Ctr, Ecb, FromKeyBytes, Gcm, Ofb};