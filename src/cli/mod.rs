//! Command-line interface module.
//!
//! This module contains types and functions for parsing and validating
//! command-line arguments for the cryptocore application.
//!
//! # Structure
//!
//! - [`parser`] submodule - Contains the main argument parsing logic
//! - Re-exports of public types from parser for convenient access

pub mod parser;

#[allow(unused_imports)]
pub use parser::*;