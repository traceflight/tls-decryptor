//! TLS key derivation module
//!
//! This module provides key derivation functionality for TLS 1.2 and TLS 1.3.

mod tls12;
mod tls13;

// Re-export TLS 1.2 key deriver and derive function
pub use tls12::{
    DeriverEvent as Tls12DeriverEvent, DeriverState as Tls12DeriverState, Tls12KeyDeriver,
    derive_keys_tls12,
};

// Re-export TLS 1.3 key deriver and derive function
pub use tls13::{
    DeriverEvent, DeriverState, HandshakeHashAccumulator, HrrData, Tls13KeyDeriver,
    derive_keys_tls13,
};
