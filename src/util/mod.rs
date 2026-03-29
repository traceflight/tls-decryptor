//! TLS utility module
//!
//! This module provides utility functions for TLS key exchange operations.

mod ecdhe;
mod tls12;
mod tls13;

pub use ecdhe::compute_ecdhe_shared_secret;
pub use tls12::{
    DhParamsRef, ServerPublicKey, compute_pre_master_secret_dhe, compute_pre_master_secret_ecdhe,
    compute_pre_master_secret_from_key_exchange, extract_server_public_key,
};
pub use tls13::{compute_shared_secret_tls13, extract_keys_from_hello_messages};
