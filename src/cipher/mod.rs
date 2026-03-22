//! Cipher suite related definitions and implementations
//!
//! # Directory Structure
//!
//! ```text
//! cipher/
//! ├── mod.rs              # Module entry point
//! ├── trait_def.rs        # CipherContext trait definition
//! ├── registry.rs         # Cipher suite registry
//! └── suites/             # Cipher suite implementations directory
//!     ├── mod.rs
//!     ├── tls_rsa_with_aes_128_gcm_sha256.rs
//!     ├── tls_rsa_with_aes_256_gcm_sha384.rs
//!     ├── tls13_aes_128_gcm_sha256.rs
//!     ├── tls13_aes_256_gcm_sha384.rs
//!     ├── tls13_chacha20_poly1305_sha256.rs
//!     └── tls_ecdhe_rsa_with_chacha20_poly1305_sha256.rs
//! ```

pub mod registry;
pub mod suites;
pub mod trait_def;

pub use registry::{CipherRegistry, get_cipher, get_cipher_by_id};
pub use trait_def::CipherContext;
