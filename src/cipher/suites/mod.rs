//! Cipher suite implementation module
//!
//! Each file corresponds to an officially named cipher suite implementation for easy extension and maintenance.
//!
//! # Naming Convention
//!
//! File names use rustls CipherSuite enum names (snake_case):
//! - `tls_rsa_with_aes_128_gcm_sha256.rs` -> TLS_RSA_WITH_AES_128_GCM_SHA256
//! - `tls13_aes_128_gcm_sha256.rs` -> TLS13_AES_128_GCM_SHA256
//!
//! # Adding New Suites
//!
//! 1. Create a new file in the `src/cipher/suites/` directory, named after the official suite name
//! 2. Implement the `CipherContext` trait
//! 3. Add a `pub mod` declaration in this file
//! 4. Register the new suite in `registry.rs`

// Common helper functions
pub mod aead_common;

// TLS 1.2 AEAD suites
pub mod tls_rsa_with_aes_128_gcm_sha256;
pub mod tls_rsa_with_aes_256_gcm_sha384;

// TLS 1.2 ChaCha20-Poly1305 suites
pub mod tls_ecdhe_rsa_with_chacha20_poly1305_sha256;

// TLS 1.3 AEAD suites
pub mod tls13_aes_128_gcm_sha256;
pub mod tls13_aes_256_gcm_sha384;
pub mod tls13_chacha20_poly1305_sha256;

// Re-export all suite types
pub use tls_ecdhe_rsa_with_chacha20_poly1305_sha256::TlsEcdheRsaWithChaCha20Poly1305Sha256;
pub use tls_rsa_with_aes_128_gcm_sha256::TlsRsaWithAes128GcmSha256;
pub use tls_rsa_with_aes_256_gcm_sha384::TlsRsaWithAes256GcmSha384;
pub use tls13_aes_128_gcm_sha256::Tls13Aes128GcmSha256;
pub use tls13_aes_256_gcm_sha384::Tls13Aes256GcmSha384;
pub use tls13_chacha20_poly1305_sha256::Tls13ChaCha20Poly1305Sha256;
