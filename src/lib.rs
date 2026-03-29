//! TLS Decryptor Library
//!
//! A TLS packet decryption library (with private key) written in Rust, supporting TLS 1.2 and TLS 1.3.
//!
//! # Features
//!
//! - Derive TLS session keys from private key and handshake parameters
//! - Decrypt individual TLS Application Data records using session keys
//! - Support for multiple cipher suites (AES-GCM, ChaCha20-Poly1305)
//! - Extensible cipher suite architecture
//!
//! # Examples
//!
//! ## TLS 1.2 RSA Key Exchange
//!
//! ```rust,ignore
//! use tls_decryptor::{
//!     TlsDecrypter, SessionKey, Direction,
//!     key_derivation::derive_keys_tls12,
//! };
//!
//! # fn example() -> Result<(), tls_decryptor::error::DecryptError> {
//! // 1. Decrypt Pre-Master Secret using private key (requires external RSA library)
//! let private_key_pem = std::fs::read_to_string("server_key.pem")?;
//! let encrypted_pms = /* extracted from ClientKeyExchange */;
//! let pre_master_secret = /* decrypt using private key */;
//!
//! // 2. Derive session keys
//! let client_random = /* extracted from ClientHello */;
//! let server_random = /* extracted from ServerHello */;
//! let cipher_suite = /* negotiated cipher suite */;
//!
//! let session_key = derive_keys_tls12(
//!     &client_random,
//!     &server_random,
//!     &pre_master_secret,
//!     cipher_suite,
//! )?;
//!
//! // 3. Create decrypter and decrypt
//! let mut decrypter = TlsDecrypter::new(session_key)?;
//! let plaintext = decrypter.decrypt_application_data(
//!     &encrypted_record,
//!     Direction::ServerToClient,
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## TLS 1.3 ECDHE Key Exchange
//!
//! ```rust,ignore
//! use tls_decryptor::{
//!     TlsDecrypter, Direction,
//!     key_derivation::derive_keys_tls13,
//! };
//!
//! # fn example() -> Result<(), tls_decryptor::error::DecryptError> {
//! // 1. Compute ECDHE shared secret
//! let shared_secret = /* ECDHE shared secret */;
//!
//! // 2. Derive session keys
//! let cipher_suite = /* TLS 1.3 cipher suite */;
//! let handshake_hash = /* hash of handshake messages */;
//!
//! let session_key = derive_keys_tls13(
//!     &shared_secret,
//!     cipher_suite,
//!     &handshake_hash,
//! )?;
//!
//! // 3. Create decrypter and decrypt
//! let mut decrypter = TlsDecrypter::new(session_key)?;
//! let plaintext = decrypter.decrypt_application_data(
//!     &encrypted_record,
//!     Direction::ServerToClient,
//! )?;
//! # Ok(())
//! # }
//! ```

pub mod cipher;
pub mod decrypter;
pub mod error;
pub mod key_derivation;
pub mod types;
pub mod util;

// Re-export commonly used types
pub use decrypter::TlsDecrypter;
pub use error::{DecryptError, Result};
pub use key_derivation::{
    DeriverEvent, DeriverState, HrrData, Tls13KeyDeriver, derive_keys_tls12, derive_keys_tls13,
};
pub use types::{
    CurveType, Direction, SessionKey, TlsRecordHeader, TlsRecordType, TlsVersion,
    parse_tls_record_header,
};
pub use util::{
    DhParamsRef, ServerPublicKey, compute_ecdhe_shared_secret, compute_pre_master_secret_dhe,
    compute_pre_master_secret_ecdhe, compute_shared_secret_tls13, extract_server_public_key,
};
