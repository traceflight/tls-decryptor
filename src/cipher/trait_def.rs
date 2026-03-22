//! CipherContext trait definition

use crate::error::Result;
use crate::types::TlsVersion;
use rustls::CipherSuite;

/// Cipher context trait - implemented by each cipher suite
///
/// This trait provides cipher suite metadata and decryption operations,
/// enabling dynamic extension to support new cipher suites.
pub trait CipherContext: Send + Sync {
    /// Returns the cipher suite identifier
    fn suite(&self) -> CipherSuite;

    /// Returns the TLS version
    fn version(&self) -> TlsVersion;

    /// Returns the key length in bytes
    fn key_length(&self) -> usize;

    /// Returns the IV length in bytes
    fn iv_length(&self) -> usize;

    /// Returns the authentication tag length in bytes, non-AEAD returns 0
    fn tag_length(&self) -> usize;

    /// Whether explicit nonce is needed (TLS 1.2 AEAD)
    fn needs_explicit_nonce(&self) -> bool;

    /// Decrypt data
    ///
    /// # Parameters
    /// - `key`: Decryption key
    /// - `iv`: Initial vector (static part)
    /// - `ciphertext`: Ciphertext (may contain explicit nonce at the beginning)
    /// - `aad`: AEAD additional data
    /// - `sequence_number`: TLS record sequence number (used to construct nonce)
    ///
    /// # Returns
    /// Decrypted plaintext
    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        sequence_number: u64,
    ) -> Result<Vec<u8>>;
}
