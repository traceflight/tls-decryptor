//! CipherContext trait definition

use crate::error::Result;
use crate::types::{CipherSuite, TlsVersion};

/// Cipher context trait - implemented by each cipher suite
///
/// This trait provides cipher suite metadata and decryption operations,
/// enabling dynamic extension to support new cipher suites.
pub trait CipherContext: Send + Sync {
    /// Returns the cipher suite identifier
    fn suite(&self) -> CipherSuite;

    /// Returns the TLS version
    ///
    /// Default implementation delegates to `CipherSuite::version()`.
    fn version(&self) -> TlsVersion {
        self.suite().version()
    }

    /// Returns the key length in bytes
    ///
    /// Default implementation delegates to `CipherSuite::key_iv_length()`.
    fn key_length(&self) -> usize {
        self.suite().key_iv_length().0
    }

    /// Returns the IV length in bytes
    ///
    /// Default implementation delegates to `CipherSuite::key_iv_length()`.
    fn iv_length(&self) -> usize {
        self.suite().key_iv_length().1
    }

    /// Returns the authentication tag length in bytes, non-AEAD returns 0
    ///
    /// Default implementation delegates to `CipherSuite::tag_length()`.
    fn tag_length(&self) -> usize {
        self.suite().tag_length()
    }

    /// Whether explicit nonce is needed (TLS 1.2 AEAD)
    ///
    /// Default implementation delegates to `CipherSuite::needs_explicit_nonce()`.
    fn needs_explicit_nonce(&self) -> bool {
        self.suite().needs_explicit_nonce()
    }

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
