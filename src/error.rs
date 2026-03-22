//! TLS decrypter error type definitions

use thiserror::Error;

/// Errors that may occur during TLS decryption
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Invalid TLS record header
    #[error("Invalid TLS record header")]
    InvalidRecordHeader,

    /// Unsupported TLS version
    #[error("Unsupported TLS version: {0}")]
    UnsupportedTlsVersion(u16),

    /// Unsupported cipher suite
    #[error("Unsupported cipher suite: {0:#x}")]
    UnsupportedCipherSuite(u16),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Insufficient data
    #[error("Insufficient data")]
    InsufficientData,

    /// Authentication tag verification failed
    #[error("Authentication tag verification failed")]
    AuthenticationFailed,

    /// Invalid Pre-Master Secret
    #[error("Invalid Pre-Master Secret")]
    InvalidPreMasterSecret,

    /// RSA decryption error
    #[error("RSA decryption error: {0}")]
    RsaError(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid IV length
    #[error("Invalid IV length: expected {expected}, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },

    /// Sequence number overflow
    #[error("Sequence number overflow")]
    SequenceNumberOverflow,

    /// Unknown crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Type alias for decryption results
pub type Result<T> = std::result::Result<T, DecryptError>;
