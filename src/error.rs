//! TLS Decryptor error type definitions

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

    /// Invalid handshake message
    #[error("Invalid handshake message")]
    InvalidHandshakeMessage,

    /// Handshake not complete
    #[error("Handshake not complete")]
    HandshakeNotComplete,

    /// TLS 1.3 key deriver state error
    #[error("Invalid key deriver state: {0}")]
    InvalidDeriverState(String),

    /// Unexpected handshake message order
    #[error("Unexpected handshake message: expected {expected}, got {got}")]
    UnexpectedHandshakeMessage { expected: String, got: String },

    /// Hello Retry Request processing error
    #[error("Hello Retry Request error: {0}")]
    HrrError(String),

    /// Unsupported key share group
    #[error("Unsupported key share group: {0}")]
    UnsupportedKeyShareGroup(u16),

    /// Unsupported curve type
    #[error("Unsupported curve type: {0:#x}")]
    UnsupportedCurveType(u16),

    /// DHE computation error
    #[error("DHE computation error: {0}")]
    DheError(String),

    /// Invalid DH parameters
    #[error("Invalid DH parameters: {0}")]
    InvalidDhParameters(String),

    /// Handshake message parse error
    #[error("Handshake message parse error: {0}")]
    HandshakeParseError(String),
}

/// Type alias for decryption results
pub type Result<T> = std::result::Result<T, DecryptError>;
