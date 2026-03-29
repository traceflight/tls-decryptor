//! TLS Decryptor basic type definitions

pub use tls_parser::{
    TlsCipherSuiteID, TlsRecordHeader, TlsRecordType, TlsVersion, parse_tls_record_header,
};

/// Decryption direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client to server
    ClientToServer,
    /// Server to client
    ServerToClient,
}

/// Session key material
///
/// Contains all key material required to decrypt TLS records
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// TLS version
    pub version: TlsVersion,
    /// Cipher suite
    pub cipher_suite: CipherSuite,
    /// Client write key (used to decrypt data sent by server)
    pub client_write_key: Vec<u8>,
    /// Server write key (used to decrypt data sent by client)
    pub server_write_key: Vec<u8>,
    /// Client write IV (used to decrypt data sent by server)
    pub client_write_iv: Vec<u8>,
    /// Server write IV (used to decrypt data sent by client)
    pub server_write_iv: Vec<u8>,
}

impl SessionKey {
    /// Create a new SessionKey
    pub fn new(
        version: TlsVersion,
        cipher_suite: CipherSuite,
        client_write_key: Vec<u8>,
        server_write_key: Vec<u8>,
        client_write_iv: Vec<u8>,
        server_write_iv: Vec<u8>,
    ) -> Self {
        Self {
            version,
            cipher_suite,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        }
    }

    /// Create a new SessionKey with TlsCipherSuiteID
    pub fn new_with_id(
        version: TlsVersion,
        cipher_suite: TlsCipherSuiteID,
        client_write_key: Vec<u8>,
        server_write_key: Vec<u8>,
        client_write_iv: Vec<u8>,
        server_write_iv: Vec<u8>,
    ) -> Self {
        Self {
            version,
            cipher_suite: CipherSuite::from(cipher_suite),
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        }
    }

    /// Get cipher suite ID (u16 format)
    pub fn cipher_suite_id(&self) -> u16 {
        self.cipher_suite.to_u16()
    }

    /// Get write key based on direction
    pub fn get_write_key(&self, direction: Direction) -> &[u8] {
        match direction {
            Direction::ClientToServer => &self.client_write_key,
            Direction::ServerToClient => &self.server_write_key,
        }
    }

    /// Get write IV based on direction
    pub fn get_write_iv(&self, direction: Direction) -> &[u8] {
        match direction {
            Direction::ClientToServer => &self.client_write_iv,
            Direction::ServerToClient => &self.server_write_iv,
        }
    }
}

/// TLS 1.2 parameters required for key derivation
#[derive(Debug, Clone)]
pub struct Tls12KeyParams {
    /// Client random (32 bytes)
    pub client_random: [u8; 32],
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Pre-Master Secret
    pub pre_master_secret: Vec<u8>,
}

impl Tls12KeyParams {
    pub fn new(
        client_random: [u8; 32],
        server_random: [u8; 32],
        pre_master_secret: Vec<u8>,
    ) -> Self {
        Self {
            client_random,
            server_random,
            pre_master_secret,
        }
    }
}

/// TLS 1.3 parameters required for key derivation
#[derive(Debug, Clone)]
pub struct Tls13KeyParams {
    /// ClientHello random (32 bytes)
    pub client_hello_random: [u8; 32],
    /// ServerHello random (32 bytes)
    pub server_hello_random: [u8; 32],
    /// ECDHE shared secret
    pub shared_secret: Vec<u8>,
    /// Hash of handshake messages
    pub handshake_hash: Vec<u8>,
}

impl Tls13KeyParams {
    pub fn new(
        client_hello_random: [u8; 32],
        server_hello_random: [u8; 32],
        shared_secret: Vec<u8>,
        handshake_hash: Vec<u8>,
    ) -> Self {
        Self {
            client_hello_random,
            server_hello_random,
            shared_secret,
            handshake_hash,
        }
    }
}

/// Elliptic curve type
///
/// Supports named curves for TLS 1.2 (RFC 4492) and TLS 1.3 (RFC 8446)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CurveType {
    /// secp256r1 (P-256) - RFC 4492/8446 group 0x0017
    Secp256r1 = 0x0017,
    /// secp384r1 (P-384) - RFC 4492/8446 group 0x0018
    Secp384r1 = 0x0018,
    /// secp521r1 (P-521) - RFC 4492/8446 group 0x0019
    Secp521r1 = 0x0019,
    /// x25519 - RFC 8446 group 0x001D
    X25519 = 0x001D,
    /// x448 - RFC 8446 group 0x001E
    X448 = 0x001E,
}

impl CurveType {
    /// Convert from u16 to CurveType
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x0019 => Some(Self::Secp521r1),
            0x001D => Some(Self::X25519),
            0x001E => Some(Self::X448),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// Get the expected key share length for this curve (uncompressed public key)
    ///
    /// This is the same as `public_key_uncompressed_length()`.
    /// For X25519/X448, this returns the raw key length.
    pub fn key_share_length(self) -> usize {
        self.public_key_uncompressed_length()
    }

    /// Get the shared secret length for this curve
    pub fn shared_secret_length(self) -> usize {
        match self {
            Self::Secp256r1 => 32,
            Self::Secp384r1 => 48,
            Self::Secp521r1 => 66,
            Self::X25519 => 32,
            Self::X448 => 56,
        }
    }

    /// Get the private key length for this curve (in bytes)
    pub fn private_key_length(self) -> usize {
        match self {
            Self::Secp256r1 => 32,
            Self::Secp384r1 => 48,
            Self::Secp521r1 => 66,
            Self::X25519 => 32,
            Self::X448 => 56,
        }
    }

    /// Get the public key uncompressed length for this curve (in bytes)
    ///
    /// For NIST curves (secp256r1, secp384r1, secp521r1):
    /// - Format: 0x04 prefix + X coordinate + Y coordinate
    /// - Total: 1 + 2 * coordinate_size
    ///
    /// For X25519/X448 (Montgomery curves):
    /// - No compression format, just raw bytes
    pub fn public_key_uncompressed_length(self) -> usize {
        match self {
            Self::Secp256r1 => 65,  // 1 + 32 + 32
            Self::Secp384r1 => 97,  // 1 + 48 + 48
            Self::Secp521r1 => 133, // 1 + 66 + 66
            Self::X25519 => 32,     // Raw 32-byte key
            Self::X448 => 56,       // Raw 56-byte key
        }
    }

    /// Get the public key compressed length for this curve (in bytes)
    ///
    /// For NIST curves (secp256r1, secp384r1, secp521r1):
    /// - Format: 0x02 or 0x03 prefix + X coordinate
    /// - Total: 1 + coordinate_size
    ///
    /// For X25519/X448 (Montgomery curves):
    /// - No compression format, same as uncompressed (raw bytes)
    pub fn public_key_compressed_length(self) -> usize {
        match self {
            Self::Secp256r1 => 33, // 1 + 32
            Self::Secp384r1 => 49, // 1 + 48
            Self::Secp521r1 => 67, // 1 + 66
            Self::X25519 => 32,    // Raw 32-byte key (no compression)
            Self::X448 => 56,      // Raw 56-byte key (no compression)
        }
    }

    /// Check if the given private key length is valid for this curve
    ///
    /// For P-521, both 65 and 66 bytes are accepted because:
    /// - P-521 private key is 521 bits = 65.125 bytes
    /// - When the leading bit is 0, the key can be represented in 65 bytes
    /// - When the leading bit is 1, 66 bytes are needed
    pub fn is_valid_private_key_length(self, len: usize) -> bool {
        match self {
            Self::Secp521r1 => len == 65 || len == 66,
            _ => len == self.private_key_length(),
        }
    }

    /// Check if the given public key length is valid for this curve (either compressed or uncompressed)
    pub fn is_valid_public_key_length(self, len: usize) -> bool {
        len == self.public_key_uncompressed_length() || len == self.public_key_compressed_length()
    }
}

/// DHE parameters
///
/// Used for TLS 1.2 DHE key exchange
#[derive(Debug, Clone)]
pub struct DhParams {
    /// Prime p (big-endian byte order)
    pub p: Vec<u8>,
    /// Generator g (big-endian byte order)
    pub g: Vec<u8>,
}

impl DhParams {
    /// Create new DH parameters
    pub fn new(p: Vec<u8>, g: Vec<u8>) -> Self {
        Self { p, g }
    }
}

/// TLS Cipher Suite enumeration
///
/// Provides type-safe representation of TLS cipher suites without depending on rustls.
/// Reference: rustls CipherSuite definition
///
/// Note: Uses SCREAMING_SNAKE_CASE naming convention to match industry standard
/// (RFC 8446, RFC 5246, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    /// TLS_NULL_WITH_NULL_NULL
    TLS_NULL_WITH_NULL_NULL = 0x0000,
    /// TLS_RSA_WITH_NULL_MD5
    TLS_RSA_WITH_NULL_MD5 = 0x0001,
    /// TLS_RSA_WITH_NULL_SHA
    TLS_RSA_WITH_NULL_SHA = 0x0002,
    /// TLS_RSA_WITH_RC4_128_MD5
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
    /// TLS_RSA_WITH_RC4_128_SHA
    TLS_RSA_WITH_RC4_128_SHA = 0x0005,
    /// TLS_RSA_WITH_DES_CBC_SHA
    TLS_RSA_WITH_DES_CBC_SHA = 0x0009,
    /// TLS_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a,
    /// TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    /// TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    /// TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    /// TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    /// TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    /// TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    /// TLS_PSK_WITH_AES_128_GCM_SHA256
    TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00a8,
    /// TLS_PSK_WITH_AES_256_GCM_SHA384
    TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00a9,
    /// TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
    /// TLS13_AES_128_GCM_SHA256
    TLS13_AES_128_GCM_SHA256 = 0x1301,
    /// TLS13_AES_256_GCM_SHA384
    TLS13_AES_256_GCM_SHA384 = 0x1302,
    /// TLS13_CHACHA20_POLY1305_SHA256
    TLS13_CHACHA20_POLY1305_SHA256 = 0x1303,
    /// TLS13_AES_128_CCM_SHA256
    TLS13_AES_128_CCM_SHA256 = 0x1304,
    /// TLS13_AES_128_CCM_8_SHA256
    TLS13_AES_128_CCM_8_SHA256 = 0x1305,
    /// TLS_ECDH_ECDSA_WITH_NULL_SHA
    TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xc001,
    /// TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002,
    /// TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003,
    /// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004,
    /// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005,
    /// TLS_ECDHE_ECDSA_WITH_NULL_SHA
    TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xc006,
    /// TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007,
    /// TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    /// TLS_ECDH_RSA_WITH_NULL_SHA
    TLS_ECDH_RSA_WITH_NULL_SHA = 0xc00b,
    /// TLS_ECDH_RSA_WITH_RC4_128_SHA
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c,
    /// TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d,
    /// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e,
    /// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f,
    /// TLS_ECDHE_RSA_WITH_NULL_SHA
    TLS_ECDHE_RSA_WITH_NULL_SHA = 0xc010,
    /// TLS_ECDHE_RSA_WITH_RC4_128_SHA
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011,
    /// TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    /// TLS_ECDH_anon_WITH_NULL_SHA
    TLS_ECDH_ANON_WITH_NULL_SHA = 0xc015,
    /// TLS_ECDH_anon_WITH_RC4_128_SHA
    TLS_ECDH_ANON_WITH_RC4_128_SHA = 0xc016,
    /// TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA = 0xc017,
    /// TLS_ECDH_anon_WITH_AES_128_CBC_SHA
    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA = 0xc018,
    /// TLS_ECDH_anon_WITH_AES_256_CBC_SHA
    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA = 0xc019,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    /// TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025,
    /// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    /// TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029,
    /// TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    /// TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d,
    /// TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    /// TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031,
    /// TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    /// TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
    /// Unknown cipher suite (holds the raw u16 value)
    UNKNOWN(u16),
}

impl CipherSuite {
    /// Convert from u16 to CipherSuite
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => Self::TLS_NULL_WITH_NULL_NULL,
            0x0001 => Self::TLS_RSA_WITH_NULL_MD5,
            0x0002 => Self::TLS_RSA_WITH_NULL_SHA,
            0x0004 => Self::TLS_RSA_WITH_RC4_128_MD5,
            0x0005 => Self::TLS_RSA_WITH_RC4_128_SHA,
            0x0009 => Self::TLS_RSA_WITH_DES_CBC_SHA,
            0x000a => Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            0x002f => Self::TLS_RSA_WITH_AES_128_CBC_SHA,
            0x0035 => Self::TLS_RSA_WITH_AES_256_CBC_SHA,
            0x003c => Self::TLS_RSA_WITH_AES_128_CBC_SHA256,
            0x003d => Self::TLS_RSA_WITH_AES_256_CBC_SHA256,
            0x009c => Self::TLS_RSA_WITH_AES_128_GCM_SHA256,
            0x009d => Self::TLS_RSA_WITH_AES_256_GCM_SHA384,
            0x009e => Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            0x009f => Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            0x00a8 => Self::TLS_PSK_WITH_AES_128_GCM_SHA256,
            0x00a9 => Self::TLS_PSK_WITH_AES_256_GCM_SHA384,
            0x00ff => Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            0x1301 => Self::TLS13_AES_128_GCM_SHA256,
            0x1302 => Self::TLS13_AES_256_GCM_SHA384,
            0x1303 => Self::TLS13_CHACHA20_POLY1305_SHA256,
            0x1304 => Self::TLS13_AES_128_CCM_SHA256,
            0x1305 => Self::TLS13_AES_128_CCM_8_SHA256,
            0xc001 => Self::TLS_ECDH_ECDSA_WITH_NULL_SHA,
            0xc002 => Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
            0xc003 => Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
            0xc004 => Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            0xc005 => Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
            0xc006 => Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA,
            0xc007 => Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
            0xc008 => Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            0xc009 => Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            0xc00a => Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            0xc00b => Self::TLS_ECDH_RSA_WITH_NULL_SHA,
            0xc00c => Self::TLS_ECDH_RSA_WITH_RC4_128_SHA,
            0xc00d => Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
            0xc00e => Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            0xc00f => Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
            0xc010 => Self::TLS_ECDHE_RSA_WITH_NULL_SHA,
            0xc011 => Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            0xc012 => Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            0xc013 => Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            0xc014 => Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            0xc015 => Self::TLS_ECDH_ANON_WITH_NULL_SHA,
            0xc016 => Self::TLS_ECDH_ANON_WITH_RC4_128_SHA,
            0xc017 => Self::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA,
            0xc018 => Self::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
            0xc019 => Self::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA,
            0xc023 => Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            0xc024 => Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            0xc025 => Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            0xc026 => Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
            0xc027 => Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            0xc028 => Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            0xc029 => Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            0xc02a => Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
            0xc02b => Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            0xc02c => Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            0xc02d => Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
            0xc02e => Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
            0xc02f => Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            0xc030 => Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            0xc031 => Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
            0xc032 => Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
            0xcca8 => Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            0xcca9 => Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xccaa => Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            _ => Self::UNKNOWN(value),
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        match self {
            Self::TLS_NULL_WITH_NULL_NULL => 0x0000,
            Self::TLS_RSA_WITH_NULL_MD5 => 0x0001,
            Self::TLS_RSA_WITH_NULL_SHA => 0x0002,
            Self::TLS_RSA_WITH_RC4_128_MD5 => 0x0004,
            Self::TLS_RSA_WITH_RC4_128_SHA => 0x0005,
            Self::TLS_RSA_WITH_DES_CBC_SHA => 0x0009,
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA => 0x000a,
            Self::TLS_RSA_WITH_AES_128_CBC_SHA => 0x002f,
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
            Self::TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003c,
            Self::TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003d,
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => 0x009c,
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => 0x009d,
            Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => 0x009e,
            Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => 0x009f,
            Self::TLS_PSK_WITH_AES_128_GCM_SHA256 => 0x00a8,
            Self::TLS_PSK_WITH_AES_256_GCM_SHA384 => 0x00a9,
            Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
            Self::TLS13_AES_128_GCM_SHA256 => 0x1301,
            Self::TLS13_AES_256_GCM_SHA384 => 0x1302,
            Self::TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
            Self::TLS13_AES_128_CCM_SHA256 => 0x1304,
            Self::TLS13_AES_128_CCM_8_SHA256 => 0x1305,
            Self::TLS_ECDH_ECDSA_WITH_NULL_SHA => 0xc001,
            Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA => 0xc002,
            Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc003,
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => 0xc004,
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => 0xc005,
            Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xc006,
            Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => 0xc007,
            Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc008,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,
            Self::TLS_ECDH_RSA_WITH_NULL_SHA => 0xc00b,
            Self::TLS_ECDH_RSA_WITH_RC4_128_SHA => 0xc00c,
            Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => 0xc00d,
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => 0xc00e,
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => 0xc00f,
            Self::TLS_ECDHE_RSA_WITH_NULL_SHA => 0xc010,
            Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA => 0xc011,
            Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xc012,
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,
            Self::TLS_ECDH_ANON_WITH_NULL_SHA => 0xc015,
            Self::TLS_ECDH_ANON_WITH_RC4_128_SHA => 0xc016,
            Self::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA => 0xc017,
            Self::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA => 0xc018,
            Self::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA => 0xc019,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc025,
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc026,
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => 0xc029,
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => 0xc02a,
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,
            Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02d,
            Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02e,
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,
            Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => 0xc031,
            Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => 0xc032,
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,
            Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xccaa,
            Self::UNKNOWN(v) => v,
        }
    }

    /// Get the hash length for this cipher suite
    pub fn hash_length(self) -> usize {
        match self {
            // SHA-256 based suites
            Self::TLS13_AES_128_GCM_SHA256
            | Self::TLS13_CHACHA20_POLY1305_SHA256
            | Self::TLS13_AES_128_CCM_SHA256
            | Self::TLS13_AES_128_CCM_8_SHA256
            | Self::TLS_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_PSK_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 32,
            // SHA-384 based suites
            Self::TLS13_AES_256_GCM_SHA384
            | Self::TLS_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_RSA_WITH_AES_256_CBC_SHA256
            | Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_PSK_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => 48,
            // SHA-1 based suites
            Self::TLS_RSA_WITH_NULL_SHA
            | Self::TLS_RSA_WITH_RC4_128_SHA
            | Self::TLS_RSA_WITH_DES_CBC_SHA
            | Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_RSA_WITH_AES_128_CBC_SHA
            | Self::TLS_RSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 20,
            // MD5 based suites
            Self::TLS_RSA_WITH_NULL_MD5 | Self::TLS_RSA_WITH_RC4_128_MD5 => 16,
            // Unknown defaults to SHA-256
            Self::UNKNOWN(_) => 32,
            // Other suites default to SHA-256
            _ => 32,
        }
    }

    /// Get the key length and IV length for this cipher suite
    ///
    /// For TLS 1.2 AEAD suites, returns (key_len, salt_len) where salt_len is 4.
    /// For TLS 1.3 suites, returns (key_len, iv_len) where iv_len is 12.
    pub fn key_iv_length(self) -> (usize, usize) {
        match self {
            // TLS 1.3 AES-128-GCM (iv_len = 12)
            Self::TLS13_AES_128_GCM_SHA256
            | Self::TLS13_AES_128_CCM_SHA256
            | Self::TLS13_AES_128_CCM_8_SHA256 => (16, 12),
            // TLS 1.3 AES-256-GCM (iv_len = 12)
            Self::TLS13_AES_256_GCM_SHA384 => (32, 12),
            // TLS 1.3 ChaCha20-Poly1305 (iv_len = 12)
            // TLS 1.2 ChaCha20-Poly1305 (iv_len = 12)
            Self::TLS13_CHACHA20_POLY1305_SHA256
            | Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (32, 12),
            // TLS 1.2 AES-128-GCM (salt_len = 4)
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_PSK_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => (16, 4),
            // TLS 1.2 AES-256-GCM (salt_len = 4)
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_PSK_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => (32, 4),
            // AES-128-CBC
            Self::TLS_RSA_WITH_AES_128_CBC_SHA
            | Self::TLS_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
            | Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
            | Self::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA => (16, 16),
            // AES-256-CBC
            Self::TLS_RSA_WITH_AES_256_CBC_SHA
            | Self::TLS_RSA_WITH_AES_256_CBC_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
            | Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
            | Self::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA => (32, 16),
            // 3DES
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
            | Self::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA => (24, 8),
            // DES
            Self::TLS_RSA_WITH_DES_CBC_SHA => (8, 8),
            // RC4
            Self::TLS_RSA_WITH_RC4_128_MD5
            | Self::TLS_RSA_WITH_RC4_128_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
            | Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA
            | Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA
            | Self::TLS_ECDH_RSA_WITH_RC4_128_SHA
            | Self::TLS_ECDH_ANON_WITH_RC4_128_SHA => (16, 0),
            // NULL
            Self::TLS_NULL_WITH_NULL_NULL
            | Self::TLS_RSA_WITH_NULL_MD5
            | Self::TLS_RSA_WITH_NULL_SHA
            | Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA
            | Self::TLS_ECDHE_RSA_WITH_NULL_SHA
            | Self::TLS_ECDH_ECDSA_WITH_NULL_SHA
            | Self::TLS_ECDH_RSA_WITH_NULL_SHA
            | Self::TLS_ECDH_ANON_WITH_NULL_SHA => (0, 0),
            // SCSV (Signaling Cipher Suite Value) - not a real cipher
            Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => (0, 0),
            // Unknown defaults to AES-128-GCM
            Self::UNKNOWN(_) => (16, 12),
        }
    }

    /// Check if this is a TLS 1.3 cipher suite
    pub fn is_tls13(self) -> bool {
        matches!(
            self,
            Self::TLS13_AES_128_GCM_SHA256
                | Self::TLS13_AES_256_GCM_SHA384
                | Self::TLS13_CHACHA20_POLY1305_SHA256
                | Self::TLS13_AES_128_CCM_SHA256
                | Self::TLS13_AES_128_CCM_8_SHA256
        )
    }

    /// Check if this is an AEAD cipher suite
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::TLS13_AES_128_GCM_SHA256
                | Self::TLS13_AES_256_GCM_SHA384
                | Self::TLS13_CHACHA20_POLY1305_SHA256
                | Self::TLS13_AES_128_CCM_SHA256
                | Self::TLS13_AES_128_CCM_8_SHA256
                | Self::TLS_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_PSK_WITH_AES_128_GCM_SHA256
                | Self::TLS_PSK_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                | Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
    }

    /// Get the authentication tag length for this cipher suite
    ///
    /// Returns 0 for non-AEAD cipher suites.
    pub fn tag_length(self) -> usize {
        match self {
            // AES-GCM and ChaCha20-Poly1305 use 16-byte tags
            Self::TLS13_AES_128_GCM_SHA256
            | Self::TLS13_AES_256_GCM_SHA384
            | Self::TLS13_CHACHA20_POLY1305_SHA256
            | Self::TLS_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_PSK_WITH_AES_128_GCM_SHA256
            | Self::TLS_PSK_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
            | Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
            | Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 16,
            // AES-128-CCM uses 16-byte tag
            Self::TLS13_AES_128_CCM_SHA256 => 16,
            // AES-128-CCM-8 uses 8-byte tag
            Self::TLS13_AES_128_CCM_8_SHA256 => 8,
            // Non-AEAD suites return 0
            _ => 0,
        }
    }

    /// Check if this cipher suite needs explicit nonce (TLS 1.2 AEAD)
    ///
    /// TLS 1.2 AEAD suites (GCM/CCM) prepend 8-byte explicit nonce to ciphertext.
    /// TLS 1.3 suites and TLS 1.2 ChaCha20-Poly1305 do not need explicit nonce.
    pub fn needs_explicit_nonce(self) -> bool {
        // Only TLS 1.2 GCM/CCM suites need explicit nonce
        // TLS 1.2 ChaCha20-Poly1305 (RFC 7905) does not use explicit nonce
        matches!(
            self,
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_PSK_WITH_AES_128_GCM_SHA256
                | Self::TLS_PSK_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
                | Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
                | Self::TLS13_AES_128_CCM_SHA256
                | Self::TLS13_AES_128_CCM_8_SHA256
        )
    }

    /// Get the TLS version for this cipher suite
    pub fn version(self) -> TlsVersion {
        if self.is_tls13() {
            TlsVersion::Tls13
        } else {
            TlsVersion::Tls12
        }
    }
}

impl From<TlsCipherSuiteID> for CipherSuite {
    fn from(id: TlsCipherSuiteID) -> Self {
        CipherSuite::from_u16(id.into())
    }
}

impl From<CipherSuite> for TlsCipherSuiteID {
    fn from(suite: CipherSuite) -> Self {
        TlsCipherSuiteID(suite.to_u16())
    }
}

// ============================================================================
// Unit tests for CipherSuite
// ============================================================================

#[cfg(test)]
mod cipher_suite_tests {
    use super::*;

    #[test]
    fn test_cipher_suite_from_u16() {
        assert_eq!(
            CipherSuite::from_u16(0x1301),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );
        assert_eq!(
            CipherSuite::from_u16(0x1302),
            CipherSuite::TLS13_AES_256_GCM_SHA384
        );
        assert_eq!(
            CipherSuite::from_u16(0x1303),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(
            CipherSuite::from_u16(0xcca8),
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        );
        assert!(matches!(
            CipherSuite::from_u16(0xffff),
            CipherSuite::UNKNOWN(0xffff)
        ));
    }

    #[test]
    fn test_cipher_suite_to_u16() {
        assert_eq!(CipherSuite::TLS13_AES_128_GCM_SHA256.to_u16(), 0x1301);
        assert_eq!(CipherSuite::TLS13_AES_256_GCM_SHA384.to_u16(), 0x1302);
        assert_eq!(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.to_u16(), 0x1303);
        assert_eq!(
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.to_u16(),
            0xcca8
        );
        assert_eq!(CipherSuite::UNKNOWN(0xffff).to_u16(), 0xffff);
    }

    #[test]
    fn test_cipher_suite_hash_length() {
        assert_eq!(CipherSuite::TLS13_AES_128_GCM_SHA256.hash_length(), 32);
        assert_eq!(
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.hash_length(),
            32
        );
        assert_eq!(CipherSuite::TLS13_AES_256_GCM_SHA384.hash_length(), 48);
    }

    #[test]
    fn test_cipher_suite_key_iv_length() {
        assert_eq!(
            CipherSuite::TLS13_AES_128_GCM_SHA256.key_iv_length(),
            (16, 12)
        );
        assert_eq!(
            CipherSuite::TLS13_AES_256_GCM_SHA384.key_iv_length(),
            (32, 12)
        );
        assert_eq!(
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.key_iv_length(),
            (32, 12)
        );
    }

    #[test]
    fn test_cipher_suite_is_tls13() {
        assert!(CipherSuite::TLS13_AES_128_GCM_SHA256.is_tls13());
        assert!(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.is_tls13());
        assert!(!CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_tls13());
    }

    #[test]
    fn test_cipher_suite_is_aead() {
        assert!(CipherSuite::TLS13_AES_128_GCM_SHA256.is_aead());
        assert!(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.is_aead());
        assert!(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.is_aead());
        assert!(!CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.is_aead());
    }

    #[test]
    fn test_cipher_suite_conversion_with_tls_parser() {
        let id = TlsCipherSuiteID(0x1301);
        let suite: CipherSuite = id.into();
        assert_eq!(suite, CipherSuite::TLS13_AES_128_GCM_SHA256);

        let back: TlsCipherSuiteID = suite.into();
        assert_eq!(back, TlsCipherSuiteID(0x1301));
    }
}

// ============================================================================
// Unit tests for CurveType
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_type_from_u16() {
        assert_eq!(CurveType::from_u16(0x0017), Some(CurveType::Secp256r1));
        assert_eq!(CurveType::from_u16(0x0018), Some(CurveType::Secp384r1));
        assert_eq!(CurveType::from_u16(0x0019), Some(CurveType::Secp521r1));
        assert_eq!(CurveType::from_u16(0x001D), Some(CurveType::X25519));
        assert_eq!(CurveType::from_u16(0x001E), Some(CurveType::X448));
        assert_eq!(CurveType::from_u16(0x0000), None);
    }

    #[test]
    fn test_curve_type_to_u16() {
        assert_eq!(CurveType::Secp256r1.to_u16(), 0x0017);
        assert_eq!(CurveType::Secp384r1.to_u16(), 0x0018);
        assert_eq!(CurveType::Secp521r1.to_u16(), 0x0019);
        assert_eq!(CurveType::X25519.to_u16(), 0x001D);
        assert_eq!(CurveType::X448.to_u16(), 0x001E);
    }

    #[test]
    fn test_curve_type_key_share_length() {
        assert_eq!(CurveType::Secp256r1.key_share_length(), 65);
        assert_eq!(CurveType::Secp384r1.key_share_length(), 97);
        assert_eq!(CurveType::Secp521r1.key_share_length(), 133);
        assert_eq!(CurveType::X25519.key_share_length(), 32);
        assert_eq!(CurveType::X448.key_share_length(), 56);
    }

    #[test]
    fn test_curve_type_shared_secret_length() {
        assert_eq!(CurveType::Secp256r1.shared_secret_length(), 32);
        assert_eq!(CurveType::Secp384r1.shared_secret_length(), 48);
        assert_eq!(CurveType::Secp521r1.shared_secret_length(), 66);
        assert_eq!(CurveType::X25519.shared_secret_length(), 32);
        assert_eq!(CurveType::X448.shared_secret_length(), 56);
    }

    #[test]
    fn test_curve_type_private_key_length() {
        assert_eq!(CurveType::Secp256r1.private_key_length(), 32);
        assert_eq!(CurveType::Secp384r1.private_key_length(), 48);
        assert_eq!(CurveType::Secp521r1.private_key_length(), 66);
        assert_eq!(CurveType::X25519.private_key_length(), 32);
        assert_eq!(CurveType::X448.private_key_length(), 56);
    }

    #[test]
    fn test_curve_type_public_key_lengths() {
        // P-256
        assert_eq!(CurveType::Secp256r1.public_key_uncompressed_length(), 65);
        assert_eq!(CurveType::Secp256r1.public_key_compressed_length(), 33);
        assert!(CurveType::Secp256r1.is_valid_public_key_length(65));
        assert!(CurveType::Secp256r1.is_valid_public_key_length(33));
        assert!(!CurveType::Secp256r1.is_valid_public_key_length(64));

        // P-384
        assert_eq!(CurveType::Secp384r1.public_key_uncompressed_length(), 97);
        assert_eq!(CurveType::Secp384r1.public_key_compressed_length(), 49);
        assert!(CurveType::Secp384r1.is_valid_public_key_length(97));
        assert!(CurveType::Secp384r1.is_valid_public_key_length(49));

        // P-521
        assert_eq!(CurveType::Secp521r1.public_key_uncompressed_length(), 133);
        assert_eq!(CurveType::Secp521r1.public_key_compressed_length(), 67);
        assert!(CurveType::Secp521r1.is_valid_public_key_length(133));
        assert!(CurveType::Secp521r1.is_valid_public_key_length(67));

        // X25519 (no compression, same length)
        assert_eq!(CurveType::X25519.public_key_uncompressed_length(), 32);
        assert_eq!(CurveType::X25519.public_key_compressed_length(), 32);
        assert!(CurveType::X25519.is_valid_public_key_length(32));
        assert!(!CurveType::X25519.is_valid_public_key_length(33));

        // X448 (no compression, same length)
        assert_eq!(CurveType::X448.public_key_uncompressed_length(), 56);
        assert_eq!(CurveType::X448.public_key_compressed_length(), 56);
        assert!(CurveType::X448.is_valid_public_key_length(56));
        assert!(!CurveType::X448.is_valid_public_key_length(57));
    }

    #[test]
    fn test_curve_type_is_valid_private_key_length() {
        assert!(CurveType::Secp256r1.is_valid_private_key_length(32));
        assert!(!CurveType::Secp256r1.is_valid_private_key_length(31));
        assert!(!CurveType::Secp256r1.is_valid_private_key_length(33));

        assert!(CurveType::Secp384r1.is_valid_private_key_length(48));
        assert!(!CurveType::Secp384r1.is_valid_private_key_length(47));

        // P-521 supports both 65 and 66 byte private keys
        // 65 bytes when the leading bit is 0, 66 bytes otherwise
        assert!(CurveType::Secp521r1.is_valid_private_key_length(66));
        assert!(CurveType::Secp521r1.is_valid_private_key_length(65));
        assert!(!CurveType::Secp521r1.is_valid_private_key_length(64));

        assert!(CurveType::X25519.is_valid_private_key_length(32));
        assert!(!CurveType::X25519.is_valid_private_key_length(31));

        assert!(CurveType::X448.is_valid_private_key_length(56));
        assert!(!CurveType::X448.is_valid_private_key_length(55));
    }
}
