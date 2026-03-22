//! TLS Decryptor basic type definitions

pub use rustls::CipherSuite;

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2 (RFC 5246)
    Tls12,
    /// TLS 1.3 (RFC 8446)
    Tls13,
}

impl TlsVersion {
    /// Convert from wire format to TlsVersion
    pub fn from_wire(version: u16) -> Option<Self> {
        match version {
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }

    /// Convert to wire format
    pub fn to_wire(self) -> u16 {
        match self {
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }
}

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

    /// Get cipher suite ID (u16 format)
    pub fn cipher_suite_id(&self) -> u16 {
        self.cipher_suite.into()
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

/// TLS record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// ChangeCipherSpec (TLS 1.2)
    ChangeCipherSpec = 20,
    /// Alert
    Alert = 21,
    /// Handshake
    Handshake = 22,
    /// Application Data
    ApplicationData = 23,
}

impl RecordType {
    /// Convert from byte to RecordType
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// TLS record header
#[derive(Debug, Clone)]
pub struct RecordHeader {
    /// Record type
    pub content_type: RecordType,
    /// TLS version
    pub version: u16,
    /// Payload length
    pub length: u16,
}

impl RecordHeader {
    /// Parse record header (5 bytes)
    pub fn parse(data: &[u8]) -> crate::error::Result<Self> {
        if data.len() < 5 {
            return Err(crate::error::DecryptError::InsufficientData);
        }

        let content_type = RecordType::from_byte(data[0])
            .ok_or(crate::error::DecryptError::InvalidRecordHeader)?;
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);

        Ok(Self {
            content_type,
            version,
            length,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = self.content_type.to_byte();
        bytes[1..3].copy_from_slice(&self.version.to_be_bytes());
        bytes[3..5].copy_from_slice(&self.length.to_be_bytes());
        bytes
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
