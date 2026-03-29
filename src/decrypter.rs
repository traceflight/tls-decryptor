//! TLS record decrypter

use crate::cipher::{CipherContext, CipherRegistry};
use crate::error::{DecryptError, Result};
use crate::types::{Direction, SessionKey, TlsRecordType, parse_tls_record_header};

/// TLS record decrypter
///
/// Decrypts TLS Application Data records using session keys
pub struct TlsDecrypter {
    session_key: SessionKey,
    cipher: std::sync::Arc<dyn CipherContext>,
    /// Sequence number for client-to-server direction
    client_to_server_seq: u64,
    /// Sequence number for server-to-client direction
    server_to_client_seq: u64,
}

impl TlsDecrypter {
    /// Create a new decrypter instance
    pub fn new(session_key: SessionKey) -> Result<Self> {
        let cipher = CipherRegistry::global().try_get(session_key.cipher_suite)?;

        Ok(Self {
            session_key,
            cipher,
            client_to_server_seq: 0,
            server_to_client_seq: 0,
        })
    }

    /// Create a decrypter instance with specified initial sequence numbers
    pub fn with_sequence_numbers(
        session_key: SessionKey,
        client_to_server_seq: u64,
        server_to_client_seq: u64,
    ) -> Result<Self> {
        let cipher = CipherRegistry::global().try_get(session_key.cipher_suite)?;

        Ok(Self {
            session_key,
            cipher,
            client_to_server_seq,
            server_to_client_seq,
        })
    }

    /// Decrypt a single TLS Application Data record
    ///
    /// # Arguments
    /// - `encrypted_record`: Encrypted TLS record (including record header and payload)
    /// - `direction`: Data flow direction (determines which key to use)
    ///
    /// # Returns
    /// Decrypted application data
    ///
    /// # Example
    /// ```rust,ignore
    /// use tls_decryptor::{TlsDecrypter, SessionKey, Direction};
    ///
    /// # fn example() -> Result<(), tls_decryptor::error::DecryptError> {
    /// // Session key derived from TLS handshake
    /// let session_key: SessionKey = /* derived from handshake */;
    ///
    /// // Create decrypter with the session key
    /// let mut decrypter = TlsDecrypter::new(session_key)?;
    ///
    /// // Decrypt a TLS Application Data record
    /// let encrypted_bytes = /* TLS record bytes */;
    /// let plaintext = decrypter.decrypt_application_data(
    ///     &encrypted_bytes,
    ///     Direction::ClientToServer,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_application_data(
        &mut self,
        encrypted_record: &[u8],
        direction: Direction,
    ) -> Result<Vec<u8>> {
        // Parse record header
        let (remaining, header) = parse_tls_record_header(encrypted_record)
            .map_err(|_| DecryptError::InvalidRecordHeader)?;

        // Validate record type
        if header.record_type != TlsRecordType::ApplicationData {
            return Err(DecryptError::InvalidRecordHeader);
        }

        // Extract payload (skip 5-byte record header)
        if remaining.len() < header.len as usize {
            return Err(DecryptError::InsufficientData);
        }

        let payload = &remaining[..header.len as usize];

        // Get current sequence number
        let sequence_number = self.get_sequence_number(direction);

        // Construct AAD (Additional Authenticated Data)
        // AAD = record_header (5 bytes)
        let aad = &encrypted_record[..5];

        // Decrypt payload
        let plaintext = self.decrypt_payload(payload, direction, sequence_number, aad)?;

        // Update sequence number
        self.increment_sequence_number(direction);

        Ok(plaintext)
    }

    /// Decrypt raw payload (without record header)
    ///
    /// # Arguments
    /// - `encrypted_payload`: Encrypted payload part (without 5-byte record header)
    /// - `direction`: Data flow direction
    /// - `sequence_number`: Sequence number
    /// - `additional_data`: AEAD additional data (record header)
    pub fn decrypt_payload(
        &self,
        encrypted_payload: &[u8],
        direction: Direction,
        sequence_number: u64,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.session_key.get_write_key(direction);
        let iv = self.session_key.get_write_iv(direction);

        self.cipher
            .decrypt(key, iv, encrypted_payload, additional_data, sequence_number)
    }

    /// Decrypt raw payload (without record header), with automatic sequence number management
    ///
    /// # Arguments
    /// - `encrypted_payload`: Encrypted payload part (without 5-byte record header)
    /// - `direction`: Data flow direction
    /// - `additional_data`: AEAD additional data (record header)
    pub fn decrypt_payload_auto_seq(
        &mut self,
        encrypted_payload: &[u8],
        direction: Direction,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let sequence_number = self.get_sequence_number(direction);
        let result = self.decrypt_payload(
            encrypted_payload,
            direction,
            sequence_number,
            additional_data,
        )?;
        self.increment_sequence_number(direction);
        Ok(result)
    }

    /// Get current sequence number for specified direction
    fn get_sequence_number(&self, direction: Direction) -> u64 {
        match direction {
            Direction::ClientToServer => self.client_to_server_seq,
            Direction::ServerToClient => self.server_to_client_seq,
        }
    }

    /// Increment sequence number for specified direction
    ///
    /// # Panics
    /// Panics if sequence number overflows (reaches 2^64-1).
    /// According to RFC 8446 Section 5.4, the connection must be terminated
    /// when the sequence number would wrap.
    fn increment_sequence_number(&mut self, direction: Direction) {
        let seq = match direction {
            Direction::ClientToServer => &mut self.client_to_server_seq,
            Direction::ServerToClient => &mut self.server_to_client_seq,
        };

        *seq = seq
            .checked_add(1)
            .expect("Sequence number overflow - connection must be terminated per RFC 8446");
    }

    /// Set sequence number for specified direction
    pub fn set_sequence_number(&mut self, direction: Direction, seq: u64) {
        match direction {
            Direction::ClientToServer => self.client_to_server_seq = seq,
            Direction::ServerToClient => self.server_to_client_seq = seq,
        }
    }

    /// Get current client-to-server sequence number
    pub fn client_to_server_sequence(&self) -> u64 {
        self.client_to_server_seq
    }

    /// Get current server-to-client sequence number
    pub fn server_to_client_sequence(&self) -> u64 {
        self.server_to_client_seq
    }

    /// Reset sequence numbers for both directions
    pub fn reset_sequence_numbers(&mut self) {
        self.client_to_server_seq = 0;
        self.server_to_client_seq = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CipherSuite, TlsVersion};

    #[test]
    fn test_decrypter_creation() {
        let session_key = SessionKey::new(
            TlsVersion::Tls13,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 12],
        );

        let decrypter = TlsDecrypter::new(session_key);
        assert!(decrypter.is_ok());
    }

    #[test]
    fn test_sequence_number_management() {
        let session_key = SessionKey::new(
            TlsVersion::Tls13,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 12],
            vec![0u8; 12],
        );

        let result = TlsDecrypter::new(session_key);
        assert!(result.is_ok(), "Failed to create decrypter");
        let Ok(mut decrypter) = result else {
            return;
        };

        assert_eq!(decrypter.client_to_server_sequence(), 0);
        assert_eq!(decrypter.server_to_client_sequence(), 0);

        decrypter.set_sequence_number(Direction::ClientToServer, 100);
        assert_eq!(decrypter.client_to_server_sequence(), 100);

        decrypter.reset_sequence_numbers();
        assert_eq!(decrypter.client_to_server_sequence(), 0);
    }
}
