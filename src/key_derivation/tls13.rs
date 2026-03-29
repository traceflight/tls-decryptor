//! TLS 1.3 Key Deriver
//!
//! This module provides a stateful TLS 1.3 key derivation process
//! that processes TLS messages sequentially and derives keys at
//! appropriate points in the handshake.
//!
//! # Features
//! - Supports standard TLS 1.3 handshake
//! - Supports Hello Retry Request (HRR) scenario
//! - Returns intermediate events to notify caller of key derivation progress
//! - Decrypts encrypted handshake messages internally using CipherRegistry
//!
//! # Example
//! ```rust,ignore
//! use tls_decryptor::key_derivation::Tls13KeyDeriver;
//! use tls_parser::{TlsMessage, TlsMessageHandshake};
//!
//! let mut deriver = Tls13KeyDeriver::new(shared_secret);
//!
//! // Feed all TLS messages (always provide 5-byte record header)
//! for record in records {
//!     let header = &record[..5]; // 5-byte record header
//!     let (_, msg) = tls_parser::parse_tls_record(&record[5..])?; // Parse payload
//!
//!     if let Some(event) = deriver.feed_message(&msg, header)? {
//!         match event {
//!             DeriverEvent::HandshakeKeysDerived { .. } => {
//!                 // Now can decrypt encrypted handshake messages
//!             }
//!             DeriverEvent::ApplicationKeysDerived { session_key, .. } => {
//!                 // Application keys ready
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//!
//! let (session_key, handshake_hash) = deriver.finish()?;
//! ```

use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use tls_parser::{TlsMessage, TlsMessageHandshake};

use crate::cipher::CipherRegistry;
use crate::error::{DecryptError, Result};
use crate::types::{CipherSuite, SessionKey, TlsCipherSuiteID, TlsVersion};

/// Hello Retry Request data
#[derive(Debug, Clone)]
pub struct HrrData {
    /// Server's selected key share group
    pub selected_group: u16,
    /// Optional cookie for verification
    pub cookie: Option<Vec<u8>>,
}

/// TLS 1.3 key derivation events
///
/// Used to notify the caller of key derivation progress
#[derive(Debug, Clone)]
pub enum DeriverEvent {
    /// ClientHello received
    ClientHelloReceived { client_random: [u8; 32] },

    /// Hello Retry Request received, need to resend ClientHello
    HelloRetryRequestReceived {
        selected_group: u16,
        cookie: Option<Vec<u8>>,
    },

    /// ServerHello received, handshake keys derived
    HandshakeKeysDerived {
        server_random: [u8; 32],
        cipher_suite: CipherSuite,
        server_handshake_key: Vec<u8>,
        server_handshake_iv: Vec<u8>,
    },

    /// EncryptedExtensions received (decrypted from Application Data)
    EncryptedExtensionsReceived,

    /// Certificate received (decrypted from Application Data)
    CertificateReceived,

    /// CertificateRequest received (optional, for mutual authentication)
    CertificateRequestReceived,

    /// CertificateVerify received (decrypted from Application Data)
    CertificateVerifyReceived,

    /// Finished received (decrypted from Application Data), application keys derived
    ApplicationKeysDerived {
        session_key: SessionKey,
        handshake_hash: Vec<u8>,
    },
}

/// TLS 1.3 key deriver internal state
#[derive(Debug)]
pub enum DeriverState {
    /// Initial state, waiting for ClientHello
    WaitingClientHello,

    /// ClientHello received, waiting for ServerHello or HelloRetryRequest
    WaitingServerHelloOrHrr { client_hello_random: [u8; 32] },

    /// HelloRetryRequest received, waiting for second ClientHello
    WaitingClientHello2 {
        client_hello_random: [u8; 32],
        hrr_data: HrrData,
    },

    /// Second ClientHello received, waiting for ServerHello
    WaitingServerHello2 {
        client_hello_random: [u8; 32],
        hrr_data: HrrData,
    },

    /// ServerHello received, waiting for encrypted handshake messages
    /// Handshake keys have been derived
    WaitingEncryptedExtensions {
        server_hello_random: [u8; 32],
        cipher_suite: CipherSuite,
        handshake_secret: Vec<u8>,
        server_handshake_key: Vec<u8>,
        server_handshake_iv: Vec<u8>,
    },

    /// Collecting encrypted handshake messages
    CollectingHandshake {
        server_hello_random: [u8; 32],
        cipher_suite: CipherSuite,
        handshake_secret: Vec<u8>,
        server_handshake_key: Vec<u8>,
        server_handshake_iv: Vec<u8>,
    },

    /// Finished received, deriving application keys
    DerivingApplicationKeys {
        server_hello_random: [u8; 32],
        cipher_suite: CipherSuite,
        handshake_secret: Vec<u8>,
    },

    /// Key derivation completed
    Completed {
        session_key: SessionKey,
        handshake_hash: Vec<u8>,
    },
}

/// TLS 1.3 Handshake Hash Accumulator
///
/// Accumulates handshake message bytes for computing the handshake hash.
/// This is a re-implementation that does not depend on HandshakeHashCalculator.
#[derive(Debug, Clone)]
pub struct HandshakeHashAccumulator {
    /// Accumulated handshake message bytes (including handshake headers)
    messages: Vec<u8>,
    /// Negotiated cipher suite (extracted from ServerHello)
    cipher_suite: Option<CipherSuite>,
}

impl HandshakeHashAccumulator {
    /// Create a new handshake hash accumulator
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            cipher_suite: None,
        }
    }

    /// Add a handshake message to the accumulator
    ///
    /// # Arguments
    /// - `msg_data`: Complete handshake message data (including 4-byte handshake header)
    /// - `cipher_suite`: Optional cipher suite (extracted from ServerHello)
    pub fn add_message(&mut self, msg_data: &[u8], cipher_suite: Option<CipherSuite>) {
        self.messages.extend_from_slice(msg_data);
        if let Some(suite) = cipher_suite {
            self.cipher_suite = Some(suite);
        }
    }

    /// Compute the handshake hash
    ///
    /// # Returns
    /// The computed handshake hash based on the negotiated cipher suite
    pub fn compute_hash(&self) -> Result<Vec<u8>> {
        let cipher_suite = self.cipher_suite.ok_or(DecryptError::KeyDerivationFailed(
            "Cipher suite not set".to_string(),
        ))?;

        let suite = CipherSuite::from(cipher_suite);
        match suite {
            CipherSuite::Tls13Aes128GcmSha256 | CipherSuite::Tls13ChaCha20Poly1305Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&self.messages);
                Ok(hasher.finalize().to_vec())
            }
            CipherSuite::Tls13Aes256GcmSha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&self.messages);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(DecryptError::UnsupportedCipherSuite(cipher_suite.to_u16())),
        }
    }

    /// Get the accumulated handshake messages
    pub fn messages(&self) -> &[u8] {
        &self.messages
    }

    /// Get the negotiated cipher suite
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Reset the accumulator
    pub fn reset(&mut self) {
        self.messages.clear();
        self.cipher_suite = None;
    }
}

impl Default for HandshakeHashAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS 1.3 Key Deriver
///
/// A stateful object that processes TLS 1.3 messages sequentially
/// and derives keys at appropriate points in the handshake.
/// Supports standard handshake and Hello Retry Request scenario.
///
/// # Note
/// This deriver accepts `TlsMessage` for all messages.
/// For encrypted handshake messages (ApplicationData records), pass the
/// `TlsMessage::ApplicationData` variant with the raw record bytes.
pub struct Tls13KeyDeriver {
    /// Current state
    state: DeriverState,
    /// Handshake hash accumulator
    handshake_hash: HandshakeHashAccumulator,
    /// ECDHE shared secret
    shared_secret: Vec<u8>,
    /// Whether HRR has been received
    hrr_received: bool,
    /// Sequence number for decrypting encrypted handshake messages
    decrypt_seq: u64,
}

impl Tls13KeyDeriver {
    /// Create a new TLS 1.3 key deriver
    ///
    /// # Arguments
    /// - `shared_secret`: ECDHE shared secret (computed from key exchange)
    ///
    /// # Returns
    /// A new deriver instance
    pub fn new(shared_secret: Vec<u8>) -> Self {
        Self {
            state: DeriverState::WaitingClientHello,
            handshake_hash: HandshakeHashAccumulator::new(),
            shared_secret,
            hrr_received: false,
            decrypt_seq: 0,
        }
    }

    /// Feed a TLS message for processing.
    ///
    /// # Arguments
    /// - `msg`: Parsed `TlsMessage` from tls-parser
    /// - `record_header`: The 5-byte TLS record header. This is required for all messages
    ///   as it's used for AEAD decryption of encrypted handshake messages.
    ///
    /// # Returns
    /// - `Ok(Some(DeriverEvent))` if processing succeeded with an event
    /// - `Ok(None)` if processing succeeded but no event
    /// - `Err(DecryptError)` if processing failed
    ///
    /// # Note
    /// This method handles all TLS message types:
    /// - Plaintext handshake messages (ClientHello, ServerHello) are processed directly
    /// - `ApplicationData` records containing encrypted handshake messages are decrypted
    ///   internally using the derived handshake keys
    ///
    /// # Example
    /// ```rust,ignore
    /// // Parse a TLS record
    /// let record = /* raw record bytes */;
    /// let header = &record[..5]; // 5-byte record header
    /// let (_, msg) = tls_parser::parse_tls_record(&record[5..])?; // Parse payload
    /// deriver.feed_message(&msg, header)?;
    /// ```
    pub fn feed_message(
        &mut self,
        msg: &TlsMessage<'_>,
        record_header: &[u8],
    ) -> Result<Option<DeriverEvent>> {
        match msg {
            TlsMessage::Handshake(hs_msg) => self.process_handshake_message(hs_msg),
            TlsMessage::ChangeCipherSpec => {
                // Ignore ChangeCipherSpec in TLS 1.3
                Ok(None)
            }
            TlsMessage::Alert(_) => {
                // Ignore alerts
                Ok(None)
            }
            TlsMessage::ApplicationData(app_data) => {
                // ApplicationData records contain encrypted handshake messages
                // Decrypt using the provided record header
                self.process_application_data_with_aad(&app_data.blob, record_header)
            }
            TlsMessage::Heartbeat(_) => {
                // Ignore heartbeat
                Ok(None)
            }
        }
    }

    /// Process ApplicationData payload with AAD (record header)
    fn process_application_data_with_aad(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Option<DeriverEvent>> {
        // Check if we have handshake keys ready
        let (cipher_suite, server_handshake_key, server_handshake_iv) = match &self.state {
            DeriverState::WaitingEncryptedExtensions {
                cipher_suite,
                server_handshake_key,
                server_handshake_iv,
                ..
            }
            | DeriverState::CollectingHandshake {
                cipher_suite,
                server_handshake_key,
                server_handshake_iv,
                ..
            } => (
                *cipher_suite,
                server_handshake_key.clone(),
                server_handshake_iv.clone(),
            ),
            _ => {
                return Err(DecryptError::KeyDerivationFailed(
                    "Handshake keys not ready for decryption".to_string(),
                ));
            }
        };

        // Get cipher context
        let cipher = CipherRegistry::global().try_get(cipher_suite)?;

        // Decrypt the record
        let plaintext = cipher.decrypt(
            &server_handshake_key,
            &server_handshake_iv,
            ciphertext,
            aad,
            self.decrypt_seq,
        )?;

        // Increment sequence number for next decryption
        self.decrypt_seq = self.decrypt_seq.checked_add(1).unwrap_or(0);

        // In TLS 1.3, the decrypted plaintext has the following structure:
        // - content_type (1 byte)
        // - payload (variable)
        // - padding (variable, zeros)
        // The content_type indicates the actual type of the inner content

        if plaintext.is_empty() {
            return Err(DecryptError::InsufficientData);
        }

        let content_type = plaintext[0];
        let payload = &plaintext[1..];

        // Remove trailing padding (zeros) and the content type byte at the end
        let mut end = payload.len();
        while end > 0 && payload[end - 1] == 0 {
            end -= 1;
        }
        // Also remove the trailing content type (last non-zero byte before padding)
        if end > 0 {
            end -= 1;
        }

        let inner_payload = &payload[..end];

        // The content_type should be 0x17 (Application Data) for encrypted handshake messages
        match content_type {
            0x17 => {
                // Application Data - contains encrypted handshake message
                self.parse_and_process_encrypted_handshake(inner_payload)
            }
            _ => {
                // Unknown content type
                Err(DecryptError::InvalidRecordHeader)
            }
        }
    }

    /// Parse and process an encrypted handshake message
    fn parse_and_process_encrypted_handshake(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<DeriverEvent>> {
        if payload.is_empty() {
            return Err(DecryptError::InvalidHandshakeMessage);
        }

        // Parse handshake message header
        let msg_type = payload[0];
        let msg_len =
            ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);

        if payload.len() < 4 + msg_len {
            return Err(DecryptError::InsufficientData);
        }

        let msg_data = &payload[..4 + msg_len];

        // Add to handshake hash (before processing to ensure correct order)
        self.handshake_hash.add_message(msg_data, None);

        // Process based on message type
        match msg_type {
            0x08 => self.process_encrypted_extensions_inner(),
            0x0b => self.process_certificate_inner(),
            0x0d => self.process_certificate_request_inner(),
            0x0f => self.process_certificate_verify_inner(),
            0x14 => self.process_finished_inner(msg_data),
            _ => Err(DecryptError::InvalidHandshakeMessage),
        }
    }

    /// Process a handshake message (plaintext)
    fn process_handshake_message(
        &mut self,
        msg: &TlsMessageHandshake<'_>,
    ) -> Result<Option<DeriverEvent>> {
        match msg {
            TlsMessageHandshake::ClientHello(ch) => self.process_client_hello(ch),
            TlsMessageHandshake::ServerHello(sh) => self.process_server_hello(sh),
            TlsMessageHandshake::HelloRetryRequest(hrr) => self.process_hello_retry_request(hrr),
            // These messages are encrypted in TLS 1.3, should not appear as plaintext
            TlsMessageHandshake::Certificate(_)
            | TlsMessageHandshake::CertificateRequest(_)
            | TlsMessageHandshake::CertificateVerify(_)
            | TlsMessageHandshake::Finished(_) => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "encrypted record".to_string(),
                got: "plaintext handshake message".to_string(),
            }),
            // ServerDone may appear in some tls-parser versions
            TlsMessageHandshake::ServerDone(_) => {
                // In TLS 1.3, this might be EncryptedExtensions
                // But it should be encrypted, so return error
                Err(DecryptError::UnexpectedHandshakeMessage {
                    expected: "encrypted record".to_string(),
                    got: "ServerDone".to_string(),
                })
            }
            // Ignore other handshake messages
            _ => Ok(None),
        }
    }

    /// Process ClientHello message
    fn process_client_hello(
        &mut self,
        ch: &tls_parser::TlsClientHelloContents<'_>,
    ) -> Result<Option<DeriverEvent>> {
        // Extract client random (32 bytes)
        let client_random: [u8; 32] = ch
            .random
            .try_into()
            .map_err(|_| DecryptError::InvalidHandshakeMessage)?;

        // Build handshake message data for hash accumulation
        let msg_data = build_client_hello_message(ch);
        self.handshake_hash.add_message(&msg_data, None);

        match &self.state {
            DeriverState::WaitingClientHello => {
                self.state = DeriverState::WaitingServerHelloOrHrr {
                    client_hello_random: client_random,
                };
                Ok(Some(DeriverEvent::ClientHelloReceived { client_random }))
            }
            DeriverState::WaitingClientHello2 { hrr_data, .. } => {
                // Second ClientHello after HRR
                let hrr_data = hrr_data.clone();
                self.state = DeriverState::WaitingServerHello2 {
                    client_hello_random: client_random,
                    hrr_data,
                };
                Ok(Some(DeriverEvent::ClientHelloReceived { client_random }))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "ServerHello or HRR".to_string(),
                got: "ClientHello".to_string(),
            }),
        }
    }

    /// Process ServerHello message
    fn process_server_hello(
        &mut self,
        sh: &tls_parser::TlsServerHelloContents<'_>,
    ) -> Result<Option<DeriverEvent>> {
        // Check if this is a HelloRetryRequest (random has special value)
        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE9, 0xA9, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];

        if sh.random == HRR_RANDOM {
            return Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "ClientHello".to_string(),
                got: "ServerHello with HRR random".to_string(),
            });
        }

        // Extract server random (32 bytes)
        let server_random: [u8; 32] = sh
            .random
            .try_into()
            .map_err(|_| DecryptError::InvalidHandshakeMessage)?;

        // Extract cipher suite
        let cipher_suite = CipherSuite::from(TlsCipherSuiteID(sh.cipher.0));

        // Build handshake message data for hash accumulation
        let msg_data = build_server_hello_message(sh);
        self.handshake_hash
            .add_message(&msg_data, Some(cipher_suite));

        // Get client_hello_random from current state
        let _client_hello_random = match &self.state {
            DeriverState::WaitingServerHelloOrHrr {
                client_hello_random,
            } => *client_hello_random,
            DeriverState::WaitingServerHello2 {
                client_hello_random,
                ..
            } => *client_hello_random,
            _ => {
                return Err(DecryptError::UnexpectedHandshakeMessage {
                    expected: "ClientHello".to_string(),
                    got: "ServerHello".to_string(),
                });
            }
        };

        // Derive handshake keys
        let cipher_suite = CipherSuite::from(cipher_suite);
        let (handshake_secret, server_handshake_key, server_handshake_iv) =
            self.derive_handshake_keys(&cipher_suite)?;

        self.state = DeriverState::WaitingEncryptedExtensions {
            server_hello_random: server_random,
            cipher_suite,
            handshake_secret,
            server_handshake_key: server_handshake_key.clone(),
            server_handshake_iv: server_handshake_iv.clone(),
        };

        Ok(Some(DeriverEvent::HandshakeKeysDerived {
            server_random,
            cipher_suite: CipherSuite::from(cipher_suite),
            server_handshake_key,
            server_handshake_iv,
        }))
    }

    /// Process HelloRetryRequest message
    fn process_hello_retry_request(
        &mut self,
        hrr: &tls_parser::TlsHelloRetryRequestContents<'_>,
    ) -> Result<Option<DeriverEvent>> {
        // Parse extensions to find key_share (selected_group) and cookie
        let (selected_group, cookie) = if let Some(ext_data) = hrr.ext {
            parse_hrr_extensions(ext_data)?
        } else {
            return Err(DecryptError::HrrError(
                "No extensions in HelloRetryRequest".to_string(),
            ));
        };

        self.hrr_received = true;

        // Get client_hello_random from current state
        let client_hello_random = match &self.state {
            DeriverState::WaitingServerHelloOrHrr {
                client_hello_random,
            } => *client_hello_random,
            _ => {
                return Err(DecryptError::UnexpectedHandshakeMessage {
                    expected: "ClientHello".to_string(),
                    got: "HelloRetryRequest".to_string(),
                });
            }
        };

        // Build handshake message data for hash accumulation
        let msg_data = build_hrr_message(hrr);
        self.handshake_hash.add_message(&msg_data, None);

        self.state = DeriverState::WaitingClientHello2 {
            client_hello_random,
            hrr_data: HrrData {
                selected_group,
                cookie: cookie.clone(),
            },
        };

        Ok(Some(DeriverEvent::HelloRetryRequestReceived {
            selected_group,
            cookie,
        }))
    }

    /// Process EncryptedExtensions message (inner, after decryption)
    fn process_encrypted_extensions_inner(&mut self) -> Result<Option<DeriverEvent>> {
        match &self.state {
            DeriverState::WaitingEncryptedExtensions {
                server_hello_random,
                cipher_suite,
                handshake_secret,
                server_handshake_key,
                server_handshake_iv,
            } => {
                self.state = DeriverState::CollectingHandshake {
                    server_hello_random: *server_hello_random,
                    cipher_suite: *cipher_suite,
                    handshake_secret: handshake_secret.clone(),
                    server_handshake_key: server_handshake_key.clone(),
                    server_handshake_iv: server_handshake_iv.clone(),
                };
                Ok(Some(DeriverEvent::EncryptedExtensionsReceived))
            }
            DeriverState::CollectingHandshake { .. } => {
                // Already collecting, just continue
                Ok(Some(DeriverEvent::EncryptedExtensionsReceived))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "ServerHello".to_string(),
                got: "EncryptedExtensions".to_string(),
            }),
        }
    }

    /// Process Certificate message (inner, after decryption)
    fn process_certificate_inner(&mut self) -> Result<Option<DeriverEvent>> {
        match &self.state {
            DeriverState::CollectingHandshake { .. }
            | DeriverState::WaitingEncryptedExtensions { .. } => {
                // Transition to CollectingHandshake if in WaitingEncryptedExtensions
                if let DeriverState::WaitingEncryptedExtensions {
                    server_hello_random,
                    cipher_suite,
                    handshake_secret,
                    server_handshake_key,
                    server_handshake_iv,
                } = &self.state
                {
                    self.state = DeriverState::CollectingHandshake {
                        server_hello_random: *server_hello_random,
                        cipher_suite: *cipher_suite,
                        handshake_secret: handshake_secret.clone(),
                        server_handshake_key: server_handshake_key.clone(),
                        server_handshake_iv: server_handshake_iv.clone(),
                    };
                }
                Ok(Some(DeriverEvent::CertificateReceived))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "EncryptedExtensions".to_string(),
                got: "Certificate".to_string(),
            }),
        }
    }

    /// Process CertificateRequest message (inner, after decryption)
    fn process_certificate_request_inner(&mut self) -> Result<Option<DeriverEvent>> {
        match &self.state {
            DeriverState::CollectingHandshake { .. } => {
                Ok(Some(DeriverEvent::CertificateRequestReceived))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "Certificate".to_string(),
                got: "CertificateRequest".to_string(),
            }),
        }
    }

    /// Process CertificateVerify message (inner, after decryption)
    fn process_certificate_verify_inner(&mut self) -> Result<Option<DeriverEvent>> {
        match &self.state {
            DeriverState::CollectingHandshake { .. } => {
                Ok(Some(DeriverEvent::CertificateVerifyReceived))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "Certificate".to_string(),
                got: "CertificateVerify".to_string(),
            }),
        }
    }

    /// Process Finished message (inner, after decryption)
    fn process_finished_inner(&mut self, _msg_data: &[u8]) -> Result<Option<DeriverEvent>> {
        match &self.state {
            DeriverState::CollectingHandshake {
                cipher_suite,
                handshake_secret,
                ..
            } => {
                // Derive application keys
                let cipher_suite = *cipher_suite;
                let handshake_secret = handshake_secret.clone();

                let (session_key, handshake_hash) =
                    self.derive_application_keys(cipher_suite, &handshake_secret)?;

                self.state = DeriverState::Completed {
                    session_key: session_key.clone(),
                    handshake_hash: handshake_hash.clone(),
                };

                Ok(Some(DeriverEvent::ApplicationKeysDerived {
                    session_key,
                    handshake_hash,
                }))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "CertificateVerify".to_string(),
                got: "Finished".to_string(),
            }),
        }
    }

    /// Derive handshake keys
    fn derive_handshake_keys(
        &self,
        cipher_suite: &CipherSuite,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let hash_len = cipher_suite.hash_length();

        // 1. Compute handshake_secret = HKDF-Extract(0, shared_secret)
        let zeros = vec![0u8; hash_len];
        let handshake_secret = hkdf_extract(&zeros, &self.shared_secret, cipher_suite)?;

        // 2. Get current handshake hash (ClientHello || ServerHello)
        let handshake_hash = self.handshake_hash.compute_hash()?;

        // 3. Derive server_handshake_traffic_secret
        let server_hs_secret = hkdf_expand_label(
            &handshake_secret,
            b"s hs traffic",
            &handshake_hash,
            hash_len,
            cipher_suite,
        )?;

        // 4. Derive server_handshake_key and server_handshake_iv
        let (key_len, iv_len) = cipher_suite.key_iv_length();
        let server_handshake_key =
            hkdf_expand_label(&server_hs_secret, b"key", b"", key_len, cipher_suite)?;
        let server_handshake_iv =
            hkdf_expand_label(&server_hs_secret, b"iv", b"", iv_len, cipher_suite)?;

        Ok((handshake_secret, server_handshake_key, server_handshake_iv))
    }

    /// Derive application keys
    fn derive_application_keys(
        &self,
        cipher_suite: CipherSuite,
        handshake_secret: &[u8],
    ) -> Result<(SessionKey, Vec<u8>)> {
        let hash_len = cipher_suite.hash_length();

        // 1. Compute master_secret = HKDF-Extract(0, handshake_secret)
        let zeros = vec![0u8; hash_len];
        let master_secret = hkdf_extract(&zeros, handshake_secret, &cipher_suite)?;

        // 2. Get final handshake hash (all handshake messages including Finished)
        let handshake_hash = self.handshake_hash.compute_hash()?;

        // 3. Derive client_application_traffic_secret_0
        let client_app_secret = hkdf_expand_label(
            &master_secret,
            b"c ap traffic",
            &handshake_hash,
            hash_len,
            &cipher_suite,
        )?;

        // 4. Derive server_application_traffic_secret_0
        let server_app_secret = hkdf_expand_label(
            &master_secret,
            b"s ap traffic",
            &handshake_hash,
            hash_len,
            &cipher_suite,
        )?;

        // 5. Derive keys and IVs
        let (key_len, iv_len) = get_key_iv_length(&cipher_suite);

        let client_write_key =
            hkdf_expand_label(&client_app_secret, b"key", b"", key_len, &cipher_suite)?;
        let client_write_iv =
            hkdf_expand_label(&client_app_secret, b"iv", b"", iv_len, &cipher_suite)?;
        let server_write_key =
            hkdf_expand_label(&server_app_secret, b"key", b"", key_len, &cipher_suite)?;
        let server_write_iv =
            hkdf_expand_label(&server_app_secret, b"iv", b"", iv_len, &cipher_suite)?;

        let session_key = SessionKey::new(
            TlsVersion::Tls13,
            CipherSuite::from(cipher_suite),
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        );

        Ok((session_key, handshake_hash))
    }

    /// Check if handshake keys are ready (for decrypting encrypted handshake messages)
    pub fn is_handshake_keys_ready(&self) -> bool {
        matches!(
            self.state,
            DeriverState::WaitingEncryptedExtensions { .. }
                | DeriverState::CollectingHandshake { .. }
        )
    }

    /// Check if key derivation is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DeriverState::Completed { .. })
    }

    /// Finish key derivation and return result
    ///
    /// # Returns
    /// - `Ok((SessionKey, handshake_hash))` if derivation succeeded
    /// - `Err(DecryptError::HandshakeNotComplete)` if handshake not complete
    pub fn finish(self) -> Result<(SessionKey, Vec<u8>)> {
        match self.state {
            DeriverState::Completed {
                session_key,
                handshake_hash,
            } => Ok((session_key, handshake_hash)),
            _ => Err(DecryptError::HandshakeNotComplete),
        }
    }

    /// Get current state (for debugging)
    pub fn state(&self) -> &DeriverState {
        &self.state
    }

    /// Reset deriver for Hello Retry Request scenario
    ///
    /// # Arguments
    /// - `new_shared_secret`: New ECDHE shared secret
    ///
    /// # Note
    /// This method preserves the processed handshake messages hash (including HRR message)
    pub fn reset_for_hrr(&mut self, new_shared_secret: Vec<u8>) {
        self.state = DeriverState::WaitingClientHello;
        self.shared_secret = new_shared_secret;
        self.decrypt_seq = 0;
        // Note: handshake_hash is NOT reset, HRR message is kept in the hash
    }

    /// Get handshake hash accumulator (for debugging)
    pub fn handshake_hash_accumulator(&self) -> &HandshakeHashAccumulator {
        &self.handshake_hash
    }
}

impl Default for Tls13KeyDeriver {
    fn default() -> Self {
        // Create with empty shared secret - should be replaced before use
        Self::new(Vec::new())
    }
}

// ============================================================================
// Helper functions for building handshake messages
// ============================================================================

/// Build a ClientHello handshake message from parsed contents
fn build_client_hello_message(ch: &tls_parser::TlsClientHelloContents<'_>) -> Vec<u8> {
    let mut msg_data = Vec::new();

    // Handshake header: type (1) + length (3)
    msg_data.push(0x01); // ClientHello type

    // Build body
    let mut body = Vec::new();
    body.extend_from_slice(&ch.version.0.to_be_bytes());
    body.extend_from_slice(ch.random);

    // Session ID
    if let Some(sid) = ch.session_id {
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
    } else {
        body.push(0);
    }

    // Cipher suites
    let ciphers_len = ch.ciphers.len() * 2;
    body.extend_from_slice(&(ciphers_len as u16).to_be_bytes());
    for cipher in &ch.ciphers {
        body.extend_from_slice(&cipher.0.to_be_bytes());
    }

    // Compression methods
    body.push(ch.comp.len() as u8);
    for comp in &ch.comp {
        body.push(comp.0);
    }

    // Extensions
    if let Some(ext) = ch.ext {
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(ext);
    } else {
        body.extend_from_slice(&0u16.to_be_bytes());
    }

    // Set length
    let len = body.len() as u32;
    msg_data.push(((len >> 16) & 0xFF) as u8);
    msg_data.push(((len >> 8) & 0xFF) as u8);
    msg_data.push((len & 0xFF) as u8);

    msg_data.extend_from_slice(&body);
    msg_data
}

/// Build a ServerHello handshake message from parsed contents
fn build_server_hello_message(sh: &tls_parser::TlsServerHelloContents<'_>) -> Vec<u8> {
    let mut msg_data = Vec::new();

    // Handshake header: type (1) + length (3)
    msg_data.push(0x02); // ServerHello type

    // Build body
    let mut body = Vec::new();
    body.extend_from_slice(&sh.version.0.to_be_bytes());
    body.extend_from_slice(sh.random);

    // Session ID
    if let Some(sid) = sh.session_id {
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
    } else {
        body.push(0);
    }

    // Cipher suite
    body.extend_from_slice(&sh.cipher.0.to_be_bytes());

    // Compression method
    body.push(sh.compression.0);

    // Extensions
    if let Some(ext) = sh.ext {
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(ext);
    } else {
        body.extend_from_slice(&0u16.to_be_bytes());
    }

    // Set length
    let len = body.len() as u32;
    msg_data.push(((len >> 16) & 0xFF) as u8);
    msg_data.push(((len >> 8) & 0xFF) as u8);
    msg_data.push((len & 0xFF) as u8);

    msg_data.extend_from_slice(&body);
    msg_data
}

/// Build a HelloRetryRequest handshake message from parsed contents
fn build_hrr_message(hrr: &tls_parser::TlsHelloRetryRequestContents<'_>) -> Vec<u8> {
    let mut msg_data = Vec::new();

    // Handshake header: type (1) + length (3)
    msg_data.push(0x06); // HelloRetryRequest type

    // Build body
    let mut body = Vec::new();
    body.extend_from_slice(&hrr.version.0.to_be_bytes());

    // HRR random (special value)
    const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE9, 0xA9, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];
    body.extend_from_slice(&HRR_RANDOM);

    // Cipher suite
    body.extend_from_slice(&hrr.cipher.0.to_be_bytes());

    // Extensions
    if let Some(ext) = hrr.ext {
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(ext);
    } else {
        body.extend_from_slice(&0u16.to_be_bytes());
    }

    // Set length
    let len = body.len() as u32;
    msg_data.push(((len >> 16) & 0xFF) as u8);
    msg_data.push(((len >> 8) & 0xFF) as u8);
    msg_data.push((len & 0xFF) as u8);

    msg_data.extend_from_slice(&body);
    msg_data
}

// ============================================================================
// Helper functions for HKDF
// ============================================================================

/// TLS 1.3 HKDF-Extract
/// HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
fn hkdf_extract(salt: &[u8], ikm: &[u8], cipher_suite: &CipherSuite) -> Result<Vec<u8>> {
    match cipher_suite {
        CipherSuite::Tls13Aes128GcmSha256 | CipherSuite::Tls13ChaCha20Poly1305Sha256 => {
            let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(salt)
                .map_err(|_| DecryptError::KeyDerivationFailed("HMAC init failed".to_string()))?;
            hmac.update(ikm);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        CipherSuite::Tls13Aes256GcmSha384 => {
            let mut hmac = <Hmac<Sha384> as KeyInit>::new_from_slice(salt)
                .map_err(|_| DecryptError::KeyDerivationFailed("HMAC init failed".to_string()))?;
            hmac.update(ikm);
            Ok(hmac.finalize().into_bytes().to_vec())
        }
        _ => Err(DecryptError::UnsupportedCipherSuite(cipher_suite.to_u16())),
    }
}

/// TLS 1.3 HKDF-Expand-Label
fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
    cipher_suite: &CipherSuite,
) -> Result<Vec<u8>> {
    // Build HkdfLabel
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(output_len as u16).to_be_bytes());
    hkdf_label.extend_from_slice(b"TLS 1.3, ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    match cipher_suite {
        CipherSuite::Tls13Aes128GcmSha256 | CipherSuite::Tls13ChaCha20Poly1305Sha256 => {
            let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| {
                DecryptError::KeyDerivationFailed("HKDF from_prk failed".to_string())
            })?;
            let mut okm = vec![0u8; output_len];
            hkdf.expand(&hkdf_label, &mut okm)
                .map_err(|_| DecryptError::KeyDerivationFailed("HKDF expand failed".to_string()))?;
            Ok(okm)
        }
        CipherSuite::Tls13Aes256GcmSha384 => {
            let hkdf = Hkdf::<Sha384>::from_prk(secret).map_err(|_| {
                DecryptError::KeyDerivationFailed("HKDF from_prk failed".to_string())
            })?;
            let mut okm = vec![0u8; output_len];
            hkdf.expand(&hkdf_label, &mut okm)
                .map_err(|_| DecryptError::KeyDerivationFailed("HKDF expand failed".to_string()))?;
            Ok(okm)
        }
        _ => Err(DecryptError::UnsupportedCipherSuite(cipher_suite.to_u16())),
    }
}

/// Get hash length for cipher suite
fn get_hash_length(cipher_suite: &CipherSuite) -> usize {
    cipher_suite.hash_length()
}

/// Get key and IV length for cipher suite
fn get_key_iv_length(cipher_suite: &CipherSuite) -> (usize, usize) {
    cipher_suite.key_iv_length()
}

/// Parse HelloRetryRequest extensions
fn parse_hrr_extensions(extensions_data: &[u8]) -> Result<(u16, Option<Vec<u8>>)> {
    let mut offset = 0;
    let mut selected_group: Option<u16> = None;
    let mut cookie: Option<Vec<u8>> = None;

    while offset + 4 <= extensions_data.len() {
        let ext_type = u16::from_be_bytes([extensions_data[offset], extensions_data[offset + 1]]);
        let ext_len =
            u16::from_be_bytes([extensions_data[offset + 2], extensions_data[offset + 3]]) as usize;

        if offset + 4 + ext_len > extensions_data.len() {
            return Err(DecryptError::InvalidHandshakeMessage);
        }

        let ext_data = &extensions_data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            51 => {
                // key_share extension
                if ext_data.len() < 2 {
                    return Err(DecryptError::InvalidHandshakeMessage);
                }
                selected_group = Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
            }
            44 => {
                // cookie extension
                cookie = Some(ext_data.to_vec());
            }
            _ => {}
        }

        offset += 4 + ext_len;
    }

    let selected_group = selected_group.ok_or_else(|| {
        DecryptError::HrrError("No key_share extension in HelloRetryRequest".to_string())
    })?;

    Ok((selected_group, cookie))
}

// ============================================================================
// Public API for TLS 1.3 key derivation
// ============================================================================

/// Derive session keys from TLS 1.3 handshake parameters
///
/// # Arguments
/// - `shared_secret`: ECDHE shared secret
/// - `cipher_suite`: TLS 1.3 cipher suite
/// - `handshake_hash`: Hash of handshake messages
///
/// # Returns
/// Derived session key
pub fn derive_keys_tls13(
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
    handshake_hash: &[u8],
) -> Result<SessionKey> {
    // TLS 1.3 uses HKDF for key derivation
    // See RFC 8446 Section 7.1

    let hash_len = get_hash_length(&cipher_suite);

    // 1. Compute handshake_secret
    // handshake_secret = HKDF-Extract(0, shared_secret)
    let zeros = vec![0u8; hash_len];
    let handshake_secret = hkdf_extract(&zeros, shared_secret, &cipher_suite)?;

    // 2. Compute client_handshake_traffic_secret
    // client_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", handshake_hash)
    let _client_handshake_traffic_secret = hkdf_expand_label(
        &handshake_secret,
        b"c hs traffic",
        handshake_hash,
        hash_len,
        &cipher_suite,
    )?;

    // 3. Compute server_handshake_traffic_secret
    // server_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "s hs traffic", handshake_hash)
    let _server_handshake_traffic_secret = hkdf_expand_label(
        &handshake_secret,
        b"s hs traffic",
        handshake_hash,
        hash_len,
        &cipher_suite,
    )?;

    // 4. Compute master_secret
    // master_secret = HKDF-Extract(0, handshake_secret)
    let master_secret = hkdf_extract(&zeros, &handshake_secret, &cipher_suite)?;

    // 5. Compute client_application_traffic_secret
    // client_application_traffic_secret_0 = HKDF-Expand-Label(master_secret, "c ap traffic", handshake_hash)
    let client_app_traffic_secret = hkdf_expand_label(
        &master_secret,
        b"c ap traffic",
        handshake_hash,
        hash_len,
        &cipher_suite,
    )?;

    // 6. Compute server_application_traffic_secret
    // server_application_traffic_secret_0 = HKDF-Expand-Label(master_secret, "s ap traffic", handshake_hash)
    let server_app_traffic_secret = hkdf_expand_label(
        &master_secret,
        b"s ap traffic",
        handshake_hash,
        hash_len,
        &cipher_suite,
    )?;

    // 7. Derive actual keys and IVs from traffic secrets
    // key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
    // iv = HKDF-Expand-Label(traffic_secret, "iv", "", iv_length)
    let (key_len, iv_len) = get_key_iv_length(&cipher_suite);

    let client_write_key = hkdf_expand_label(
        &client_app_traffic_secret,
        b"key",
        &[],
        key_len,
        &cipher_suite,
    )?;
    let client_write_iv = hkdf_expand_label(
        &client_app_traffic_secret,
        b"iv",
        &[],
        iv_len,
        &cipher_suite,
    )?;
    let server_write_key = hkdf_expand_label(
        &server_app_traffic_secret,
        b"key",
        &[],
        key_len,
        &cipher_suite,
    )?;
    let server_write_iv = hkdf_expand_label(
        &server_app_traffic_secret,
        b"iv",
        &[],
        iv_len,
        &cipher_suite,
    )?;

    Ok(SessionKey::new(
        TlsVersion::Tls13,
        cipher_suite.into(),
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ))
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;
    use hex_literal::hex;
    use tls_parser::TlsClientHelloContents;

    #[test]
    fn test_derive_keys_tls13_aes128gcm() {
        let shared_secret =
            hex!("b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0");
        let handshake_hash =
            hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::Tls13Aes128GcmSha256,
            &handshake_hash,
        )
        .expect("TLS 1.3 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("3b18f23f8f43fd03081c89a5fd994e2a"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("a84affab414e3ff06323bef6a2ae41ac"),
            "Server write key mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ClientToServer),
            &hex!("95f693a6d1adc21d9a1d7fa9"),
            "Client write IV mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ServerToClient),
            &hex!("4d4e08b9c946c150e24c0ddc"),
            "Server write IV mismatch"
        );
    }

    #[test]
    fn test_derive_keys_tls13_aes256gcm() {
        let shared_secret = hex!(
            "c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0"
        );
        let handshake_hash = hex!(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::Tls13Aes256GcmSha384,
            &handshake_hash,
        )
        .expect("TLS 1.3 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("badfba28b3ee81b8bcb6ba3200d2b271484510c713b0c124cc336efda12a8258"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("fb7dae5b87c1070d99a2d13eb7ef05910558ecdefcd2c7c9ddfb01233735254d"),
            "Server write key mismatch"
        );
    }

    #[test]
    fn test_derive_keys_tls13_chacha20poly1305() {
        let shared_secret =
            hex!("d1e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0");
        let handshake_hash =
            hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::Tls13ChaCha20Poly1305Sha256,
            &handshake_hash,
        )
        .expect("TLS 1.3 ChaCha20 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("e70701dbecd779b49e35a369073e908a54288fda04045eea48171e55ceadd62b"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("b6759777815b337880adb54e57f59ce31912d3d8d6b26917bac05c05e3957925"),
            "Server write key mismatch"
        );
    }

    #[test]
    fn test_new_deriver() {
        let shared_secret = vec![0u8; 32];
        let deriver = Tls13KeyDeriver::new(shared_secret);
        assert!(matches!(deriver.state(), DeriverState::WaitingClientHello));
        assert!(!deriver.is_complete());
        assert!(!deriver.is_handshake_keys_ready());
    }

    #[test]
    fn test_handshake_hash_accumulator() {
        let mut acc = HandshakeHashAccumulator::new();

        // Add some test data
        acc.add_message(
            &[0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05],
            None,
        );
        acc.add_message(
            &[0x02, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],
            Some(CipherSuite::Tls13Aes128GcmSha256),
        );

        let hash = acc.compute_hash();
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 32); // SHA-256
    }

    #[test]
    fn test_hkdf_extract_sha256() {
        let salt = vec![0u8; 32];
        let ikm = vec![1u8; 32];
        let result = hkdf_extract(&salt, &ikm, &CipherSuite::Tls13Aes128GcmSha256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_hkdf_expand_label_sha256() {
        let secret = vec![0u8; 32];
        let result =
            hkdf_expand_label(&secret, b"key", b"", 16, &CipherSuite::Tls13Aes128GcmSha256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_get_hash_length() {
        assert_eq!(get_hash_length(&CipherSuite::Tls13Aes128GcmSha256), 32);
        assert_eq!(get_hash_length(&CipherSuite::Tls13Aes256GcmSha384), 48);
        assert_eq!(
            get_hash_length(&CipherSuite::Tls13ChaCha20Poly1305Sha256),
            32
        );
    }

    #[test]
    fn test_get_key_iv_length() {
        assert_eq!(
            get_key_iv_length(&CipherSuite::Tls13Aes128GcmSha256),
            (16, 12)
        );
        assert_eq!(
            get_key_iv_length(&CipherSuite::Tls13Aes256GcmSha384),
            (32, 12)
        );
        assert_eq!(
            get_key_iv_length(&CipherSuite::Tls13ChaCha20Poly1305Sha256),
            (32, 12)
        );
    }

    #[test]
    fn test_build_client_hello_message() {
        let ch = TlsClientHelloContents::new(
            0x0303,
            &[0u8; 32],
            None,
            vec![TlsCipherSuiteID(0x1301)],
            vec![tls_parser::TlsCompressionID(0)],
            None,
        );
        let msg = build_client_hello_message(&ch);
        assert!(!msg.is_empty());
        assert_eq!(msg[0], 0x01); // ClientHello type
    }
}
