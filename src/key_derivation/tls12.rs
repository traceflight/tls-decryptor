//! TLS 1.2 Key Deriver
//!
//! This module provides a stateful TLS 1.2 key derivation process
//! that processes handshake records sequentially and derives keys
//! after receiving the pre-master secret.
//!
//! # Features
//! - Supports TLS 1.2 RSA and ECDHE key exchange
//! - Extracts parameters from parsed handshake messages
//! - Derives session keys from pre-master secret
//!
//! # Example
//! ```rust,ignore
//! use tls_decryptor::key_derivation::Tls12KeyDeriver;
//! use tls_parser::{TlsMessageHandshake, parse_tls_record};
//!
//! let mut deriver = Tls12KeyDeriver::new();
//!
//! // Parse and feed ClientHello and ServerHello from TLS records
//! for record in records {
//!     let (_, msg) = parse_tls_record(&record[5..])?; // Skip 5-byte record header
//!     if let TlsMessage::Handshake(hs_msg) = msg {
//!         deriver.feed_message(hs_msg)?;
//!     }
//! }
//!
//! // After extracting parameters, provide pre-master secret to derive keys
//! let pre_master_secret = /* obtained from RSA decryption or ECDHE computation */;
//! let session_key = deriver.derive_keys(&pre_master_secret)?;
//! ```

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use tls_parser::TlsMessageHandshake;

use crate::error::{DecryptError, Result};
use crate::types::{CipherSuite, SessionKey, TlsVersion};

/// Derive TLS 1.2 session keys from pre-master secret and handshake parameters
///
/// # Arguments
/// - `client_random`: Client random (32 bytes)
/// - `server_random`: Server random (32 bytes)
/// - `pre_master_secret`: Pre-master secret (obtained by decrypting with private key or ECDHE)
/// - `cipher_suite`: Negotiated cipher suite
///
/// # Returns
/// Derived session key
pub fn derive_keys_tls12(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    pre_master_secret: &[u8],
    cipher_suite: CipherSuite,
) -> Result<SessionKey> {
    // 1. Compute Master Secret
    // master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
    let seed = [client_random.as_slice(), server_random.as_slice()].concat();
    let master_secret = prf_tls12(pre_master_secret, b"master secret", &seed, 48, cipher_suite)?;

    // 2. Compute Key Block
    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    let key_expansion_seed = [server_random.as_slice(), client_random.as_slice()].concat();

    // Determine required key material length based on cipher suite
    let (key_len, iv_len) = cipher_suite.key_iv_length();
    // key_block = client_write_key + server_write_key + client_write_IV + server_write_IV
    let key_block_len = 2 * key_len + 2 * iv_len;
    let key_block = prf_tls12(
        &master_secret,
        b"key expansion",
        &key_expansion_seed,
        key_block_len,
        cipher_suite,
    )?;

    // 3. Extract keys and IVs
    let mut offset = 0;
    let client_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let server_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let client_write_iv = key_block[offset..offset + iv_len].to_vec();
    offset += iv_len;
    let server_write_iv = key_block[offset..offset + iv_len].to_vec();

    Ok(SessionKey::new(
        TlsVersion::Tls12,
        cipher_suite,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ))
}

/// TLS 1.2 PRF function
/// PRF(secret, label, seed) = P_hash(secret, label + seed)
/// For SHA-384 based cipher suites, use HMAC-SHA384
fn prf_tls12(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    output_len: usize,
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>> {
    let seed = [label, seed].concat();
    match cipher_suite {
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            p_hash::<Hmac<Sha384>>(secret, &seed, output_len)
        }
        _ => p_hash::<Hmac<Sha256>>(secret, &seed, output_len),
    }
}

/// P_hash function
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
/// A(0) = seed
/// A(i) = HMAC_hash(secret, A(i-1))
fn p_hash<H: Mac + Clone + KeyInit>(
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(output_len);
    let mut a = seed.to_vec();

    while result.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut hmac = <H as KeyInit>::new_from_slice(secret)
            .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
        hmac.update(&a);
        let a_result = hmac.finalize().into_bytes();
        a = a_result.to_vec();

        // HMAC(secret, A(i) + seed)
        let mut hmac = <H as KeyInit>::new_from_slice(secret)
            .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
        hmac.update(&a);
        hmac.update(seed);
        let result_bytes = hmac.finalize().into_bytes();

        result.extend_from_slice(&result_bytes);
    }

    result.truncate(output_len);
    Ok(result)
}

/// TLS 1.2 key derivation events
///
/// Used to notify the caller of key derivation progress
#[derive(Debug, Clone)]
pub enum DeriverEvent {
    /// ClientHello received
    ClientHelloReceived { client_random: [u8; 32] },

    /// ServerHello received, parameters extracted
    ServerHelloReceived {
        server_random: [u8; 32],
        cipher_suite: CipherSuite,
    },

    /// All parameters extracted, ready to receive pre-master secret
    ParametersReady,
}

/// TLS 1.2 key deriver internal state
#[derive(Debug)]
pub enum DeriverState {
    /// Initial state, waiting for ClientHello
    WaitingClientHello,

    /// ClientHello received, waiting for ServerHello
    WaitingServerHello { client_random: [u8; 32] },

    /// ServerHello received, all parameters extracted
    ParametersReady {
        client_random: [u8; 32],
        server_random: [u8; 32],
        cipher_suite: CipherSuite,
    },

    /// Keys derived
    Completed { session_key: SessionKey },
}

/// TLS 1.2 Key Deriver
///
/// A stateful object that processes TLS 1.2 handshake messages
/// and derives keys after receiving the pre-master secret.
pub struct Tls12KeyDeriver {
    /// Current state
    state: DeriverState,
}

impl Tls12KeyDeriver {
    /// Create a new TLS 1.2 key deriver
    ///
    /// # Returns
    /// A new deriver instance in the initial state
    pub fn new() -> Self {
        Self {
            state: DeriverState::WaitingClientHello,
        }
    }

    /// Feed a handshake message
    ///
    /// # Arguments
    /// - `msg`: Parsed `TlsMessageHandshake` from tls-parser
    ///
    /// # Returns
    /// - `Ok(Some(DeriverEvent))` if processing succeeded with an event
    /// - `Ok(None)` if processing succeeded but no event
    /// - `Err(DecryptError)` if processing failed
    pub fn feed_message(&mut self, msg: &TlsMessageHandshake<'_>) -> Result<Option<DeriverEvent>> {
        match msg {
            TlsMessageHandshake::ClientHello(ch) => self.process_client_hello(ch),
            TlsMessageHandshake::ServerHello(sh) => self.process_server_hello(sh),
            // Ignore other handshake messages for key derivation
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

        match &self.state {
            DeriverState::WaitingClientHello => {
                self.state = DeriverState::WaitingServerHello { client_random };
                Ok(Some(DeriverEvent::ClientHelloReceived { client_random }))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "ServerHello".to_string(),
                got: "ClientHello".to_string(),
            }),
        }
    }

    /// Process ServerHello message
    fn process_server_hello(
        &mut self,
        sh: &tls_parser::TlsServerHelloContents<'_>,
    ) -> Result<Option<DeriverEvent>> {
        // Extract server random (32 bytes)
        let server_random: [u8; 32] = sh
            .random
            .try_into()
            .map_err(|_| DecryptError::InvalidHandshakeMessage)?;

        // Extract cipher suite
        let cipher_suite = CipherSuite::from(sh.cipher);

        match &self.state {
            DeriverState::WaitingServerHello { client_random } => {
                self.state = DeriverState::ParametersReady {
                    client_random: *client_random,
                    server_random,
                    cipher_suite,
                };
                Ok(Some(DeriverEvent::ServerHelloReceived {
                    server_random,
                    cipher_suite,
                }))
            }
            _ => Err(DecryptError::UnexpectedHandshakeMessage {
                expected: "ClientHello".to_string(),
                got: "ServerHello".to_string(),
            }),
        }
    }

    /// Check if all parameters have been extracted
    pub fn is_parameters_ready(&self) -> bool {
        matches!(self.state, DeriverState::ParametersReady { .. })
    }

    /// Check if key derivation is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, DeriverState::Completed { .. })
    }

    /// Derive session keys from pre-master secret
    ///
    /// # Arguments
    /// - `pre_master_secret`: The pre-master secret (obtained from RSA decryption or ECDHE computation)
    ///
    /// # Returns
    /// - `Ok(SessionKey)` if key derivation succeeded
    /// - `Err(DecryptError)` if parameters not ready or derivation failed
    pub fn derive_keys(&mut self, pre_master_secret: &[u8]) -> Result<SessionKey> {
        let (client_random, server_random, cipher_suite) = match &self.state {
            DeriverState::ParametersReady {
                client_random,
                server_random,
                cipher_suite,
            } => (*client_random, *server_random, *cipher_suite),
            _ => {
                return Err(DecryptError::KeyDerivationFailed(
                    "Parameters not ready, feed ClientHello and ServerHello first".to_string(),
                ));
            }
        };

        // Derive keys using the local function
        let session_key = derive_keys_tls12(
            &client_random,
            &server_random,
            pre_master_secret,
            cipher_suite,
        )?;

        self.state = DeriverState::Completed {
            session_key: session_key.clone(),
        };

        Ok(session_key)
    }

    /// Get the extracted client random (if available)
    pub fn client_random(&self) -> Option<[u8; 32]> {
        match &self.state {
            DeriverState::WaitingServerHello { client_random }
            | DeriverState::ParametersReady { client_random, .. } => Some(*client_random),
            DeriverState::WaitingClientHello | DeriverState::Completed { .. } => None,
        }
    }

    /// Get the extracted server random (if available)
    pub fn server_random(&self) -> Option<[u8; 32]> {
        match &self.state {
            DeriverState::ParametersReady { server_random, .. } => Some(*server_random),
            DeriverState::WaitingClientHello
            | DeriverState::WaitingServerHello { .. }
            | DeriverState::Completed { .. } => None,
        }
    }

    /// Get the negotiated cipher suite (if available)
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        match &self.state {
            DeriverState::ParametersReady { cipher_suite, .. } => Some(*cipher_suite),
            DeriverState::Completed { session_key } => Some(session_key.cipher_suite),
            _ => None,
        }
    }

    /// Get current state (for debugging)
    pub fn state(&self) -> &DeriverState {
        &self.state
    }

    /// Reset deriver to initial state
    pub fn reset(&mut self) {
        self.state = DeriverState::WaitingClientHello;
    }
}

impl Default for Tls12KeyDeriver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;
    use hex_literal::hex;
    use tls_parser::{TlsClientHelloContents, TlsServerHelloContents};

    /// Build a minimal ClientHello message
    fn build_client_hello() -> TlsClientHelloContents<'static> {
        TlsClientHelloContents::new(
            0x0303,     // TLS 1.2
            &[0u8; 32], // Random
            None,       // Session ID
            vec![],     // Cipher suites
            vec![],     // Compression methods
            None,       // Extensions
        )
    }

    /// Build a minimal ServerHello message
    fn build_server_hello() -> TlsServerHelloContents<'static> {
        TlsServerHelloContents::new(
            0x0303,     // TLS 1.2
            &[1u8; 32], // Random
            None,       // Session ID
            0x009C,     // TLS_RSA_WITH_AES_128_GCM_SHA256 (rustls internal ID)
            0,          // Compression
            None,       // Extensions
        )
    }

    #[test]
    fn test_new_deriver() {
        let deriver = Tls12KeyDeriver::new();
        assert!(matches!(deriver.state(), DeriverState::WaitingClientHello));
        assert!(!deriver.is_parameters_ready());
        assert!(!deriver.is_complete());
    }

    #[test]
    fn test_feed_client_hello() {
        let mut deriver = Tls12KeyDeriver::new();
        let client_hello = build_client_hello();

        let event = deriver.feed_message(&TlsMessageHandshake::ClientHello(client_hello));
        assert!(event.is_ok());

        let event = event.unwrap();
        assert!(event.is_some());
        if let Some(DeriverEvent::ClientHelloReceived { client_random }) = event {
            assert_eq!(client_random, [0u8; 32]);
        } else {
            panic!("Expected ClientHelloReceived event");
        }

        assert!(matches!(
            deriver.state(),
            DeriverState::WaitingServerHello { .. }
        ));
    }

    #[test]
    fn test_feed_server_hello() {
        let mut deriver = Tls12KeyDeriver::new();

        // Feed ClientHello first
        let client_hello = build_client_hello();
        deriver
            .feed_message(&TlsMessageHandshake::ClientHello(client_hello))
            .unwrap();

        // Feed ServerHello
        let server_hello = build_server_hello();
        let event = deriver.feed_message(&TlsMessageHandshake::ServerHello(server_hello));
        assert!(event.is_ok());

        let event = event.unwrap();
        assert!(event.is_some());
        if let Some(DeriverEvent::ServerHelloReceived {
            server_random,
            cipher_suite,
        }) = event
        {
            assert_eq!(server_random, [1u8; 32]);
            assert_eq!(cipher_suite, CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256);
        } else {
            panic!("Expected ServerHelloReceived event");
        }

        assert!(deriver.is_parameters_ready());
        assert!(matches!(
            deriver.state(),
            DeriverState::ParametersReady { .. }
        ));
    }

    #[test]
    fn test_derive_keys() {
        let mut deriver = Tls12KeyDeriver::new();

        // Feed ClientHello
        let client_hello = TlsClientHelloContents::new(
            0x0303,
            &hex!("20bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49"),
            None,
            vec![],
            vec![],
            None,
        );
        deriver
            .feed_message(&TlsMessageHandshake::ClientHello(client_hello))
            .unwrap();

        // Feed ServerHello
        let server_hello = TlsServerHelloContents::new(
            0x0303,
            &hex!("35c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555"),
            None,
            0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256 (rustls internal ID)
            0,
            None,
        );
        deriver
            .feed_message(&TlsMessageHandshake::ServerHello(server_hello))
            .unwrap();

        // Derive keys with pre-master secret
        let pre_master_secret = hex!(
            "03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e"
        );
        let session_key = deriver.derive_keys(&pre_master_secret).unwrap();

        // Verify derived keys
        assert_eq!(session_key.version, TlsVersion::Tls12);
        assert_eq!(
            session_key.cipher_suite,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("0621b262dccd5d443d7c67e2602f0774"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("b2c806916a7e6601360a36c9880ae11a"),
            "Server write key mismatch"
        );

        assert!(deriver.is_complete());
    }

    #[test]
    fn test_derive_keys_without_parameters() {
        let mut deriver = Tls12KeyDeriver::new();
        let pre_master_secret = vec![0u8; 48];

        let result = deriver.derive_keys(&pre_master_secret);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::KeyDerivationFailed(_)
        ));
    }

    #[test]
    fn test_reset() {
        let mut deriver = Tls12KeyDeriver::new();

        // Feed messages
        let client_hello = build_client_hello();
        deriver
            .feed_message(&TlsMessageHandshake::ClientHello(client_hello))
            .unwrap();

        // Reset
        deriver.reset();
        assert!(matches!(deriver.state(), DeriverState::WaitingClientHello));
    }

    #[test]
    fn test_prf_tls12() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        let result = prf_tls12(
            secret,
            label,
            seed,
            32,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        );
        assert!(result.is_ok());
        if let Ok(output) = result {
            assert_eq!(output.len(), 32);
        }
    }
}
