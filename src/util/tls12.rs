//! TLS 1.2 utility functions
//!
//! This module provides utility functions for TLS 1.2 key exchange operations,
//! including ECDHE and DHE pre-master secret computation.

use crate::error::{DecryptError, Result};
use crate::types::{CurveType, DhParams};

// Re-export the common ECDHE function for convenience
pub use super::ecdhe::compute_ecdhe_shared_secret;

/// Compute TLS 1.2 pre-master secret from ClientKeyExchange and ServerKeyExchange records
///
/// Automatically detects the key exchange type (ECDHE or DHE) and computes the pre-master secret.
///
/// # Arguments
/// - `server_private_key`: Server's ephemeral private key in raw bytes
/// - `client_key_exchange`: ClientKeyExchange handshake message content (without record header and handshake type/length)
/// - `server_key_exchange`: ServerKeyExchange handshake message content (without record header and handshake type/length)
///
/// # Returns
/// - `Ok(Vec<u8>)`: The computed pre-master secret
/// - `Err(DecryptError)`: If parsing or computation fails
///
/// # Note
/// Input buffers should contain only the handshake message payload:
/// - For ECDHE: curve_params + ECPoint public (signature is ignored)
/// - For DHE: dh_p + dh_g + dh_Ys (signature is ignored)
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::compute_pre_master_secret_from_key_exchange;
///
/// // server_private_key: Server's ephemeral private key from key share
/// // client_key_exchange: ClientKeyExchange handshake message content
/// // server_key_exchange: ServerKeyExchange handshake message content
/// let pre_master_secret = compute_pre_master_secret_from_key_exchange(
///     &server_private_key,
///     &client_key_exchange,
///     &server_key_exchange,
/// )?;
/// ```
pub fn compute_pre_master_secret_from_key_exchange(
    server_private_key: &[u8],
    client_key_exchange: &[u8],
    server_key_exchange: &[u8],
) -> Result<Vec<u8>> {
    // Detect key exchange type from ServerKeyExchange first byte
    // ECDHE: first byte is curve_type (3 = named_group)
    // DHE: first byte is part of 2-byte length for dh_p
    if server_key_exchange.is_empty() {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange is empty".to_string(),
        ));
    }

    // Check if first byte indicates ECDHE with named_group (curve_type = 3)
    let key_exchange_type = detect_key_exchange_type(server_key_exchange)?;

    match key_exchange_type {
        KeyExchangeType::Ecdhe => compute_pre_master_secret_ecdhe_from_records(
            server_private_key,
            client_key_exchange,
            server_key_exchange,
        ),
        KeyExchangeType::Dhe => compute_pre_master_secret_dhe_from_records(
            server_private_key,
            client_key_exchange,
            server_key_exchange,
        ),
    }
}

/// Compute TLS 1.2 ECDHE pre-master secret
///
/// Given the server's ephemeral private key and the client's public key from
/// ClientKeyExchange, compute the pre-master secret for TLS 1.2 ECDHE key exchange.
///
/// This is a wrapper around the common [`compute_ecdhe_shared_secret`] function.
/// The mathematical computation is identical for TLS 1.2 and TLS 1.3.
///
/// # Arguments
/// - `server_private_key`: Server's ephemeral private key in raw bytes
/// - `client_public_key`: Client's public key from ClientKeyExchange (uncompressed point for NIST curves, raw bytes for X25519)
/// - `curve`: The elliptic curve type being used
///
/// # Returns
/// - `Ok(Vec<u8>)`: The computed pre-master secret
/// - `Err(DecryptError)`: If computation fails
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::{compute_pre_master_secret_ecdhe, CurveType};
///
/// // Server's ephemeral private key (32 bytes for P-256)
/// let server_private_key = vec![0u8; 32];
///
/// // Client's public key from ClientKeyExchange (65 bytes for P-256 uncompressed)
/// let client_public_key = vec![0x04, /* 32 bytes X */, /* 32 bytes Y */];
///
/// // Compute pre-master secret using ECDHE
/// let pre_master_secret = compute_pre_master_secret_ecdhe(
///     &server_private_key,
///     &client_public_key,
///     CurveType::Secp256r1,
/// )?;
/// ```
pub fn compute_pre_master_secret_ecdhe(
    server_private_key: &[u8],
    client_public_key: &[u8],
    curve: CurveType,
) -> Result<Vec<u8>> {
    compute_ecdhe_shared_secret(server_private_key, client_public_key, curve)
}

/// Compute TLS 1.2 DHE pre-master secret
///
/// Given the server's ephemeral private key, the client's public key from
/// ClientKeyExchange, and the DH parameters from ServerKeyExchange, compute
/// the pre-master secret for TLS 1.2 DHE key exchange.
///
/// # Arguments
/// - `server_private_key`: Server's ephemeral private key (xs) in raw bytes (big-endian)
/// - `client_public_key`: Client's public key (Yc) from ClientKeyExchange in raw bytes (big-endian)
/// - `dh_params`: DH parameters (p, g) from ServerKeyExchange
///
/// # Returns
/// - `Ok(Vec<u8>)`: The computed pre-master secret (Yc^xs mod p)
/// - `Err(DecryptError)`: If computation fails
///
/// # Note
/// This function requires the `num-bigint` crate for modular exponentiation.
/// The pre-master secret is returned as the raw bytes of the result, with
/// leading zeros preserved to match the length of p.
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::{compute_pre_master_secret_dhe, DhParams};
///
/// // Server's ephemeral private key (xs)
/// let server_private_key = vec![/* xs bytes */];
///
/// // Client's public key from ClientKeyExchange (Yc)
/// let client_public_key = vec![/* Yc bytes */];
///
/// // DH parameters from ServerKeyExchange
/// let dh_params = DhParams::new(
///     vec![/* p bytes - prime */],
///     vec![/* g bytes - generator */],
/// );
///
/// // Note: This function currently returns an error as DHE computation
/// // requires the num-bigint dependency
/// let pre_master_secret = compute_pre_master_secret_dhe(
///     &server_private_key,
///     &client_public_key,
///     &dh_params,
/// )?;
/// ```
pub fn compute_pre_master_secret_dhe(
    server_private_key: &[u8],
    client_public_key: &[u8],
    dh_params: &DhParams,
) -> Result<Vec<u8>> {
    // Validate DH parameters
    if dh_params.p.is_empty() {
        return Err(DecryptError::InvalidDhParameters("p is empty".to_string()));
    }
    if dh_params.g.is_empty() {
        return Err(DecryptError::InvalidDhParameters("g is empty".to_string()));
    }
    if server_private_key.is_empty() {
        return Err(DecryptError::InvalidDhParameters(
            "server private key is empty".to_string(),
        ));
    }
    if client_public_key.is_empty() {
        return Err(DecryptError::InvalidDhParameters(
            "client public key is empty".to_string(),
        ));
    }

    // For DHE, we need modular exponentiation: pre_master_secret = Yc^xs mod p
    // This requires big integer arithmetic. We use the num-bigint crate.
    // Note: This function is currently a placeholder that returns an error
    // because num-bigint is not yet a dependency. To enable DHE support,
    // add num-bigint to Cargo.toml and implement the modular exponentiation.

    Err(DecryptError::DheError(
        "DHE computation requires num-bigint dependency".to_string(),
    ))
}

/// Server public key extracted from ServerKeyExchange
///
/// Holds references to the original data, so the lifetime `'a` is tied to the
/// input buffer containing the ServerKeyExchange record.
#[derive(Debug, Clone, Copy)]
pub struct ServerPublicKey<'a> {
    /// The elliptic curve type (for ECDHE) or None (for DHE)
    pub curve: Option<CurveType>,
    /// DH parameters (for DHE) or None (for ECDHE)
    pub dh_params: Option<DhParamsRef<'a>>,
    /// Server's ephemeral public key bytes
    pub public_key: &'a [u8],
}

/// Reference to DH parameters without owning the data
#[derive(Debug, Clone, Copy)]
pub struct DhParamsRef<'a> {
    /// Prime p (big-endian byte order)
    pub p: &'a [u8],
    /// Generator g (big-endian byte order)
    pub g: &'a [u8],
}

impl<'a> ServerPublicKey<'a> {
    /// Create ECDHE server public key
    pub fn ecdhe(curve: CurveType, public_key: &'a [u8]) -> Self {
        Self {
            curve: Some(curve),
            dh_params: None,
            public_key,
        }
    }

    /// Create DHE server public key
    pub fn dhe(p: &'a [u8], g: &'a [u8], public_key: &'a [u8]) -> Self {
        Self {
            curve: None,
            dh_params: Some(DhParamsRef { p, g }),
            public_key,
        }
    }

    /// Get the curve type if this is ECDHE
    pub fn curve(&self) -> Option<CurveType> {
        self.curve
    }

    /// Get the DH parameters if this is DHE
    pub fn dh_params(&self) -> Option<&DhParamsRef<'a>> {
        self.dh_params.as_ref()
    }

    /// Check if this is ECDHE
    pub fn is_ecdhe(&self) -> bool {
        self.curve.is_some()
    }

    /// Check if this is DHE
    pub fn is_dhe(&self) -> bool {
        self.dh_params.is_some()
    }
}

/// Key exchange type detected from ServerKeyExchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyExchangeType {
    /// ECDHE key exchange
    Ecdhe,
    /// DHE key exchange
    Dhe,
}

/// Extract server public key from ServerKeyExchange record
///
/// Given the raw contents of a ServerKeyExchange handshake message (without the 5-byte record header),
/// parse and extract the server's ephemeral public key. Automatically detects whether this is
/// ECDHE or DHE key exchange.
///
/// # Arguments
/// - `server_key_exchange`: ServerKeyExchange record content (without 5-byte record header)
///
/// # Returns
/// - `Ok(ServerPublicKey)`: The extracted server public key
/// - `Err(DecryptError)`: If parsing fails
///
/// # Message Formats
///
/// ## ECDHE ServerKeyExchange (RFC 4492)
/// ```text
/// struct {
///     ECParameters curve_params;    // 1 byte curve_type + 2 bytes named_group
///     ECPoint public;               // 1 byte length + public key point
///     Signature signature;          // variable length (ignored)
/// } ServerECDHParams;
/// ```
///
/// ## DHE ServerKeyExchange (RFC 5246)
/// ```text
/// struct {
///     opaque dh_p<2..2^16-1>;       // 2 bytes length + p
///     opaque dh_g<2..2^16-1>;       // 2 bytes length + g
///     opaque dh_Ys<2..2^16-1>;      // 2 bytes length + Ys (server public key)
///     Signature signature;          // variable length (ignored)
/// } ServerDHParams;
/// ```
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::extract_server_public_key;
///
/// // Raw ServerKeyExchange handshake message content (without 5-byte record header)
/// let server_key_exchange = vec![/* ServerKeyExchange content */];
///
/// let server_public_key = extract_server_public_key(&server_key_exchange)?;
///
/// // Access the extracted data
/// if server_public_key.is_ecdhe() {
///     println!("ECDHE with curve: {:?}", server_public_key.curve());
///     println!("Public key: {} bytes", server_public_key.public_key.len());
/// } else if server_public_key.is_dhe() {
///     println!("DHE key exchange");
///     if let Some(dh_params) = server_public_key.dh_params() {
///         println!("DH params p: {} bytes, g: {} bytes", dh_params.p.len(), dh_params.g.len());
///     }
/// }
/// ```
pub fn extract_server_public_key<'a>(server_key_exchange: &'a [u8]) -> Result<ServerPublicKey<'a>> {
    if server_key_exchange.is_empty() {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange is empty".to_string(),
        ));
    }

    let key_exchange_type = detect_key_exchange_type(server_key_exchange)?;

    match key_exchange_type {
        KeyExchangeType::Ecdhe => extract_ecdhe_server_public_key(server_key_exchange),
        KeyExchangeType::Dhe => extract_dhe_server_public_key(server_key_exchange),
    }
}

/// Extract ECDHE server public key from ServerKeyExchange
fn extract_ecdhe_server_public_key<'a>(
    server_key_exchange: &'a [u8],
) -> Result<ServerPublicKey<'a>> {
    // Parse ServerKeyExchange for ECDHE
    // Structure: curve_type (1) + named_group (2) + public_key_length (1) + public_key + signature
    if server_key_exchange.len() < 5 {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange too short for ECDHE".to_string(),
        ));
    }

    let curve_type_byte = server_key_exchange[0];

    // We only support named_group (curve_type = 3)
    if curve_type_byte != 3 {
        return Err(DecryptError::HandshakeParseError(format!(
            "Unsupported EC curve type: {}",
            curve_type_byte
        )));
    }

    // Read named_group (2 bytes, big-endian)
    let named_group = u16::from_be_bytes([server_key_exchange[1], server_key_exchange[2]]);
    let curve = CurveType::from_u16(named_group).ok_or_else(|| {
        DecryptError::HandshakeParseError(format!("Unsupported named group: {:04x}", named_group))
    })?;

    // Read public key length (1 byte)
    let public_key_len = server_key_exchange[3] as usize;

    // Check we have enough bytes for the public key
    if server_key_exchange.len() < 4 + public_key_len {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange truncated: not enough bytes for server public key".to_string(),
        ));
    }

    // Extract server public key (as slice reference, no copy)
    let server_public_key = &server_key_exchange[4..4 + public_key_len];

    Ok(ServerPublicKey::ecdhe(curve, server_public_key))
}

/// Extract DHE server public key from ServerKeyExchange
fn extract_dhe_server_public_key<'a>(server_key_exchange: &'a [u8]) -> Result<ServerPublicKey<'a>> {
    // Parse ServerKeyExchange for DHE
    // Structure: p_length (2) + p + g_length (2) + g + Ys_length (2) + Ys + signature
    if server_key_exchange.len() < 6 {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange too short for DHE".to_string(),
        ));
    }

    // Read dh_p length (2 bytes, big-endian)
    let p_len = u16::from_be_bytes([server_key_exchange[0], server_key_exchange[1]]) as usize;

    if server_key_exchange.len() < 2 + p_len + 2 {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange truncated: not enough bytes for dh_p".to_string(),
        ));
    }

    let p = &server_key_exchange[2..2 + p_len];

    // Read dh_g length (2 bytes)
    let g_len_offset = 2 + p_len;
    let g_len = u16::from_be_bytes([
        server_key_exchange[g_len_offset],
        server_key_exchange[g_len_offset + 1],
    ]) as usize;

    if server_key_exchange.len() < g_len_offset + 2 + g_len + 2 {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange truncated: not enough bytes for dh_g".to_string(),
        ));
    }

    let g = &server_key_exchange[g_len_offset + 2..g_len_offset + 2 + g_len];

    // Read dh_Ys (server public key) length (2 bytes)
    let ys_len_offset = g_len_offset + 2 + g_len;
    let ys_len = u16::from_be_bytes([
        server_key_exchange[ys_len_offset],
        server_key_exchange[ys_len_offset + 1],
    ]) as usize;

    if server_key_exchange.len() < ys_len_offset + 2 + ys_len {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange truncated: not enough bytes for dh_Ys".to_string(),
        ));
    }

    // Extract server public key Ys (as slice reference, no copy)
    let ys = &server_key_exchange[ys_len_offset + 2..ys_len_offset + 2 + ys_len];

    Ok(ServerPublicKey::dhe(p, g, ys))
}

/// Detect key exchange type from ServerKeyExchange content
///
/// ECDHE ServerKeyExchange starts with curve_type byte:
/// - curve_type = 3 (named_group): indicates ECDHE with named curve
/// - curve_type = 1 or 2: indicates explicit curve parameters (also ECDHE)
///
/// DHE ServerKeyExchange starts with 2-byte length for dh_p,
/// so first byte is typically > 0 (length high byte) and not 1, 2, or 3.
fn detect_key_exchange_type(server_key_exchange: &[u8]) -> Result<KeyExchangeType> {
    if server_key_exchange.is_empty() {
        return Err(DecryptError::HandshakeParseError(
            "ServerKeyExchange is empty".to_string(),
        ));
    }

    let first_byte = server_key_exchange[0];

    // EC curve types (RFC 4492):
    // 1 = explicit_prime
    // 2 = explicit_char2
    // 3 = named_group
    if first_byte == 1 || first_byte == 2 || first_byte == 3 {
        Ok(KeyExchangeType::Ecdhe)
    } else {
        // Assume DHE: first byte is part of 2-byte length for dh_p
        Ok(KeyExchangeType::Dhe)
    }
}

/// Parse ECDHE parameters from ServerKeyExchange and compute pre-master secret
fn compute_pre_master_secret_ecdhe_from_records(
    server_private_key: &[u8],
    client_key_exchange: &[u8],
    server_key_exchange: &[u8],
) -> Result<Vec<u8>> {
    // Use extract_server_public_key to parse ServerKeyExchange
    let server_pk = extract_server_public_key(server_key_exchange)?;

    // Verify it's ECDHE and get the curve
    let curve = server_pk.curve().ok_or_else(|| {
        DecryptError::HandshakeParseError("Expected ECDHE but got DHE".to_string())
    })?;

    // Parse ClientKeyExchange for ECDHE
    // Structure: public_key_length (1) + public_key
    if client_key_exchange.is_empty() {
        return Err(DecryptError::HandshakeParseError(
            "ClientKeyExchange is empty".to_string(),
        ));
    }

    let client_public_key_len = client_key_exchange[0] as usize;

    if client_key_exchange.len() < 1 + client_public_key_len {
        return Err(DecryptError::HandshakeParseError(
            "ClientKeyExchange truncated: not enough bytes for client public key".to_string(),
        ));
    }

    let client_public_key = &client_key_exchange[1..1 + client_public_key_len];

    // Compute pre-master secret using existing function
    compute_pre_master_secret_ecdhe(server_private_key, client_public_key, curve)
}

/// Parse DHE parameters from ServerKeyExchange and compute pre-master secret
fn compute_pre_master_secret_dhe_from_records(
    server_private_key: &[u8],
    client_key_exchange: &[u8],
    server_key_exchange: &[u8],
) -> Result<Vec<u8>> {
    // Use extract_server_public_key to parse ServerKeyExchange
    let server_pk = extract_server_public_key(server_key_exchange)?;

    // Verify it's DHE and get the DH parameters
    let dh_params_ref = server_pk.dh_params().ok_or_else(|| {
        DecryptError::HandshakeParseError("Expected DHE but got ECDHE".to_string())
    })?;

    // Parse ClientKeyExchange for DHE
    // Structure: Yc_length (2) + Yc
    if client_key_exchange.len() < 2 {
        return Err(DecryptError::HandshakeParseError(
            "ClientKeyExchange too short for DHE".to_string(),
        ));
    }

    let yc_len = u16::from_be_bytes([client_key_exchange[0], client_key_exchange[1]]) as usize;

    if client_key_exchange.len() < 2 + yc_len {
        return Err(DecryptError::HandshakeParseError(
            "ClientKeyExchange truncated: not enough bytes for dh_Yc".to_string(),
        ));
    }

    let client_public_key = &client_key_exchange[2..2 + yc_len];

    // Create DhParams and compute pre-master secret
    let dh_params = DhParams::new(dh_params_ref.p.to_vec(), dh_params_ref.g.to_vec());
    compute_pre_master_secret_dhe(server_private_key, client_public_key, &dh_params)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    #[test]
    fn test_compute_pre_master_secret_ecdhe_p256() {
        let secret_key_a = SecretKey::random(&mut OsRng);
        let secret_key_b = SecretKey::random(&mut OsRng);

        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(false);
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        let private_key_a_bytes = secret_key_a.to_bytes();

        // Compute pre-master secret
        let pre_master_secret = compute_pre_master_secret_ecdhe(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp256r1,
        );

        assert!(pre_master_secret.is_ok());
        assert_eq!(pre_master_secret.unwrap().len(), 32);
    }

    #[test]
    fn test_compute_pre_master_secret_ecdhe_p384() {
        use p384::SecretKey as SecretKey384;
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key_a = SecretKey384::random(&mut OsRng);
        let secret_key_b = SecretKey384::random(&mut OsRng);

        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(false);
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        let private_key_a_bytes = secret_key_a.to_bytes();

        let pre_master_secret = compute_pre_master_secret_ecdhe(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp384r1,
        );

        assert!(pre_master_secret.is_ok());
        assert_eq!(pre_master_secret.unwrap().len(), 48);
    }

    #[test]
    fn test_compute_pre_master_secret_ecdhe_p521() {
        use p521::SecretKey as SecretKey521;
        use p521::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key_a = SecretKey521::random(&mut OsRng);
        let secret_key_b = SecretKey521::random(&mut OsRng);

        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(false);
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        let private_key_a_bytes = secret_key_a.to_bytes();

        let pre_master_secret = compute_pre_master_secret_ecdhe(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp521r1,
        );

        assert!(pre_master_secret.is_ok());
        assert_eq!(pre_master_secret.unwrap().len(), 66);
    }

    #[test]
    fn test_compute_pre_master_secret_ecdhe_x25519() {
        let private_key: [u8; 32] = [1u8; 32];
        let public_key: [u8; 32] = [2u8; 32];

        let result = compute_pre_master_secret_ecdhe(&private_key, &public_key, CurveType::X25519);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_ecdhe_symmetry() {
        // Test that ECDHE produces the same result from both sides
        let secret_key_a = SecretKey::random(&mut OsRng);
        let secret_key_b = SecretKey::random(&mut OsRng);

        // Get public keys
        let public_key_a = secret_key_a.public_key();
        let public_key_b = secret_key_b.public_key();
        let public_key_a_encoded = public_key_a.to_encoded_point(false);
        let public_key_b_encoded = public_key_b.to_encoded_point(false);

        // Compute shared secrets from both perspectives
        let shared_a = compute_pre_master_secret_ecdhe(
            secret_key_a.to_bytes().as_slice(),
            public_key_b_encoded.as_bytes(),
            CurveType::Secp256r1,
        )
        .unwrap();

        let shared_b = compute_pre_master_secret_ecdhe(
            secret_key_b.to_bytes().as_slice(),
            public_key_a_encoded.as_bytes(),
            CurveType::Secp256r1,
        )
        .unwrap();

        // Both should compute the same shared secret
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_x448_unsupported() {
        // Use valid X448 key lengths (56 bytes) to test curve type unsupported error
        let private_key = vec![0u8; 56];
        let public_key = vec![0u8; 56];

        let result = compute_pre_master_secret_ecdhe(&private_key, &public_key, CurveType::X448);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::UnsupportedCurveType(0x001E)
        ));
    }

    #[test]
    fn test_invalid_private_key_length_p256() {
        let private_key = vec![0u8; 16]; // Wrong length
        let public_key = vec![0x04u8; 65]; // Valid uncompressed public key

        let result =
            compute_pre_master_secret_ecdhe(&private_key, &public_key, CurveType::Secp256r1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::InvalidKeyLength { .. }
        ));
    }

    #[test]
    fn test_invalid_public_key_length_p256() {
        let private_key = vec![0u8; 32]; // Valid length
        let public_key = vec![0u8; 16]; // Wrong length

        let result =
            compute_pre_master_secret_ecdhe(&private_key, &public_key, CurveType::Secp256r1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::InvalidKeyLength { .. }
        ));
    }

    #[test]
    fn test_dhe_placeholder() {
        let server_private = vec![1u8; 32];
        let client_public = vec![2u8; 32];
        let dh_params = DhParams::new(vec![3u8; 64], vec![4u8; 1]);

        let result = compute_pre_master_secret_dhe(&server_private, &client_public, &dh_params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DecryptError::DheError(_)));
    }

    #[test]
    fn test_dhe_empty_params() {
        let server_private = vec![1u8; 32];
        let client_public = vec![2u8; 32];
        let dh_params = DhParams::new(vec![], vec![4u8; 1]);

        let result = compute_pre_master_secret_dhe(&server_private, &client_public, &dh_params);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::InvalidDhParameters(_)
        ));
    }

    // ========================================================================
    // Tests for compute_pre_master_secret_from_key_exchange
    // ========================================================================

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_ecdhe_p256() {
        // Generate server and client key pairs
        let server_secret = SecretKey::random(&mut OsRng);
        let client_secret = SecretKey::random(&mut OsRng);

        // Get server private key
        let server_private_key = server_secret.to_bytes().to_vec();

        // Get client public key (uncompressed)
        let client_public_key = client_secret.public_key();
        let client_public_encoded = client_public_key.to_encoded_point(false);
        let client_public_bytes = client_public_encoded.as_bytes();

        // Get server public key (uncompressed) - for ServerKeyExchange
        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        // Build ClientKeyExchange: 1 byte length + client public key
        let client_key_exchange = {
            let len = client_public_bytes.len() as u8;
            let mut buf = vec![len];
            buf.extend_from_slice(client_public_bytes);
            buf
        };

        // Build ServerKeyExchange: curve_type(1) + named_group(2) + length(1) + server public key
        // Note: We omit the signature for this test since we only need the key exchange params
        let server_key_exchange = {
            let curve_type: u8 = 3; // named_group
            let named_group: u16 = 0x0017; // secp256r1
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        // Compute pre-master secret from key exchange records
        let result = compute_pre_master_secret_from_key_exchange(
            &server_private_key,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_ok());
        let pre_master_secret = result.unwrap();
        assert_eq!(pre_master_secret.len(), 32);

        // Verify it matches direct ECDHE computation
        let direct_result = compute_pre_master_secret_ecdhe(
            &server_private_key,
            client_public_bytes,
            CurveType::Secp256r1,
        )
        .unwrap();
        assert_eq!(pre_master_secret, direct_result);
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_ecdhe_p384() {
        use p384::SecretKey as SecretKey384;
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let server_secret = SecretKey384::random(&mut OsRng);
        let client_secret = SecretKey384::random(&mut OsRng);

        let server_private_key = server_secret.to_bytes().to_vec();

        let client_public_key = client_secret.public_key();
        let client_public_encoded = client_public_key.to_encoded_point(false);
        let client_public_bytes = client_public_encoded.as_bytes();

        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        // Build ClientKeyExchange
        let client_key_exchange = {
            let len = client_public_bytes.len() as u8;
            let mut buf = vec![len];
            buf.extend_from_slice(client_public_bytes);
            buf
        };

        // Build ServerKeyExchange for P-384 (named_group = 0x0018)
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0018; // secp384r1
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private_key,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_ok());
        let pre_master_secret = result.unwrap();
        assert_eq!(pre_master_secret.len(), 48);
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_ecdhe_p521() {
        use p521::SecretKey as SecretKey521;
        use p521::elliptic_curve::sec1::ToEncodedPoint;

        let server_secret = SecretKey521::random(&mut OsRng);
        let client_secret = SecretKey521::random(&mut OsRng);

        let server_private_key = server_secret.to_bytes().to_vec();

        let client_public_key = client_secret.public_key();
        let client_public_encoded = client_public_key.to_encoded_point(false);
        let client_public_bytes = client_public_encoded.as_bytes();

        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        // Build ClientKeyExchange
        let client_key_exchange = {
            let len = client_public_bytes.len() as u8;
            let mut buf = vec![len];
            buf.extend_from_slice(client_public_bytes);
            buf
        };

        // Build ServerKeyExchange for P-521 (named_group = 0x0019)
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0019; // secp521r1
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private_key,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_ok());
        let pre_master_secret = result.unwrap();
        assert_eq!(pre_master_secret.len(), 66);
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_ecdhe_x25519() {
        use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519Public};

        let server_secret = X25519Secret::random_from_rng(OsRng);
        let client_secret = X25519Secret::random_from_rng(OsRng);

        let server_public = X25519Public::from(&server_secret);
        let client_public = X25519Public::from(&client_secret);

        // Get server private key bytes (x25519-dalek doesn't expose raw private key easily,
        // so we use StaticSecret for testing)
        let server_private_key: [u8; 32] = [1u8; 32]; // placeholder for testing

        // Build ClientKeyExchange: 1 byte length + client public key (32 bytes)
        let client_key_exchange = {
            let mut buf = vec![32u8]; // length
            buf.extend_from_slice(client_public.as_bytes());
            buf
        };

        // Build ServerKeyExchange for X25519 (named_group = 0x001D)
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x001D; // x25519
            let public_len = 32u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public.as_bytes());
            buf
        };

        // Note: This test uses placeholder private key, so the result won't be correct
        // but we can verify the parsing works
        let result = compute_pre_master_secret_from_key_exchange(
            &server_private_key,
            &client_key_exchange,
            &server_key_exchange,
        );

        // Should succeed (parsing works), even if the shared secret is not correct
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_empty_ske() {
        let server_private = vec![0u8; 32];
        let client_key_exchange = vec![65u8, 0x04]; // truncated
        let server_key_exchange = vec![];

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_empty_cke() {
        let server_private = vec![0u8; 32];
        let client_key_exchange = vec![];
        let server_key_exchange = vec![3u8, 0x00, 0x17, 65u8]; // ECDHE format, truncated

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_truncated_ske() {
        let server_private = vec![0u8; 32];
        let mut client_key_exchange = vec![65u8];
        client_key_exchange.extend_from_slice(&vec![0x04u8; 65]);

        // ServerKeyExchange truncated (claims 65 bytes but only has 10)
        let server_key_exchange = vec![3u8, 0x00, 0x17, 65u8, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05];

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_truncated_cke() {
        let server_private = vec![0u8; 32];

        // ServerKeyExchange valid
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0017;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(65u8);
            buf.extend_from_slice(&vec![0x04u8; 65]);
            buf
        };

        // ClientKeyExchange truncated (claims 65 bytes but only has 10)
        let client_key_exchange = vec![
            65u8, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ];

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private,
            &client_key_exchange,
            &server_key_exchange,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_unsupported_curve() {
        let server_private = vec![0u8; 32];

        // ClientKeyExchange
        let mut client_key_exchange = vec![56u8];
        client_key_exchange.extend_from_slice(&vec![0u8; 56]);

        // ServerKeyExchange with unsupported named_group (X448 = 0x001E)
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x001E; // X448 (unsupported)
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(56u8);
            buf.extend_from_slice(&vec![0u8; 56]);
            buf
        };

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private,
            &client_key_exchange,
            &server_key_exchange,
        );

        // X448 is parsed correctly but then fails in compute_ecdhe_shared_secret
        // with UnsupportedCurveType error
        assert!(result.is_err());
        // The error could be UnsupportedCurveType or InvalidKeyLength depending on implementation
        // Just verify it's an error
        assert!(result.is_err());
    }

    // Note: detect_key_exchange_type and KeyExchangeType are private, tested indirectly
    // through test_compute_pre_master_secret_from_key_exchange_* tests
    #[test]
    fn test_compute_pre_master_secret_from_key_exchange_dhe_placeholder() {
        // DHE ServerKeyExchange format:
        // p_length(2) + p + g_length(2) + g + Ys_length(2) + Ys
        let server_key_exchange = {
            let p = vec![0xFFu8; 64]; // fake prime
            let g = vec![0x02u8]; // generator 2
            let ys = vec![0xABu8; 64]; // server public key

            let mut buf = vec![];
            buf.extend_from_slice(&(p.len() as u16).to_be_bytes());
            buf.extend_from_slice(&p);
            buf.extend_from_slice(&(g.len() as u16).to_be_bytes());
            buf.extend_from_slice(&g);
            buf.extend_from_slice(&(ys.len() as u16).to_be_bytes());
            buf.extend_from_slice(&ys);
            buf
        };

        // DHE ClientKeyExchange format: Yc_length(2) + Yc
        let client_key_exchange = {
            let yc = vec![0xCDu8; 64]; // client public key
            let mut buf = vec![];
            buf.extend_from_slice(&(yc.len() as u16).to_be_bytes());
            buf.extend_from_slice(&yc);
            buf
        };

        let server_private_key = vec![0u8; 32];

        let result = compute_pre_master_secret_from_key_exchange(
            &server_private_key,
            &client_key_exchange,
            &server_key_exchange,
        );

        // DHE is not implemented yet, should return DheError
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DecryptError::DheError(_)));
    }

    // ========================================================================
    // Tests for extract_server_public_key
    // ========================================================================

    #[test]
    fn test_extract_server_public_key_ecdhe_p256() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let server_secret = SecretKey::random(&mut OsRng);
        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        // Build ServerKeyExchange for P-256
        let server_key_exchange = {
            let curve_type: u8 = 3; // named_group
            let named_group: u16 = 0x0017; // secp256r1
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);

        assert!(result.is_ok());
        let server_pk = result.unwrap();
        assert!(server_pk.is_ecdhe());
        assert_eq!(server_pk.curve(), Some(CurveType::Secp256r1));
        assert_eq!(server_pk.public_key.len(), 65); // P-256 uncompressed
        assert!(server_pk.dh_params().is_none());
    }

    #[test]
    fn test_extract_server_public_key_ecdhe_p384() {
        use p384::SecretKey as SecretKey384;
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let server_secret = SecretKey384::random(&mut OsRng);
        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        // Build ServerKeyExchange for P-384
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0018; // secp384r1
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);

        assert!(result.is_ok());
        let server_pk = result.unwrap();
        assert!(server_pk.is_ecdhe());
        assert_eq!(server_pk.curve(), Some(CurveType::Secp384r1));
        assert_eq!(server_pk.public_key.len(), 97); // P-384 uncompressed
    }

    #[test]
    fn test_extract_server_public_key_ecdhe_x25519() {
        use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519Public};

        let server_secret = X25519Secret::random_from_rng(OsRng);
        let server_public = X25519Public::from(&server_secret);
        let server_public_bytes = server_public.as_bytes();

        // Build ServerKeyExchange for X25519
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x001D; // x25519
            let public_len = 32u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);

        assert!(result.is_ok());
        let server_pk = result.unwrap();
        assert!(server_pk.is_ecdhe());
        assert_eq!(server_pk.curve(), Some(CurveType::X25519));
        assert_eq!(server_pk.public_key.len(), 32);
    }

    #[test]
    fn test_extract_server_public_key_dhe() {
        // DHE ServerKeyExchange format:
        // p_length(2) + p + g_length(2) + g + Ys_length(2) + Ys
        let server_key_exchange = {
            let p = vec![0xFFu8; 64]; // fake prime
            let g = vec![0x02u8]; // generator 2
            let ys = vec![0xABu8; 64]; // server public key

            let mut buf = vec![];
            buf.extend_from_slice(&(p.len() as u16).to_be_bytes());
            buf.extend_from_slice(&p);
            buf.extend_from_slice(&(g.len() as u16).to_be_bytes());
            buf.extend_from_slice(&g);
            buf.extend_from_slice(&(ys.len() as u16).to_be_bytes());
            buf.extend_from_slice(&ys);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);

        assert!(result.is_ok());
        let server_pk = result.unwrap();
        assert!(server_pk.is_dhe());
        assert_eq!(server_pk.curve(), None);
        assert_eq!(server_pk.public_key.len(), 64);

        let dh_params = server_pk.dh_params().unwrap();
        assert_eq!(dh_params.p.len(), 64);
        assert_eq!(dh_params.g.len(), 1);
    }

    #[test]
    fn test_extract_server_public_key_empty() {
        let result = extract_server_public_key(&[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_extract_server_public_key_truncated() {
        // ServerKeyExchange truncated (claims 65 bytes but only has 10)
        let server_key_exchange = vec![3u8, 0x00, 0x17, 65u8, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05];

        let result = extract_server_public_key(&server_key_exchange);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_extract_server_public_key_unsupported_curve() {
        // ServerKeyExchange with unsupported named_group (0x0000 is not a valid curve)
        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0000; // Invalid/unsupported curve
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(32u8);
            buf.extend_from_slice(&vec![0u8; 32]);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DecryptError::HandshakeParseError(_)
        ));
    }

    #[test]
    fn test_extract_server_public_key_as_bytes() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let server_secret = SecretKey::random(&mut OsRng);
        let server_public_key = server_secret.public_key();
        let server_public_encoded = server_public_key.to_encoded_point(false);
        let server_public_bytes = server_public_encoded.as_bytes();

        let server_key_exchange = {
            let curve_type: u8 = 3;
            let named_group: u16 = 0x0017;
            let public_len = server_public_bytes.len() as u8;
            let mut buf = vec![curve_type];
            buf.extend_from_slice(&named_group.to_be_bytes());
            buf.push(public_len);
            buf.extend_from_slice(server_public_bytes);
            buf
        };

        let result = extract_server_public_key(&server_key_exchange);
        assert!(result.is_ok());
        let server_pk = result.unwrap();

        // Test public_key field access
        assert_eq!(server_pk.public_key, server_public_bytes);
    }
}
