//! TLS 1.3 utility functions
//!
//! This module provides utility functions for TLS 1.3 key exchange operations.

use crate::error::{DecryptError, Result};
use crate::types::CurveType;
use tls_parser::{
    KeyShareEntry, NamedGroup, TlsClientHelloContents, TlsExtension, TlsServerHelloContents,
};

// Re-export the common ECDHE function for convenience
pub use super::ecdhe::compute_ecdhe_shared_secret;

/// Extracted key share information from TLS 1.3 handshake
#[derive(Debug, Clone)]
pub struct KeyShareData<'a> {
    /// Client's public key from ClientHello key_share extension
    pub client_public_key: &'a [u8],
    /// Server's public key from ServerHello key_share extension
    pub server_public_key: &'a [u8],
    /// Negotiated elliptic curve type
    pub curve: CurveType,
}

/// Convert tls-parser's NamedGroup to our CurveType
fn named_group_to_curve_type(group: NamedGroup) -> Option<CurveType> {
    match group.0 {
        0x0017 => Some(CurveType::Secp256r1), // secp256r1
        0x0018 => Some(CurveType::Secp384r1), // secp384r1
        0x0019 => Some(CurveType::Secp521r1), // secp521r1
        0x001D => Some(CurveType::X25519),    // x25519
        0x001E => Some(CurveType::X448),      // x448
        _ => None,
    }
}

/// Extract client and server public keys from ClientHello and ServerHello messages
///
/// This function parses the key_share extensions from both ClientHello and ServerHello
/// to extract the ephemeral public keys and the negotiated curve type.
///
/// # Arguments
/// - `client_hello`: Parsed ClientHello message from tls-parser
/// - `server_hello`: Parsed ServerHello message from tls-parser
///
/// # Returns
/// - `Ok(Some(KeyShareData))` if key shares were successfully extracted
/// - `Ok(None)` if ServerHello is a HelloRetryRequest (needs to resend ClientHello)
/// - `Err(DecryptError)` if parsing failed or key_share extensions are missing
///
/// # Note
/// In TLS 1.3, the key_share extension contains the ephemeral public keys.
/// The ServerHello may be a HelloRetryRequest, in which case this function returns `Ok(None)`.
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::extract_keys_from_hello_messages;
/// use tls_parser::{TlsMessageHandshake, TlsClientHelloContents, TlsServerHelloContents};
///
/// // Parse ClientHello and ServerHello from TLS records
/// let client_hello: &TlsClientHelloContents = ...;
/// let server_hello: &TlsServerHelloContents = ...;
///
/// let key_data = extract_keys_from_hello_messages(client_hello, server_hello)?;
/// if let Some(data) = key_data {
///     println!("Curve: {:?}", data.curve);
///     println!("Client public key: {} bytes", data.client_public_key.len());
///     println!("Server public key: {} bytes", data.server_public_key.len());
/// } else {
///     // HelloRetryRequest received, need to resend ClientHello with new key share
///     println!("HelloRetryRequest received, need to resend ClientHello");
/// }
/// ```
pub fn extract_keys_from_hello_messages<'a>(
    client_hello: &'a TlsClientHelloContents<'a>,
    server_hello: &'a TlsServerHelloContents<'a>,
) -> Result<Option<KeyShareData<'a>>> {
    // Check if this is a HelloRetryRequest by checking the random value
    // HelloRetryRequest has a special random value (all 0xCF, 0x21, etc.)
    const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE9, 0xA9, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];

    if server_hello.random == HRR_RANDOM {
        // This is a HelloRetryRequest, return None to indicate we need to resend ClientHello
        return Ok(None);
    }

    // Parse ClientHello extensions using tls-parser's parse_tls_extensions
    let client_extensions = client_hello
        .ext
        .as_ref()
        .and_then(|ext_data| {
            tls_parser::parse_tls_extensions(ext_data)
                .ok()
                .map(|(_, exts)| exts)
        })
        .unwrap_or_default();

    // Parse ServerHello extensions using tls-parser's parse_tls_extensions
    let server_extensions = server_hello
        .ext
        .as_ref()
        .and_then(|ext_data| {
            tls_parser::parse_tls_extensions(ext_data)
                .ok()
                .map(|(_, exts)| exts)
        })
        .unwrap_or_default();

    // Find key_share extension in ClientHello
    let client_key_share = client_extensions.iter().find_map(|ext| match ext {
        TlsExtension::KeyShare(data) => Some(data),
        _ => None,
    });

    // Find key_share extension in ServerHello
    let server_key_share = server_extensions.iter().find_map(|ext| match ext {
        TlsExtension::KeyShare(data) => Some(data),
        _ => None,
    });

    // Both key shares must be present
    let client_data = client_key_share.ok_or_else(|| {
        DecryptError::KeyDerivationFailed("ClientHello missing key_share extension".to_string())
    })?;

    let server_data = server_key_share.ok_or_else(|| {
        DecryptError::KeyDerivationFailed("ServerHello missing key_share extension".to_string())
    })?;

    // Parse key share entries from ClientHello
    // ClientHello may have multiple key shares, we take the first one
    let client_entries = parse_key_share_entries(client_data)?;
    let client_entry = client_entries.first().ok_or_else(|| {
        DecryptError::KeyDerivationFailed("ClientHello has no key share entries".to_string())
    })?;

    // Parse key share entries from ServerHello
    // ServerHello has exactly one key share entry
    let server_entries = parse_key_share_entries(server_data)?;
    let server_entry = server_entries.first().ok_or_else(|| {
        DecryptError::KeyDerivationFailed("ServerHello has no key share entries".to_string())
    })?;

    // Verify both use the same group
    if client_entry.group.0 != server_entry.group.0 {
        return Err(DecryptError::KeyDerivationFailed(
            "Client and server key_share groups do not match".to_string(),
        ));
    }

    // Convert NamedGroup to CurveType
    let curve = named_group_to_curve_type(client_entry.group)
        .ok_or_else(|| DecryptError::UnsupportedCurveType(client_entry.group.0))?;

    Ok(Some(KeyShareData {
        client_public_key: client_entry.kx,
        server_public_key: server_entry.kx,
        curve,
    }))
}

/// Parse key share entries from key_share extension data
///
/// The key_share extension data format is:
/// struct {
///     KeyShareEntry entries<0..2^16-1>;
/// } KeyShare;
///
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
fn parse_key_share_entries(data: &[u8]) -> Result<Vec<KeyShareEntry<'_>>> {
    if data.is_empty() {
        return Err(DecryptError::KeyDerivationFailed(
            "key_share extension data is empty".to_string(),
        ));
    }

    let entries_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + entries_len || entries_len == 0 {
        return Err(DecryptError::KeyDerivationFailed(
            "key_share extension data is too short".to_string(),
        ));
    }

    let entries_data = &data[2..2 + entries_len];
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset < entries_data.len() {
        if offset + 4 > entries_data.len() {
            break;
        }

        let group = NamedGroup(u16::from_be_bytes([
            entries_data[offset],
            entries_data[offset + 1],
        ]));
        let kx_len =
            u16::from_be_bytes([entries_data[offset + 2], entries_data[offset + 3]]) as usize;

        if offset + 4 + kx_len > entries_data.len() {
            break;
        }

        let kx = &entries_data[offset + 4..offset + 4 + kx_len];
        entries.push(KeyShareEntry { group, kx });
        offset += 4 + kx_len;
    }

    if entries.is_empty() {
        return Err(DecryptError::KeyDerivationFailed(
            "No valid key share entries found".to_string(),
        ));
    }

    Ok(entries)
}

/// Compute ECDHE shared secret for TLS 1.3
///
/// Given the ephemeral private key from one side and the public key from the other side,
/// compute the shared secret used in TLS 1.3 key derivation.
///
/// This is a wrapper around the common [`compute_ecdhe_shared_secret`] function.
///
/// # Arguments
/// - `private_key`: The ephemeral private key in raw bytes
/// - `public_key`: The peer's public key in TLS key_share format (uncompressed point for NIST curves, raw bytes for X25519)
/// - `curve`: The named group (elliptic curve) being used
///
/// # Returns
/// - `Ok(Vec<u8>)`: The computed shared secret
/// - `Err(DecryptError)`: If key computation fails
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::{compute_shared_secret_tls13, CurveType};
///
/// // Server's ephemeral private key (32 bytes for P-256)
/// let server_private_key = vec![0u8; 32];
///
/// // Client's public key from key_share extension (65 bytes for P-256 uncompressed)
/// let client_public_key = vec![0x04, /* 32 bytes X coordinate */, /* 32 bytes Y coordinate */];
///
/// // Compute ECDHE shared secret for TLS 1.3 key derivation
/// let shared_secret = compute_shared_secret_tls13(
///     &server_private_key,
///     &client_public_key,
///     CurveType::Secp256r1,
/// )?;
/// ```
pub fn compute_shared_secret_tls13(
    private_key: &[u8],
    public_key: &[u8],
    curve: CurveType,
) -> Result<Vec<u8>> {
    compute_ecdhe_shared_secret(private_key, public_key, curve)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_group_to_curve_type() {
        assert_eq!(
            named_group_to_curve_type(NamedGroup(0x0017)),
            Some(CurveType::Secp256r1)
        );
        assert_eq!(
            named_group_to_curve_type(NamedGroup(0x0018)),
            Some(CurveType::Secp384r1)
        );
        assert_eq!(
            named_group_to_curve_type(NamedGroup(0x0019)),
            Some(CurveType::Secp521r1)
        );
        assert_eq!(
            named_group_to_curve_type(NamedGroup(0x001D)),
            Some(CurveType::X25519)
        );
        assert_eq!(
            named_group_to_curve_type(NamedGroup(0x001E)),
            Some(CurveType::X448)
        );
        assert_eq!(named_group_to_curve_type(NamedGroup(0x0000)), None);
    }

    #[test]
    fn test_parse_key_share_entries() {
        // Build KeyShare extension data: entries_len (2) + entries
        let mut ext = vec![0x00, 0x24]; // 36 bytes of entries
        // Entry 1: group (2) + kx_len (2) + kx_data (32)
        ext.extend_from_slice(&0x0017u16.to_be_bytes()); // secp256r1
        ext.extend_from_slice(&0x0020u16.to_be_bytes()); // 32 bytes
        ext.extend_from_slice(&[0u8; 32]);

        let result = parse_key_share_entries(&ext);
        assert!(result.is_ok());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group.0, 0x0017);
        assert_eq!(entries[0].kx.len(), 32);
    }

    #[test]
    fn test_compute_shared_secret_tls13_p256() {
        use p256::SecretKey;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use rand::rngs::OsRng;

        let secret_key_a = SecretKey::random(&mut OsRng);
        let secret_key_b = SecretKey::random(&mut OsRng);

        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(false);
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        let private_key_a_bytes = secret_key_a.to_bytes();

        let shared_secret = compute_shared_secret_tls13(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp256r1,
        )
        .unwrap();

        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_compute_shared_secret_tls13_x25519() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

        let secret_a = StaticSecret::random_from_rng(OsRng);
        let secret_b = StaticSecret::random_from_rng(OsRng);

        let public_a = X25519PublicKey::from(&secret_a);
        let public_b = X25519PublicKey::from(&secret_b);

        let shared_a = compute_shared_secret_tls13(
            secret_a.as_bytes(),
            public_b.as_bytes(),
            CurveType::X25519,
        )
        .unwrap();

        let shared_b = compute_shared_secret_tls13(
            secret_b.as_bytes(),
            public_a.as_bytes(),
            CurveType::X25519,
        )
        .unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }
}
