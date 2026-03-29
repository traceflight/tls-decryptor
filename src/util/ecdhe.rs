//! ECDHE shared secret computation
//!
//! This module provides common ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
//! shared secret computation functions used by both TLS 1.2 and TLS 1.3.
//!
//! The mathematical computation is identical for both TLS versions:
//! - For NIST curves (P-256, P-384, P-521): uses ECDH to compute the x-coordinate
//!   of the resulting point as the shared secret
//! - For Montgomery curves (X25519, X448): uses the native Diffie-Hellman function

use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, SecretKey};
use p384::{
    AffinePoint as AffinePoint384, EncodedPoint as EncodedPoint384, SecretKey as SecretKey384,
};
use p521::{
    AffinePoint as AffinePoint521, EncodedPoint as EncodedPoint521, SecretKey as SecretKey521,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{DecryptError, Result};
use crate::types::CurveType;

/// Compute ECDHE shared secret
///
/// Given the ephemeral private key from one side and the public key from the other side,
/// compute the shared secret (ECDH result).
///
/// This function is used by both TLS 1.2 (as pre-master secret) and TLS 1.3 (as shared secret).
/// The mathematical computation is identical for both versions.
///
/// # Arguments
/// - `private_key`: The ephemeral private key in raw bytes
/// - `public_key`: The peer's public key (uncompressed point for NIST curves, raw bytes for X25519)
/// - `curve`: The elliptic curve type
///
/// # Returns
/// - `Ok(Vec<u8>)`: The computed shared secret (x-coordinate of ECDH result)
/// - `Err(DecryptError)`: If key computation fails
///
/// # Example
/// ```rust,ignore
/// use tls_decryptor::util::compute_ecdhe_shared_secret;
/// use tls_decryptor::types::CurveType;
///
/// // Private key (32 bytes for P-256)
/// let private_key = vec![0u8; 32];
///
/// // Public key (65 bytes uncompressed for P-256: 0x04 prefix + 32 bytes X + 32 bytes Y)
/// let public_key = vec![0x04, /* 32 bytes X coordinate */, /* 32 bytes Y coordinate */];
///
/// // Compute ECDHE shared secret
/// let shared_secret = compute_ecdhe_shared_secret(
///     &private_key,
///     &public_key,
///     CurveType::Secp256r1,
/// )?;
/// ```
pub fn compute_ecdhe_shared_secret(
    private_key: &[u8],
    public_key: &[u8],
    curve: CurveType,
) -> Result<Vec<u8>> {
    // Validate key lengths using CurveType methods
    if !curve.is_valid_private_key_length(private_key.len()) {
        return Err(DecryptError::InvalidKeyLength {
            expected: curve.private_key_length(),
            actual: private_key.len(),
        });
    }

    if !curve.is_valid_public_key_length(public_key.len()) {
        return Err(DecryptError::InvalidKeyLength {
            expected: curve.public_key_uncompressed_length(),
            actual: public_key.len(),
        });
    }

    match curve {
        CurveType::Secp256r1 => compute_ecdhe_p256(private_key, public_key),
        CurveType::Secp384r1 => compute_ecdhe_p384(private_key, public_key),
        CurveType::Secp521r1 => compute_ecdhe_p521(private_key, public_key),
        CurveType::X25519 => compute_ecdhe_x25519(private_key, public_key),
        CurveType::X448 => Err(DecryptError::UnsupportedCurveType(0x001E)),
    }
}

/// Compute ECDHE shared secret for P-256 (secp256r1)
fn compute_ecdhe_p256(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    // Parse private key
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|e| DecryptError::CryptoError(format!("Invalid P-256 private key: {}", e)))?;

    // Parse public key
    let encoded_point = EncodedPoint::from_bytes(public_key).map_err(|e| {
        DecryptError::CryptoError(format!("Invalid P-256 public key format: {}", e))
    })?;

    // Decode as AffinePoint
    let affine_point = AffinePoint::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| DecryptError::CryptoError("Invalid P-256 public key point".to_string()))?;

    // Compute shared secret using ECDH
    let shared_secret = p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), affine_point);

    // The shared secret is the x-coordinate of the resulting point
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute ECDHE shared secret for P-384 (secp384r1)
fn compute_ecdhe_p384(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    // Parse private key
    let secret_key = SecretKey384::from_slice(private_key)
        .map_err(|e| DecryptError::CryptoError(format!("Invalid P-384 private key: {}", e)))?;

    // Parse public key
    let encoded_point = EncodedPoint384::from_bytes(public_key).map_err(|e| {
        DecryptError::CryptoError(format!("Invalid P-384 public key format: {}", e))
    })?;

    // Decode as AffinePoint
    let affine_point = AffinePoint384::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| DecryptError::CryptoError("Invalid P-384 public key point".to_string()))?;

    // Compute shared secret using ECDH
    let shared_secret = p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), affine_point);

    // The shared secret is the x-coordinate of the resulting point
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute ECDHE shared secret for P-521 (secp521r1)
fn compute_ecdhe_p521(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    // Parse private key
    let secret_key = SecretKey521::from_slice(private_key)
        .map_err(|e| DecryptError::CryptoError(format!("Invalid P-521 private key: {}", e)))?;

    // Parse public key
    let encoded_point = EncodedPoint521::from_bytes(public_key).map_err(|e| {
        DecryptError::CryptoError(format!("Invalid P-521 public key format: {}", e))
    })?;

    // Decode as AffinePoint
    let affine_point = AffinePoint521::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or_else(|| DecryptError::CryptoError("Invalid P-521 public key point".to_string()))?;

    // Compute shared secret using ECDH
    let shared_secret = p521::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), affine_point);

    // The shared secret is the x-coordinate of the resulting point
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Compute ECDHE shared secret for X25519
fn compute_ecdhe_x25519(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    // Parse private key (X25519 uses 32-byte keys)
    let secret_key_bytes: [u8; 32] =
        private_key
            .try_into()
            .map_err(|_| DecryptError::InvalidKeyLength {
                expected: 32,
                actual: private_key.len(),
            })?;
    let secret_key = StaticSecret::from(secret_key_bytes);

    // Parse public key
    let public_key_bytes: [u8; 32] =
        public_key
            .try_into()
            .map_err(|_| DecryptError::InvalidKeyLength {
                expected: 32,
                actual: public_key.len(),
            })?;
    let public_key = X25519PublicKey::from(public_key_bytes);

    // Compute shared secret
    let shared_secret = secret_key.diffie_hellman(&public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    #[test]
    fn test_compute_ecdhe_p256() {
        // Generate two key pairs
        let secret_key_a = SecretKey::random(&mut OsRng);
        let secret_key_b = SecretKey::random(&mut OsRng);

        // Get public key B (uncompressed)
        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(false);
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        // Get private key A
        let private_key_a_bytes = secret_key_a.to_bytes();

        // Compute shared secret from A's perspective
        let shared_secret_a = compute_ecdhe_shared_secret(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp256r1,
        )
        .unwrap();

        // Compute shared secret from B's perspective
        let public_key_a = secret_key_a.public_key();
        let public_key_a_encoded = public_key_a.to_encoded_point(false);
        let public_key_a_bytes = public_key_a_encoded.as_bytes();
        let private_key_b_bytes = secret_key_b.to_bytes();

        let shared_secret_b = compute_ecdhe_shared_secret(
            private_key_b_bytes.as_slice(),
            public_key_a_bytes,
            CurveType::Secp256r1,
        )
        .unwrap();

        // Both should compute the same shared secret
        assert_eq!(shared_secret_a, shared_secret_b);
        assert_eq!(shared_secret_a.len(), 32);
    }

    #[test]
    fn test_compute_ecdhe_p256_compressed_public_key() {
        let secret_key_a = SecretKey::random(&mut OsRng);
        let secret_key_b = SecretKey::random(&mut OsRng);

        // Use compressed public key (33 bytes)
        let public_key_b = secret_key_b.public_key();
        let public_key_b_encoded = public_key_b.to_encoded_point(true); // compressed
        let public_key_b_bytes = public_key_b_encoded.as_bytes();

        assert_eq!(public_key_b_bytes.len(), 33);

        let private_key_a_bytes = secret_key_a.to_bytes();

        let shared_secret = compute_ecdhe_shared_secret(
            private_key_a_bytes.as_slice(),
            public_key_b_bytes,
            CurveType::Secp256r1,
        )
        .unwrap();

        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_invalid_private_key_length() {
        let private_key = vec![0u8; 16]; // Wrong length for P-256
        let public_key = vec![0x04u8; 65]; // Valid uncompressed length

        let result = compute_ecdhe_shared_secret(&private_key, &public_key, CurveType::Secp256r1);

        assert!(result.is_err());
        if let Err(DecryptError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        }
    }

    #[test]
    fn test_invalid_public_key_length() {
        let private_key = vec![0u8; 32]; // Valid length for P-256
        let public_key = vec![0x04u8; 50]; // Wrong length

        let result = compute_ecdhe_shared_secret(&private_key, &public_key, CurveType::Secp256r1);

        assert!(result.is_err());
        if let Err(DecryptError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 65);
            assert_eq!(actual, 50);
        }
    }

    #[test]
    fn test_x448_unsupported() {
        let private_key = vec![0u8; 56];
        let public_key = vec![0u8; 56];

        let result = compute_ecdhe_shared_secret(&private_key, &public_key, CurveType::X448);

        assert!(result.is_err());
        if let Err(DecryptError::UnsupportedCurveType(code)) = result {
            assert_eq!(code, 0x001E);
        }
    }
}
