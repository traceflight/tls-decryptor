//! AEAD decryption common helper functions
//!
//! Provides common logic for TLS 1.2 and TLS 1.3 AEAD decryption

use crate::error::DecryptError;

/// TLS 1.2 AEAD nonce construction
///
/// TLS 1.2 AEAD (e.g., GCM) nonce format:
/// - 4-byte salt (from key derivation, passed as iv parameter)
/// - 8-byte explicit_nonce (ciphertext prefix)
///
/// # Returns
/// 12-byte complete nonce (salt || explicit_nonce)
///
/// # Errors
/// Returns an error if `salt` length is not 4 bytes or `explicit_nonce` length is not 8 bytes
#[inline]
pub fn build_tls12_nonce(salt: &[u8], explicit_nonce: &[u8]) -> Result<[u8; 12], DecryptError> {
    if salt.len() != 4 {
        return Err(DecryptError::InvalidIvLength {
            expected: 4,
            actual: salt.len(),
        });
    }
    if explicit_nonce.len() != 8 {
        return Err(DecryptError::InsufficientData);
    }
    let mut full_nonce = [0u8; 12];
    full_nonce[..4].copy_from_slice(salt);
    full_nonce[4..].copy_from_slice(explicit_nonce);
    Ok(full_nonce)
}

/// TLS 1.3 nonce calculation
///
/// TLS 1.3 nonce = static_iv XOR sequence_number
/// sequence_number is 8 bytes, right-aligned XORed into the last 8 bytes of the nonce
///
/// # Returns
/// 12-byte nonce (iv XOR sequence_number)
///
/// # Errors
/// Returns an error if `iv` length is not 12 bytes
#[inline]
pub fn build_tls13_nonce(iv: &[u8], sequence_number: u64) -> Result<[u8; 12], DecryptError> {
    if iv.len() != 12 {
        return Err(DecryptError::InvalidIvLength {
            expected: 12,
            actual: iv.len(),
        });
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);

    // XOR with sequence number (big-endian, right-aligned)
    for (i, byte) in sequence_number.to_be_bytes().iter().enumerate() {
        nonce_bytes[i + 4] ^= byte;
    }
    Ok(nonce_bytes)
}

/// Extract explicit_nonce and encrypted_data_with_tag from TLS 1.2 AEAD ciphertext
///
/// TLS 1.2 AEAD ciphertext format: explicit_nonce (8 bytes) || encrypted_data || tag
#[inline]
pub fn split_tls12_ciphertext<'a>(ciphertext: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if ciphertext.len() < 8 {
        return None;
    }
    let explicit_nonce = &ciphertext[..8];
    let encrypted_data_with_tag = &ciphertext[8..];
    Some((explicit_nonce, encrypted_data_with_tag))
}

/// Separate ciphertext and tag from AEAD ciphertext
///
/// AEAD ciphertext format: encrypted_data || tag (tag_length bytes)
#[inline]
pub fn split_ciphertext_and_tag<'a>(
    data: &'a [u8],
    tag_length: usize,
) -> Option<(&'a [u8], &'a [u8])> {
    if data.len() < tag_length {
        return None;
    }
    let tag_offset = data.len() - tag_length;
    let plaintext = &data[..tag_offset];
    let tag = &data[tag_offset..];
    Some((plaintext, tag))
}

/// Validate key and IV lengths
#[inline]
pub fn validate_key_iv_length(
    key: &[u8],
    iv: &[u8],
    expected_key_len: usize,
    expected_iv_len: usize,
) -> Result<(), crate::error::DecryptError> {
    use crate::error::DecryptError;

    if key.len() != expected_key_len {
        return Err(DecryptError::InvalidKeyLength {
            expected: expected_key_len,
            actual: key.len(),
        });
    }

    if iv.len() != expected_iv_len {
        return Err(DecryptError::InvalidIvLength {
            expected: expected_iv_len,
            actual: iv.len(),
        });
    }

    Ok(())
}
