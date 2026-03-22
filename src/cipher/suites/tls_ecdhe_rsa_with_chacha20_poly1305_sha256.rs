//! TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8) cipher suite implementation

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use rustls::CipherSuite;

use crate::cipher::trait_def::CipherContext;
use crate::error::{DecryptError, Result};
use crate::types::TlsVersion;

use super::aead_common::{build_tls13_nonce, split_ciphertext_and_tag};

/// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
pub struct TlsEcdheRsaWithChaCha20Poly1305Sha256;

impl CipherContext for TlsEcdheRsaWithChaCha20Poly1305Sha256 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    }

    fn version(&self) -> TlsVersion {
        TlsVersion::Tls12
    }

    fn key_length(&self) -> usize {
        32
    }

    fn iv_length(&self) -> usize {
        12
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn needs_explicit_nonce(&self) -> bool {
        false
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        sequence_number: u64,
    ) -> Result<Vec<u8>> {
        if key.len() != self.key_length() {
            return Err(DecryptError::InvalidKeyLength {
                expected: self.key_length(),
                actual: key.len(),
            });
        }

        if iv.len() != self.iv_length() {
            return Err(DecryptError::InvalidIvLength {
                expected: self.iv_length(),
                actual: iv.len(),
            });
        }
        // TLS 1.2 ChaCha20-Poly1305 uses similar nonce construction as TLS 1.3
        let nonce = build_tls13_nonce(iv, sequence_number)?;

        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| DecryptError::InvalidKeyLength {
                expected: self.key_length(),
                actual: key.len(),
            })?;
        let nonce = Nonce::from_slice(&nonce);

        let (plaintext, tag) =
            split_ciphertext_and_tag(ciphertext, 16).ok_or(DecryptError::InsufficientData)?;
        let plaintext_vec = plaintext.to_vec();
        let mut plaintext_buf = plaintext_vec;
        let tag = Tag::from_slice(tag);

        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut plaintext_buf, tag)
            .map_err(|_| DecryptError::AuthenticationFailed)?;

        Ok(plaintext_buf)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_suite_id() {
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        assert_eq!(
            cipher.suite(),
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        );
    }

    #[test]
    fn test_key_iv_lengths() {
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.iv_length(), 12);
        assert_eq!(cipher.tag_length(), 16);
        assert!(!cipher.needs_explicit_nonce());
    }

    #[test]
    fn test_decrypt_empty() {
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 12];
        let ciphertext = vec![];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InsufficientData)));
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let ciphertext = vec![0u8; 16];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_decrypt_invalid_iv_length() {
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 8];
        let ciphertext = vec![0u8; 16];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidIvLength { .. })));
    }

    #[test]
    fn test_decrypt_with_generated_data() {
        // Test data from tests/testdata/tls_decrypt_test_cases.json
        // Test case: tls12_ecdhe_chacha20poly1305_basic
        let cipher = TlsEcdheRsaWithChaCha20Poly1305Sha256;
        let key = &hex!("4935bdf7cf7e2556e726f99681d7ae3e97f302efb1e95856f395a13cd4042f06");
        let iv = &hex!("6a7ac4936f65dc9717fcff04");
        let record = &hex!(
            "1703030037e19e647ba195705d2bbc3b81c4b211eacade62ec813d2909a8beb79bf0e234a52aff45708c4346422a4ca7f699a67ace6e68dcd9870eca"
        );
        let expected_plaintext = "Hello, TLS 1.2 ECDHE ChaCha20-Poly1305!";
        let aad = &record[..5];
        let ciphertext = &record[5..];
        let result = cipher.decrypt(key, iv, ciphertext, aad, 0).unwrap();
        let decrypted = String::from_utf8(result).unwrap();
        assert_eq!(decrypted, expected_plaintext);
    }
}
