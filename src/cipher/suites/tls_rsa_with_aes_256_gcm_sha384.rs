//! TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D) cipher suite implementation

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use rustls::CipherSuite;

use crate::cipher::trait_def::CipherContext;
use crate::error::{DecryptError, Result};
use crate::types::TlsVersion;

use super::aead_common::{split_ciphertext_and_tag, split_tls12_ciphertext};

/// TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)
pub struct TlsRsaWithAes256GcmSha384;

impl CipherContext for TlsRsaWithAes256GcmSha384 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384
    }

    fn version(&self) -> TlsVersion {
        TlsVersion::Tls12
    }

    fn key_length(&self) -> usize {
        32 // AES-256
    }

    fn iv_length(&self) -> usize {
        4 // explicit nonce (TLS 1.2 AEAD)
    }

    fn tag_length(&self) -> usize {
        16
    }

    fn needs_explicit_nonce(&self) -> bool {
        true
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        _sequence_number: u64,
    ) -> Result<Vec<u8>> {
        let (explicit_nonce, encrypted_data_with_tag) =
            split_tls12_ciphertext(ciphertext).ok_or(DecryptError::InsufficientData)?;

        if encrypted_data_with_tag.len() < 16 {
            return Err(DecryptError::InsufficientData);
        }

        if key.len() != self.key_length() {
            return Err(DecryptError::InvalidKeyLength {
                expected: self.key_length(),
                actual: key.len(),
            });
        }

        // Validate IV length (validate before constructing nonce to avoid panic)
        if iv.len() != self.iv_length() {
            return Err(DecryptError::InvalidIvLength {
                expected: self.iv_length(),
                actual: iv.len(),
            });
        }

        let full_nonce = super::aead_common::build_tls12_nonce(iv, explicit_nonce)?;

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| DecryptError::InvalidKeyLength {
                expected: self.key_length(),
                actual: key.len(),
            })?;
        let nonce = Nonce::from_slice(&full_nonce);

        let (plaintext, tag) = split_ciphertext_and_tag(encrypted_data_with_tag, 16)
            .ok_or(DecryptError::InsufficientData)?;
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
        let cipher = TlsRsaWithAes256GcmSha384;
        assert_eq!(cipher.suite(), CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_key_iv_lengths() {
        let cipher = TlsRsaWithAes256GcmSha384;
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.iv_length(), 4);
        assert_eq!(cipher.tag_length(), 16);
        assert!(cipher.needs_explicit_nonce());
    }

    #[test]
    fn test_decrypt_empty() {
        let cipher = TlsRsaWithAes256GcmSha384;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 4];
        let ciphertext = vec![];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InsufficientData)));
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let cipher = TlsRsaWithAes256GcmSha384;
        let key = vec![0u8; 16];
        let iv = vec![0u8; 4];
        // TLS 1.2: explicit_nonce (8) + tag (16) = 24 bytes minimum
        let ciphertext = vec![0u8; 24];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_decrypt_invalid_iv_length() {
        let cipher = TlsRsaWithAes256GcmSha384;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 8];
        // TLS 1.2: explicit_nonce (8) + tag (16) = 24 bytes minimum
        let ciphertext = vec![0u8; 24];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidIvLength { .. })));
    }

    #[test]
    fn test_decrypt_with_generated_data() {
        // Test data from tests/testdata/tls_decrypt_test_cases.json
        // Test case: tls12_rsa_aes256gcm_basic
        let cipher = TlsRsaWithAes256GcmSha384;
        let key = &hex!("cc8d96c9e83cf0ff3db902e88f1610d7c8db404a1e89d8b9e4e235b930882cdc");
        let iv = &hex!("4beb4cf2");
        let record = &hex!(
            "170303003700000000000000007c7f169ceff04614337abb9173a80a4733c94dcd05d4844fd7572d4d1be12c75af49efa3737e2dbf9218d61704f97f"
        );
        let expected_plaintext = "Hello, TLS 1.2 RSA AES-256-GCM!";
        let aad = &record[..5];
        let ciphertext = &record[5..];
        let result = cipher.decrypt(key, iv, ciphertext, aad, 0).unwrap();
        let decrypted = String::from_utf8(result).unwrap();
        assert_eq!(decrypted, expected_plaintext);
    }
}
