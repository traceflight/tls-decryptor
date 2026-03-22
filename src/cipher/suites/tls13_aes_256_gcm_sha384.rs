//! TLS13_AES_256_GCM_SHA384 (0x1302) cipher suite implementation

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use rustls::CipherSuite;

use crate::cipher::trait_def::CipherContext;
use crate::error::{DecryptError, Result};
use crate::types::TlsVersion;

use super::aead_common::{build_tls13_nonce, split_ciphertext_and_tag};

/// TLS13_AES_256_GCM_SHA384 (0x1302)
pub struct Tls13Aes256GcmSha384;

impl CipherContext for Tls13Aes256GcmSha384 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_AES_256_GCM_SHA384
    }

    fn version(&self) -> TlsVersion {
        TlsVersion::Tls13
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

        let nonce = build_tls13_nonce(iv, sequence_number)?;

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| DecryptError::InvalidKeyLength {
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
        let cipher = Tls13Aes256GcmSha384;
        assert_eq!(cipher.suite(), CipherSuite::TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_key_iv_lengths() {
        let cipher = Tls13Aes256GcmSha384;
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.iv_length(), 12);
        assert_eq!(cipher.tag_length(), 16);
        assert!(!cipher.needs_explicit_nonce());
    }

    #[test]
    fn test_decrypt_empty() {
        let cipher = Tls13Aes256GcmSha384;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 12];
        let ciphertext = vec![];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InsufficientData)));
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let cipher = Tls13Aes256GcmSha384;
        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let ciphertext = vec![0u8; 16];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_decrypt_invalid_iv_length() {
        let cipher = Tls13Aes256GcmSha384;
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
        // Test case: tls13_aes256gcm_basic
        let cipher = Tls13Aes256GcmSha384;
        let key = &hex!("7c6b216701090374b5d473fb65d7be66ba04b5da921a744a4e15b54a1efb5a95");
        let iv = &hex!("7183c6cebed64f9f7ef743b0");
        let record = &hex!(
            "170303002c601734c64ed8844a4188878954be6723065f1f23c9d03bc260743fb640677e50e41d85c988e3e2551c6b999e"
        );
        // TLS 1.3 inner plaintext includes content type padding: "Hello, TLS 1.3 AES-256-GCM!" + 0x17
        let expected_inner_plaintext =
            hex!("48656c6c6f2c20544c5320312e33204145532d3235362d47434d2117");
        let aad = &record[..5];
        let ciphertext = &record[5..];
        let result = cipher.decrypt(key, iv, ciphertext, aad, 0).unwrap();
        assert_eq!(result, expected_inner_plaintext);
    }
}
