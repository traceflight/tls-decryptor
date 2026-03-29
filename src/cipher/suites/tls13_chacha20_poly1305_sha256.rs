//! TLS13_CHACHA20_POLY1305_SHA256 (0x1303) cipher suite implementation

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};

use crate::cipher::trait_def::CipherContext;
use crate::error::{DecryptError, Result};
use crate::types::CipherSuite;

use super::aead_common::{build_tls13_nonce, split_ciphertext_and_tag};

/// TLS13_CHACHA20_POLY1305_SHA256 (0x1303)
pub struct Tls13ChaCha20Poly1305Sha256;

impl CipherContext for Tls13ChaCha20Poly1305Sha256 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
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
        let cipher = Tls13ChaCha20Poly1305Sha256;
        assert_eq!(cipher.suite(), CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    }

    #[test]
    fn test_key_iv_lengths() {
        let cipher = Tls13ChaCha20Poly1305Sha256;
        assert_eq!(cipher.key_length(), 32);
        assert_eq!(cipher.iv_length(), 12);
        assert_eq!(cipher.tag_length(), 16);
        assert!(!cipher.needs_explicit_nonce());
    }

    #[test]
    fn test_decrypt_empty() {
        let cipher = Tls13ChaCha20Poly1305Sha256;
        let key = vec![0u8; 32];
        let iv = vec![0u8; 12];
        let ciphertext = vec![];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InsufficientData)));
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let cipher = Tls13ChaCha20Poly1305Sha256;
        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let ciphertext = vec![0u8; 16];
        let aad = vec![];

        let result = cipher.decrypt(&key, &iv, &ciphertext, &aad, 0);
        assert!(matches!(result, Err(DecryptError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_decrypt_invalid_iv_length() {
        let cipher = Tls13ChaCha20Poly1305Sha256;
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
        // Test case: tls13_chacha20poly1305_basic
        let cipher = Tls13ChaCha20Poly1305Sha256;
        let key = &hex!("1e5437171a1807f71297581457874502834672c32aa5f1163bcf2b4c237266ee");
        let iv = &hex!("927e5a952e7f9254eb97ddd6");
        let record = &hex!(
            "17030300326578916b8f0dfbbdfaf2df99e2095a48b5fe0f6ca50fb40c4d44663e47806a1a72f3f5241608f44d1577fc756a18481cea6e"
        );
        // TLS 1.3 inner plaintext includes content type padding: "Hello, TLS 1.3 ChaCha20-Poly1305!" + 0x17
        let expected_inner_plaintext =
            hex!("48656c6c6f2c20544c5320312e332043686143686132302d506f6c79313330352117");
        let aad = &record[..5];
        let ciphertext = &record[5..];
        let result = cipher.decrypt(key, iv, ciphertext, aad, 0).unwrap();
        assert_eq!(result, expected_inner_plaintext);
    }
}
