//! Cipher suite registry

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::error::{DecryptError, Result};
use crate::types::CipherSuite;

use crate::cipher::suites::{
    Tls13Aes128GcmSha256, Tls13Aes256GcmSha384, Tls13ChaCha20Poly1305Sha256,
    TlsEcdheRsaWithChaCha20Poly1305Sha256, TlsRsaWithAes128GcmSha256, TlsRsaWithAes256GcmSha384,
};
use crate::cipher::trait_def::CipherContext;

/// Cipher suite registry
///
/// Manages all available cipher suite implementations and supports dynamic registration of new suites
pub struct CipherRegistry {
    ciphers: HashMap<CipherSuite, Arc<dyn CipherContext>>,
}

impl CipherRegistry {
    /// Create a new registry with built-in cipher suites
    pub fn new() -> Self {
        let mut registry = Self {
            ciphers: HashMap::new(),
        };
        registry.register_builtins();
        registry
    }

    /// Register built-in cipher suites
    fn register_builtins(&mut self) {
        // TLS 1.2 AEAD
        self.register(Arc::new(TlsRsaWithAes128GcmSha256));
        self.register(Arc::new(TlsRsaWithAes256GcmSha384));

        // TLS 1.2 ChaCha20-Poly1305
        self.register(Arc::new(TlsEcdheRsaWithChaCha20Poly1305Sha256));

        // TLS 1.3 AEAD
        self.register(Arc::new(Tls13Aes128GcmSha256));
        self.register(Arc::new(Tls13Aes256GcmSha384));
        self.register(Arc::new(Tls13ChaCha20Poly1305Sha256));
    }

    /// Get cipher suite implementation
    pub fn get(&self, suite: CipherSuite) -> Option<Arc<dyn CipherContext>> {
        self.ciphers.get(&suite).cloned()
    }

    /// Get cipher suite implementation, returns error if not found
    pub fn try_get(&self, suite: CipherSuite) -> Result<Arc<dyn CipherContext>> {
        self.get(suite)
            .ok_or_else(|| DecryptError::UnsupportedCipherSuite(suite.to_u16()))
    }

    /// Get cipher suite implementation by u16 ID
    pub fn get_by_id(&self, suite_id: u16) -> Option<Arc<dyn CipherContext>> {
        self.ciphers.get(&CipherSuite::from_u16(suite_id)).cloned()
    }

    /// Get cipher suite implementation by u16 ID, returns error if not found
    pub fn try_get_by_id(&self, suite_id: u16) -> Result<Arc<dyn CipherContext>> {
        self.get_by_id(suite_id)
            .ok_or_else(|| DecryptError::UnsupportedCipherSuite(suite_id))
    }

    /// Get cipher suite implementation by u16 ID, returns error if not found
    pub fn try_get_by_u16(&self, suite_id: u16) -> Result<Arc<dyn CipherContext>> {
        self.ciphers
            .get(&CipherSuite::from_u16(suite_id))
            .cloned()
            .ok_or_else(|| DecryptError::UnsupportedCipherSuite(suite_id))
    }

    /// Register custom cipher suite
    pub fn register(&mut self, cipher: Arc<dyn CipherContext>) {
        let suite = CipherSuite::from(cipher.suite());
        self.ciphers.insert(suite, cipher);
    }

    /// Get list of all supported suites
    pub fn list_suites(&self) -> Vec<CipherSuite> {
        self.ciphers.keys().copied().collect()
    }

    /// Get list of all supported suites as u16 IDs
    pub fn list_suites_as_ids(&self) -> Vec<u16> {
        self.ciphers.keys().map(|suite| suite.to_u16()).collect()
    }

    /// Get global registry (singleton)
    pub fn global() -> &'static Self {
        static GLOBAL: Lazy<CipherRegistry> = Lazy::new(CipherRegistry::new);
        &GLOBAL
    }
}

impl Default for CipherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: Get CipherContext by CipherSuite
pub fn get_cipher(suite: CipherSuite) -> Result<Arc<dyn CipherContext>> {
    CipherRegistry::global().try_get(suite)
}

/// Convenience function: Get CipherContext by u16 ID
pub fn get_cipher_by_id(suite_id: u16) -> Result<Arc<dyn CipherContext>> {
    CipherRegistry::global().try_get_by_id(suite_id)
}

/// Convenience function: Get CipherContext by u16 ID (alias for get_cipher_by_id)
pub fn get_cipher_by_u16(suite_id: u16) -> Result<Arc<dyn CipherContext>> {
    CipherRegistry::global().try_get_by_u16(suite_id)
}

/// Convenience function: Get list of all supported suites
pub fn list_supported_suites() -> Vec<CipherSuite> {
    CipherRegistry::global().list_suites()
}

/// Convenience function: Get list of all supported suites as u16 IDs
pub fn list_supported_suites_as_ids() -> Vec<u16> {
    CipherRegistry::global().list_suites_as_ids()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_ciphers_with_cipher_suite() {
        let registry = CipherRegistry::new();

        // TLS 1.2
        assert!(
            registry
                .get(CipherSuite::TlsRsaWithAes128GcmSha256)
                .is_some()
        );
        assert!(
            registry
                .get(CipherSuite::TlsRsaWithAes256GcmSha384)
                .is_some()
        );

        // TLS 1.3
        assert!(registry.get(CipherSuite::Tls13Aes128GcmSha256).is_some());
        assert!(registry.get(CipherSuite::Tls13Aes256GcmSha384).is_some());
        assert!(
            registry
                .get(CipherSuite::Tls13ChaCha20Poly1305Sha256)
                .is_some()
        );
    }

    #[test]
    fn test_builtin_ciphers_with_u16_id() {
        let registry = CipherRegistry::new();

        // TLS 1.2
        assert!(registry.get_by_id(0x009C).is_some());
        assert!(registry.get_by_id(0x009D).is_some());

        // TLS 1.3
        assert!(registry.get_by_id(0x1301).is_some());
        assert!(registry.get_by_id(0x1302).is_some());
        assert!(registry.get_by_id(0x1303).is_some());
    }

    #[test]
    fn test_unsupported_cipher() {
        let registry = CipherRegistry::new();
        // Use an undefined CipherSuite value
        assert!(registry.get(CipherSuite::Unknown(0xFFFF)).is_none());
    }

    #[test]
    fn test_list_suites() {
        let registry = CipherRegistry::new();
        let suites = registry.list_suites();
        // Should have at least 5 built-in suites
        assert!(suites.len() >= 5);
        // Verify that the returned type is CipherSuite
        for suite in suites {
            assert!(registry.get(suite).is_some());
        }
    }
}
