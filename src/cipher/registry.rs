//! Cipher suite registry

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use rustls::CipherSuite;

use crate::error::{DecryptError, Result};

use crate::cipher::suites::{
    Tls13Aes128GcmSha256, Tls13Aes256GcmSha384, Tls13ChaCha20Poly1305Sha256,
    TlsRsaWithAes128GcmSha256, TlsRsaWithAes256GcmSha384,
};
use crate::cipher::trait_def::CipherContext;

/// Cipher suite registry
///
/// Manages all available cipher suite implementations and supports dynamic registration of new suites
pub struct CipherRegistry {
    ciphers: HashMap<u16, Arc<dyn CipherContext>>,
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

        // TLS 1.3 AEAD
        self.register(Arc::new(Tls13Aes128GcmSha256));
        self.register(Arc::new(Tls13Aes256GcmSha384));
        self.register(Arc::new(Tls13ChaCha20Poly1305Sha256));
    }

    /// Get cipher suite implementation
    pub fn get(&self, suite: CipherSuite) -> Option<Arc<dyn CipherContext>> {
        self.ciphers.get(&u16::from(suite)).cloned()
    }

    /// Get cipher suite implementation, returns error if not found
    pub fn try_get(&self, suite: CipherSuite) -> Result<Arc<dyn CipherContext>> {
        self.get(suite)
            .ok_or_else(|| DecryptError::UnsupportedCipherSuite(u16::from(suite)))
    }

    /// Get cipher suite implementation by u16 ID, returns error if not found
    pub fn try_get_by_id(&self, suite_id: u16) -> Result<Arc<dyn CipherContext>> {
        self.ciphers
            .get(&suite_id)
            .cloned()
            .ok_or_else(|| DecryptError::UnsupportedCipherSuite(suite_id))
    }

    /// Register custom cipher suite
    pub fn register(&mut self, cipher: Arc<dyn CipherContext>) {
        self.ciphers.insert(u16::from(cipher.suite()), cipher);
    }

    /// Get list of all supported suites
    pub fn list_suites(&self) -> Vec<CipherSuite> {
        self.ciphers
            .keys()
            .map(|&id| CipherSuite::from(id))
            .collect()
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

/// Convenience function: Get CipherContext by CipherSuite ID
pub fn get_cipher_by_id(suite_id: u16) -> Result<Arc<dyn CipherContext>> {
    CipherRegistry::global().try_get_by_id(suite_id)
}

/// Convenience function: Get list of all supported suites
pub fn list_supported_suites() -> Vec<CipherSuite> {
    CipherRegistry::global().list_suites()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_ciphers() {
        let registry = CipherRegistry::new();

        // TLS 1.2
        assert!(
            registry
                .get(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256)
                .is_some()
        );
        assert!(
            registry
                .get(CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384)
                .is_some()
        );

        // TLS 1.3
        assert!(
            registry
                .get(CipherSuite::TLS13_AES_128_GCM_SHA256)
                .is_some()
        );
        assert!(
            registry
                .get(CipherSuite::TLS13_AES_256_GCM_SHA384)
                .is_some()
        );
        assert!(
            registry
                .get(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
                .is_some()
        );
    }

    #[test]
    fn test_unsupported_cipher() {
        let registry = CipherRegistry::new();
        // Use an undefined CipherSuite value
        assert!(registry.get(CipherSuite::from(0xFFFF)).is_none());
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
