//! TLS key derivation functions
//!
//! This module provides key derivation functionality for TLS 1.2 and TLS 1.3.

use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rustls::CipherSuite;
use sha2::{Sha256, Sha384};

use crate::error::{DecryptError, Result};
use crate::types::{SessionKey, TlsVersion};

/// Derive TLS 1.2 session keys from private key and handshake parameters
///
/// # Arguments
/// - `client_random`: Client random (32 bytes)
/// - `server_random`: Server random (32 bytes)
/// - `pre_master_secret`: Pre-master secret (obtained by decrypting with private key)
/// - `cipher_suite`: Negotiated cipher suite
///
/// # Returns
/// Derived session key
pub fn derive_keys_tls12(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    pre_master_secret: &[u8],
    cipher_suite: CipherSuite,
) -> Result<SessionKey> {
    // 1. Compute Master Secret
    // master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
    let seed = [client_random.as_slice(), server_random.as_slice()].concat();
    let master_secret = prf_tls12(pre_master_secret, b"master secret", &seed, 48)?;

    // 2. Compute Key Block
    // key_block = PRF(master_secret, "key expansion", server_random + client_random)
    let key_expansion_seed = [server_random.as_slice(), client_random.as_slice()].concat();

    // Determine required key material length based on cipher suite
    let (key_len, iv_len) = get_key_iv_lengths_tls12(cipher_suite);
    // key_block = client_write_key + server_write_key + client_write_IV + server_write_IV
    let key_block_len = 2 * key_len + 2 * iv_len;
    let key_block = prf_tls12(
        &master_secret,
        b"key expansion",
        &key_expansion_seed,
        key_block_len,
    )?;

    // 3. Extract keys and IVs
    let mut offset = 0;
    let client_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let server_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let client_write_iv = key_block[offset..offset + iv_len].to_vec();
    offset += iv_len;
    let server_write_iv = key_block[offset..offset + iv_len].to_vec();

    Ok(SessionKey::new(
        TlsVersion::Tls12,
        cipher_suite,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ))
}

/// Derive session keys from TLS 1.3 handshake parameters
///
/// # Arguments
/// - `shared_secret`: ECDHE shared secret
/// - `cipher_suite`: TLS 1.3 cipher suite
/// - `handshake_hash`: Hash of handshake messages
///
/// # Returns
/// Derived session key
pub fn derive_keys_tls13(
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
    handshake_hash: &[u8],
) -> Result<SessionKey> {
    // TLS 1.3 uses HKDF for key derivation
    // See RFC 8446 Section 7.1

    let hash_len = get_hash_length_tls13(cipher_suite);

    // 1. Compute handshake_secret
    // handshake_secret = HKDF-Extract(0, shared_secret)
    let zeros = vec![0u8; hash_len];
    let handshake_secret = hkdf_extract_tls13(&zeros, shared_secret, cipher_suite)?;

    // 2. Compute client_handshake_traffic_secret
    // client_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", handshake_hash)
    let client_label = build_tls13_label(b"c hs traffic", handshake_hash, hash_len);
    let _client_handshake_traffic_secret =
        hkdf_expand_label_tls13(&handshake_secret, &client_label, cipher_suite)?;

    // 3. Compute server_handshake_traffic_secret
    // server_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "s hs traffic", handshake_hash)
    let server_label = build_tls13_label(b"s hs traffic", handshake_hash, hash_len);
    let _server_handshake_traffic_secret =
        hkdf_expand_label_tls13(&handshake_secret, &server_label, cipher_suite)?;

    // 4. Compute master_secret
    // master_secret = HKDF-Extract(0, handshake_secret)
    let master_secret = hkdf_extract_tls13(&zeros, &handshake_secret, cipher_suite)?;

    // 5. Compute client_application_traffic_secret
    // client_application_traffic_secret_0 = HKDF-Expand-Label(master_secret, "c ap traffic", handshake_hash)
    let client_app_label = build_tls13_label(b"c ap traffic", handshake_hash, hash_len);
    let client_app_traffic_secret =
        hkdf_expand_label_tls13(&master_secret, &client_app_label, cipher_suite)?;

    // 6. Compute server_application_traffic_secret
    // server_application_traffic_secret_0 = HKDF-Expand-Label(master_secret, "s ap traffic", handshake_hash)
    let server_app_label = build_tls13_label(b"s ap traffic", handshake_hash, hash_len);
    let server_app_traffic_secret =
        hkdf_expand_label_tls13(&master_secret, &server_app_label, cipher_suite)?;

    // 7. Derive actual keys and IVs from traffic secrets
    // key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
    // iv = HKDF-Expand-Label(traffic_secret, "iv", "", iv_length)
    let (key_len, iv_len) = get_key_iv_lengths_tls13(cipher_suite);

    let client_key_label = build_tls13_label(b"key", &[], key_len);
    let client_iv_label = build_tls13_label(b"iv", &[], iv_len);
    let server_key_label = build_tls13_label(b"key", &[], key_len);
    let server_iv_label = build_tls13_label(b"iv", &[], iv_len);

    let client_write_key =
        hkdf_expand_label_tls13(&client_app_traffic_secret, &client_key_label, cipher_suite)?;
    let client_write_iv =
        hkdf_expand_label_tls13(&client_app_traffic_secret, &client_iv_label, cipher_suite)?;
    let server_write_key =
        hkdf_expand_label_tls13(&server_app_traffic_secret, &server_key_label, cipher_suite)?;
    let server_write_iv =
        hkdf_expand_label_tls13(&server_app_traffic_secret, &server_iv_label, cipher_suite)?;

    Ok(SessionKey::new(
        TlsVersion::Tls13,
        cipher_suite,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    ))
}

/// TLS 1.2 PRF function
/// PRF(secret, label, seed) = P_hash(secret, label + seed)
fn prf_tls12(secret: &[u8], label: &[u8], seed: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let seed = [label, seed].concat();
    p_hash::<Hmac<Sha256>>(secret, &seed, output_len)
}

/// P_hash function
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
/// A(0) = seed
/// A(i) = HMAC_hash(secret, A(i-1))
fn p_hash<H: Mac + Clone + KeyInit>(
    secret: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(output_len);
    let mut a = seed.to_vec();

    while result.len() < output_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut hmac = <H as KeyInit>::new_from_slice(secret)
            .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
        hmac.update(&a);
        let a_result = hmac.finalize().into_bytes();
        a = a_result.to_vec();

        // HMAC(secret, A(i) + seed)
        let mut hmac = <H as KeyInit>::new_from_slice(secret)
            .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
        hmac.update(&a);
        hmac.update(seed);
        let result_bytes = hmac.finalize().into_bytes();

        result.extend_from_slice(&result_bytes);
    }

    result.truncate(output_len);
    Ok(result)
}

/// TLS 1.3 HKDF-Extract
/// HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
fn hkdf_extract_tls13(salt: &[u8], ikm: &[u8], cipher_suite: CipherSuite) -> Result<Vec<u8>> {
    match cipher_suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            // SHA-256
            let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(salt)
                .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
            hmac.update(ikm);
            let result = hmac.finalize().into_bytes();
            Ok(result.to_vec())
        }
        CipherSuite::TLS13_AES_256_GCM_SHA384 => {
            // SHA-384
            let mut hmac = <Hmac<Sha384> as KeyInit>::new_from_slice(salt)
                .map_err(|_| DecryptError::KeyDerivationFailed("HMAC new failed".to_string()))?;
            hmac.update(ikm);
            let result = hmac.finalize().into_bytes();
            Ok(result.to_vec())
        }
        _ => Err(DecryptError::UnsupportedCipherSuite(cipher_suite.into())),
    }
}

/// TLS 1.3 HKDF-Expand-Label
/// HKDF-Expand-Label(secret, label, context, length)
fn hkdf_expand_label_tls13(
    secret: &[u8],
    label: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>> {
    // Validate label length to prevent array out of bounds
    if label.len() < 2 {
        return Err(DecryptError::KeyDerivationFailed(
            "Label too short".to_string(),
        ));
    }
    let output_len = u16::from_be_bytes([label[0], label[1]]) as usize;

    match cipher_suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            // Use from_prk because secret is already a PRK (pseudo-random key)
            let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| {
                DecryptError::KeyDerivationFailed("HKDF from_prk failed".to_string())
            })?;
            let mut okm = vec![0u8; output_len];
            hkdf.expand(label, &mut okm)
                .map_err(|_| DecryptError::KeyDerivationFailed("HKDF expand failed".to_string()))?;
            Ok(okm)
        }
        CipherSuite::TLS13_AES_256_GCM_SHA384 => {
            let hkdf = Hkdf::<Sha384>::from_prk(secret).map_err(|_| {
                DecryptError::KeyDerivationFailed("HKDF from_prk failed".to_string())
            })?;
            let mut okm = vec![0u8; output_len];
            hkdf.expand(label, &mut okm)
                .map_err(|_| DecryptError::KeyDerivationFailed("HKDF expand failed".to_string()))?;
            Ok(okm)
        }
        _ => Err(DecryptError::UnsupportedCipherSuite(cipher_suite.into())),
    }
}

/// Build TLS 1.3 HKDF Label
/// Label = length || "TLS 1.3, " || label || 0x00 || context_length || context
fn build_tls13_label(label: &[u8], context: &[u8], output_len: usize) -> Vec<u8> {
    let mut result = Vec::new();

    // length (2 bytes)
    result.extend_from_slice(&(output_len as u16).to_be_bytes());

    // "TLS 1.3, " + label
    result.extend_from_slice(b"TLS 1.3, ");
    result.extend_from_slice(label);

    // context length (1 byte) + context
    result.push(context.len() as u8);
    result.extend_from_slice(context);

    result
}

/// Get TLS 1.2 key and IV lengths
fn get_key_iv_lengths_tls12(cipher_suite: CipherSuite) -> (usize, usize) {
    match cipher_suite {
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => (16, 4),
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => (32, 4),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => (16, 4),
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => (32, 4),
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (32, 12),
        _ => (16, 4), // default
    }
}

/// Get TLS 1.3 key and IV lengths
fn get_key_iv_lengths_tls13(cipher_suite: CipherSuite) -> (usize, usize) {
    match cipher_suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => (16, 12),
        CipherSuite::TLS13_AES_256_GCM_SHA384 => (32, 12),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => (32, 12),
        _ => (16, 12), // default
    }
}

/// Get TLS 1.3 hash length
fn get_hash_length_tls13(cipher_suite: CipherSuite) -> usize {
    match cipher_suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
            hash_len_sha256()
        }
        CipherSuite::TLS13_AES_256_GCM_SHA384 => hash_len_sha384(),
        _ => hash_len_sha256(),
    }
}

fn hash_len_sha256() -> usize {
    32
}

fn hash_len_sha384() -> usize {
    48
}

/// Helper function: Decrypt Pre-Master Secret using private key (TLS 1.2 RSA key exchange)
///
/// # Arguments
/// - `private_key_pem`: Private key in PEM format
/// - `encrypted_pms`: Encrypted Pre-Master Secret
#[allow(dead_code)]
pub fn decrypt_pre_master_secret_rsa(
    private_key_pem: &str,
    encrypted_pms: &[u8],
) -> Result<Vec<u8>> {
    // This function depends on a specific version of the rsa crate
    // Returns an error for now; implementation needs to be adjusted based on rsa crate version
    let _ = (private_key_pem, encrypted_pms);
    Err(DecryptError::KeyDerivationFailed(
        "RSA decryption feature not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;
    use hex_literal::hex;

    #[test]
    fn test_prf_tls12() {
        let secret = b"secret";
        let label = b"label";
        let seed = b"seed";

        let result = prf_tls12(secret, label, seed, 32);
        assert!(result.is_ok());
        if let Ok(output) = result {
            assert_eq!(output.len(), 32);
        }
    }

    #[test]
    fn test_build_tls13_label() {
        let label = build_tls13_label(b"key", &[], 16);
        assert!(!label.is_empty());
    }

    // =========================================================================
    // TLS 1.2 Key Derivation Tests (verified using test data generated by Python script)
    // =========================================================================

    #[test]
    fn test_tls12_rsa_aes128gcm_key_derivation() {
        // Test data from tests/testdata/generate_test_data.py
        let client_random =
            hex!("20bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49");
        let server_random =
            hex!("35c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555");
        let pre_master_secret = hex!(
            "03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e"
        );

        let session_key = derive_keys_tls12(
            &client_random,
            &server_random,
            &pre_master_secret,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        )
        .expect("TLS 1.2 key derivation failed");

        // Verify derived keys (compared with Python implementation)
        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("0621b262dccd5d443d7c67e2602f0774"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("b2c806916a7e6601360a36c9880ae11a"),
            "Server write key mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ClientToServer),
            &hex!("03f29cc6"),
            "Client write IV mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ServerToClient),
            &hex!("ab8339f9"),
            "Server write IV mismatch"
        );
    }

    #[test]
    fn test_tls12_rsa_aes256gcm_key_derivation() {
        let client_random =
            hex!("21bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49");
        let server_random =
            hex!("36c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555");
        let pre_master_secret = hex!(
            "03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e"
        );

        let session_key = derive_keys_tls12(
            &client_random,
            &server_random,
            &pre_master_secret,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        )
        .expect("TLS 1.2 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("cc8d96c9e83cf0ff3db902e88f1610d7c8db404a1e89d8b9e4e235b930882cdc"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("653f5b10ad7eb47c745c8d28c150db2998e16bc96bcd67ab1ed8af0aea0acafd"),
            "Server write key mismatch"
        );
    }

    #[test]
    fn test_tls12_ecdhe_aes128gcm_key_derivation() {
        let client_random =
            hex!("22bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49");
        let server_random =
            hex!("37c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555");
        let pre_master_secret = hex!(
            "04a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a596877869504132231400a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140"
        );

        let session_key = derive_keys_tls12(
            &client_random,
            &server_random,
            &pre_master_secret,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        )
        .expect("TLS 1.2 ECDHE key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("4935bdf7cf7e2556e726f99681d7ae3e"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("97f302efb1e95856f395a13cd4042f06"),
            "Server write key mismatch"
        );
    }

    // =========================================================================
    // TLS 1.3 Key Derivation Tests (verified using test data generated by Python script)
    // =========================================================================

    #[test]
    fn test_tls13_aes128gcm_key_derivation() {
        let shared_secret =
            hex!("b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0");
        let handshake_hash =
            hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            &handshake_hash,
        )
        .expect("TLS 1.3 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("3b18f23f8f43fd03081c89a5fd994e2a"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("a84affab414e3ff06323bef6a2ae41ac"),
            "Server write key mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ClientToServer),
            &hex!("95f693a6d1adc21d9a1d7fa9"),
            "Client write IV mismatch"
        );
        assert_eq!(
            session_key.get_write_iv(Direction::ServerToClient),
            &hex!("4d4e08b9c946c150e24c0ddc"),
            "Server write IV mismatch"
        );
    }

    #[test]
    fn test_tls13_aes256gcm_key_derivation() {
        let shared_secret = hex!(
            "c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0"
        );
        let handshake_hash = hex!(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            &handshake_hash,
        )
        .expect("TLS 1.3 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("badfba28b3ee81b8bcb6ba3200d2b271484510c713b0c124cc336efda12a8258"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("fb7dae5b87c1070d99a2d13eb7ef05910558ecdefcd2c7c9ddfb01233735254d"),
            "Server write key mismatch"
        );
    }

    #[test]
    fn test_tls13_chacha20poly1305_key_derivation() {
        let shared_secret =
            hex!("d1e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0");
        let handshake_hash =
            hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let session_key = derive_keys_tls13(
            &shared_secret,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            &handshake_hash,
        )
        .expect("TLS 1.3 ChaCha20 key derivation failed");

        assert_eq!(
            session_key.get_write_key(Direction::ClientToServer),
            &hex!("e70701dbecd779b49e35a369073e908a54288fda04045eea48171e55ceadd62b"),
            "Client write key mismatch"
        );
        assert_eq!(
            session_key.get_write_key(Direction::ServerToClient),
            &hex!("b6759777815b337880adb54e57f59ce31912d3d8d6b26917bac05c05e3957925"),
            "Server write key mismatch"
        );
    }
}
