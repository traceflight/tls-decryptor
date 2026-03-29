#!/usr/bin/env python3
"""
Generate test vectors for TLS 1.2 key derivation.

This script generates deterministic test vectors for TLS 1.2 PRF-based
key derivation, testing the derive_keys_tls12() function and Tls12KeyDeriver.

Tested cipher suites:
- TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)
- TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)
"""

import json
import hmac
import hashlib
from typing import Dict, Any


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def p_hash(secret: bytes, seed: bytes, output_len: int, hash_func) -> bytes:
    """
    TLS 1.2 P_hash function.

    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
    A(0) = seed
    A(i) = HMAC_hash(secret, A(i-1))
    """
    result = b''
    a = seed

    while len(result) < output_len:
        # A(i) = HMAC(secret, A(i-1))
        a = hmac.new(secret, a, hash_func).digest()
        # HMAC(secret, A(i) + seed)
        result += hmac.new(secret, a + seed, hash_func).digest()

    return result[:output_len]


def prf_tls12(secret: bytes, label: bytes, seed: bytes, output_len: int) -> bytes:
    """
    TLS 1.2 PRF function.

    PRF(secret, label, seed) = P_hash(secret, label + seed)

    For TLS 1.2 with SHA-256 based cipher suites, we use HMAC-SHA256.
    For SHA-384 based cipher suites, we use HMAC-SHA384.
    """
    return p_hash(secret, label + seed, output_len, hashlib.sha256)


def prf_tls12_sha384(secret: bytes, label: bytes, seed: bytes, output_len: int) -> bytes:
    """TLS 1.2 PRF function using SHA-384."""
    return p_hash(secret, label + seed, output_len, hashlib.sha384)


def derive_keys_tls12(
    client_random: bytes,
    server_random: bytes,
    pre_master_secret: bytes,
    cipher_suite: str
) -> Dict[str, Any]:
    """
    Derive TLS 1.2 session keys.

    Returns a dictionary with all derived keys and IVs.
    """
    if cipher_suite == "TLS_RSA_WITH_AES_128_GCM_SHA256":
        key_len = 16
        iv_len = 4
        prf_func = prf_tls12
    elif cipher_suite == "TLS_RSA_WITH_AES_256_GCM_SHA384":
        key_len = 32
        iv_len = 4
        prf_func = prf_tls12_sha384
    else:
        raise ValueError(f"Unsupported cipher suite: {cipher_suite}")

    # 1. Compute Master Secret
    # master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
    seed = client_random + server_random
    master_secret = prf_func(pre_master_secret, b"master secret", seed, 48)

    # 2. Compute Key Block
    # key_block = PRF(master_secret, "key expansion", server_random + client_random)
    key_expansion_seed = server_random + client_random
    key_block_len = 2 * key_len + 2 * iv_len
    key_block = prf_func(master_secret, b"key expansion",
                         key_expansion_seed, key_block_len)

    # 3. Extract keys and IVs
    offset = 0
    client_write_key = key_block[offset:offset + key_len]
    offset += key_len
    server_write_key = key_block[offset:offset + key_len]
    offset += key_len
    client_write_iv = key_block[offset:offset + iv_len]
    offset += iv_len
    server_write_iv = key_block[offset:offset + iv_len]

    return {
        "master_secret": bytes_to_hex(master_secret),
        "client_write_key": bytes_to_hex(client_write_key),
        "server_write_key": bytes_to_hex(server_write_key),
        "client_write_iv": bytes_to_hex(client_write_iv),
        "server_write_iv": bytes_to_hex(server_write_iv),
    }


def generate_tls12_aes_128_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS_RSA_WITH_AES_128_GCM_SHA256."""
    # Use deterministic values for reproducibility
    client_random = bytes([
        0x20, 0xbd, 0xc2, 0xef, 0xb8, 0x38, 0x6b, 0x8b,
        0x00, 0x59, 0x4c, 0x75, 0x5b, 0x4f, 0x9e, 0x2d,
        0x0a, 0x9e, 0x9c, 0x7f, 0x5e, 0x8d, 0x3c, 0x2b,
        0x1a, 0x0f, 0x9e, 0x8d, 0x7c, 0x6b, 0x5a, 0x49
    ])

    server_random = bytes([
        0x35, 0xc5, 0xe5, 0xf5, 0xa5, 0xb5, 0xc5, 0xd5,
        0xe5, 0xf5, 0x05, 0x15, 0x25, 0x35, 0x45, 0x55,
        0x65, 0x75, 0x85, 0x95, 0xa5, 0xb5, 0xc5, 0xd5,
        0xe5, 0xf5, 0x05, 0x15, 0x25, 0x35, 0x45, 0x55
    ])

    # TLS 1.2 pre-master secret (48 bytes for RSA key exchange)
    # First 2 bytes are the TLS version (0x0303 for TLS 1.2)
    # Remaining 46 bytes are random
    pre_master_secret = bytes([
        0x03, 0x03,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f
    ])

    derived = derive_keys_tls12(
        client_random, server_random, pre_master_secret,
        "TLS_RSA_WITH_AES_128_GCM_SHA256"
    )

    return {
        "description": "TLS 1.2 RSA WITH AES 128 GCM SHA256",
        "tls_version": "1.2",
        "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "cipher_suite_id": "0x009C",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        **derived
    }


def generate_tls12_aes_256_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS_RSA_WITH_AES_256_GCM_SHA384."""
    client_random = bytes([
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ])

    server_random = bytes([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    ])

    pre_master_secret = bytes([
        0x03, 0x03,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a
    ])

    derived = derive_keys_tls12(
        client_random, server_random, pre_master_secret,
        "TLS_RSA_WITH_AES_256_GCM_SHA384"
    )

    return {
        "description": "TLS 1.2 RSA WITH AES 256 GCM SHA384",
        "tls_version": "1.2",
        "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "cipher_suite_id": "0x009D",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        **derived
    }


def generate_state_machine_test_vector() -> Dict[str, Any]:
    """
    Generate test vector for Tls12KeyDeriver state machine testing.

    This includes the same data as above but formatted for state machine testing.
    """
    # Use the AES-128-GCM test vector data
    base_vector = generate_tls12_aes_128_gcm_test_vector()

    return {
        "description": "TLS 1.2 Key Deriver State Machine Test",
        "client_random": base_vector["client_random"],
        "server_random": base_vector["server_random"],
        "cipher_suite_id": base_vector["cipher_suite_id"],
        "pre_master_secret": base_vector["pre_master_secret"],
        "expected_master_secret": base_vector["master_secret"],
        "expected_client_write_key": base_vector["client_write_key"],
        "expected_server_write_key": base_vector["server_write_key"],
        "expected_client_write_iv": base_vector["client_write_iv"],
        "expected_server_write_iv": base_vector["server_write_iv"],
    }


def main():
    """Generate all TLS 1.2 test vectors and save to JSON file."""
    test_vectors = {
        "version": "1.0",
        "description": "Test vectors for TLS 1.2 key derivation",
        "key_derivation_tests": {
            "aes_128_gcm": generate_tls12_aes_128_gcm_test_vector(),
            "aes_256_gcm": generate_tls12_aes_256_gcm_test_vector(),
        },
        "state_machine_tests": {
            "basic_flow": generate_state_machine_test_vector(),
        }
    }

    # Save to JSON file
    output_file = "tests/key_derivation/tls12_test_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(test_vectors, f, indent=2)

    print(f"TLS 1.2 test vectors generated and saved to {output_file}")
    print(f"\nSummary:")
    print(f"  - Key derivation tests: AES-128-GCM, AES-256-GCM")
    print(f"  - State machine tests: basic_flow")

    # Print samples for verification
    print(f"\nSample (AES-128-GCM master secret):")
    print(
        f"  {test_vectors['key_derivation_tests']['aes_128_gcm']['master_secret']}")
    print(f"\nSample (AES-128-GCM client write key):")
    print(
        f"  {test_vectors['key_derivation_tests']['aes_128_gcm']['client_write_key']}")


if __name__ == "__main__":
    main()
