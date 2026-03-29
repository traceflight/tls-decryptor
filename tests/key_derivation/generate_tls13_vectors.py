#!/usr/bin/env python3
"""
Generate test vectors for TLS 1.3 key derivation.

This script generates deterministic test vectors for TLS 1.3 HKDF-based
key derivation, testing the derive_keys_tls13() function and Tls13KeyDeriver.

Tested cipher suites:
- TLS_AES_128_GCM_SHA256 (0x1301)
- TLS_AES_256_GCM_SHA384 (0x1302)
"""

import json
import hmac
import hashlib
import struct
from typing import Dict, Any, Tuple


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def hkdf_extract(salt: bytes, ikm: bytes, hash_func) -> bytes:
    """
    TLS 1.3 HKDF-Extract function.

    HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
    """
    return hmac.new(salt, ikm, hash_func).digest()


def hkdf_expand(prk: bytes, info: bytes, output_len: int, hash_func) -> bytes:
    """
    TLS 1.3 HKDF-Expand function.

    HKDF-Expand(PRK, info, L) = T(1) | T(2) | ... | T(N)
    T(0) = empty string
    T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
    """
    hash_len = hash_func().digest_size
    n = (output_len + hash_len - 1) // hash_len

    result = b''
    t = b''
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_func).digest()
        result += t

    return result[:output_len]


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      output_len: int, hash_func) -> bytes:
    """
    TLS 1.3 HKDF-Expand-Label function.

    HKDF-Expand-Label(Secret, Label, Context, Length) = 
        HKDF-Expand(Secret, HkdfLabel, Length)

    Where:
    - HkdfLabel = length (2) | "TLS 1.3, " + label (variable) | context_length (1) | context (variable)
    """
    # Build HkdfLabel
    hkdf_label = struct.pack('>H', output_len)
    hkdf_label += b'TLS 1.3, ' + label
    hkdf_label += struct.pack('B', len(context))
    hkdf_label += context

    return hkdf_expand(secret, hkdf_label, output_len, hash_func)


def derive_keys_tls13(
    shared_secret: bytes,
    handshake_hash: bytes,
    cipher_suite: str
) -> Dict[str, Any]:
    """
    Derive TLS 1.3 session keys.

    Returns a dictionary with all derived keys and IVs.
    """
    if cipher_suite == "TLS_AES_128_GCM_SHA256":
        hash_func = hashlib.sha256
        hash_len = 32
        key_len = 16
        iv_len = 12
    elif cipher_suite == "TLS_AES_256_GCM_SHA384":
        hash_func = hashlib.sha384
        hash_len = 48
        key_len = 32
        iv_len = 12
    else:
        raise ValueError(f"Unsupported cipher suite: {cipher_suite}")

    # 1. Compute handshake_secret = HKDF-Extract(0, shared_secret)
    zeros = bytes(hash_len)
    handshake_secret = hkdf_extract(zeros, shared_secret, hash_func)

    # 2. Compute master_secret = HKDF-Extract(0, handshake_secret)
    master_secret = hkdf_extract(zeros, handshake_secret, hash_func)

    # 3. Derive client_application_traffic_secret_0
    client_app_secret = hkdf_expand_label(
        master_secret, b'c ap traffic', handshake_hash, hash_len, hash_func
    )

    # 4. Derive server_application_traffic_secret_0
    server_app_secret = hkdf_expand_label(
        master_secret, b's ap traffic', handshake_hash, hash_len, hash_func
    )

    # 5. Derive actual keys and IVs
    client_write_key = hkdf_expand_label(
        client_app_secret, b'key', b'', key_len, hash_func
    )
    client_write_iv = hkdf_expand_label(
        client_app_secret, b'iv', b'', iv_len, hash_func
    )
    server_write_key = hkdf_expand_label(
        server_app_secret, b'key', b'', key_len, hash_func
    )
    server_write_iv = hkdf_expand_label(
        server_app_secret, b'iv', b'', iv_len, hash_func
    )

    return {
        "handshake_secret": bytes_to_hex(handshake_secret),
        "master_secret": bytes_to_hex(master_secret),
        "client_application_traffic_secret": bytes_to_hex(client_app_secret),
        "server_application_traffic_secret": bytes_to_hex(server_app_secret),
        "client_write_key": bytes_to_hex(client_write_key),
        "server_write_key": bytes_to_hex(server_write_key),
        "client_write_iv": bytes_to_hex(client_write_iv),
        "server_write_iv": bytes_to_hex(server_write_iv),
    }


def generate_tls13_aes_128_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS_AES_128_GCM_SHA256."""
    # Use deterministic values for reproducibility
    # Shared secret from ECDHE (P-256) - 32 bytes
    shared_secret = bytes([
        0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28,
        0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0,
        0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28,
        0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0
    ])

    # Handshake hash (SHA-256 of all handshake messages) - 32 bytes
    handshake_hash = bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ])

    derived = derive_keys_tls13(
        shared_secret, handshake_hash,
        "TLS_AES_128_GCM_SHA256"
    )

    return {
        "description": "TLS 1.3 AES 128 GCM SHA256",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "cipher_suite_id": "0x1301",
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        **derived
    }


def generate_tls13_aes_256_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS_AES_256_GCM_SHA384."""
    # Shared secret from ECDHE (P-384) - 48 bytes
    shared_secret = bytes([
        0xc1, 0xd2, 0xe3, 0xf4, 0x05, 0x16, 0x27, 0x38,
        0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0,
        0xc1, 0xd2, 0xe3, 0xf4, 0x05, 0x16, 0x27, 0x38,
        0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0,
        0xc1, 0xd2, 0xe3, 0xf4, 0x05, 0x16, 0x27, 0x38,
        0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0
    ])

    # Handshake hash (SHA-384 of all handshake messages) - 48 bytes
    handshake_hash = bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ])

    derived = derive_keys_tls13(
        shared_secret, handshake_hash,
        "TLS_AES_256_GCM_SHA384"
    )

    return {
        "description": "TLS 1.3 AES 256 GCM SHA384",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_suite_id": "0x1302",
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        **derived
    }


def generate_state_machine_test_vector() -> Dict[str, Any]:
    """
    Generate test vector for Tls13KeyDeriver state machine testing.

    This includes the same data as above but formatted for state machine testing.
    """
    # Use the AES-128-GCM test vector data
    base_vector = generate_tls13_aes_128_gcm_test_vector()

    return {
        "description": "TLS 1.3 Key Deriver State Machine Test",
        "shared_secret": base_vector["shared_secret"],
        "cipher_suite_id": base_vector["cipher_suite_id"],
        "handshake_hash": base_vector["handshake_hash"],
        "expected_client_write_key": base_vector["client_write_key"],
        "expected_server_write_key": base_vector["server_write_key"],
        "expected_client_write_iv": base_vector["client_write_iv"],
        "expected_server_write_iv": base_vector["server_write_iv"],
    }


def main():
    """Generate all TLS 1.3 test vectors and save to JSON file."""
    test_vectors = {
        "version": "1.0",
        "description": "Test vectors for TLS 1.3 key derivation",
        "key_derivation_tests": {
            "aes_128_gcm": generate_tls13_aes_128_gcm_test_vector(),
            "aes_256_gcm": generate_tls13_aes_256_gcm_test_vector(),
        },
        "state_machine_tests": {
            "basic_flow": generate_state_machine_test_vector(),
        }
    }

    # Save to JSON file
    output_file = "tests/key_derivation/tls13_test_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(test_vectors, f, indent=2)

    print(f"TLS 1.3 test vectors generated and saved to {output_file}")
    print(f"\nSummary:")
    print(f"  - Key derivation tests: AES-128-GCM-SHA256, AES-256-GCM-SHA384")
    print(f"  - State machine tests: basic_flow")

    # Print samples for verification
    print(f"\nSample (AES-128-GCM-SHA256 client write key):")
    print(
        f"  {test_vectors['key_derivation_tests']['aes_128_gcm']['client_write_key']}")
    print(f"\nSample (AES-256-GCM-SHA384 client write key):")
    print(
        f"  {test_vectors['key_derivation_tests']['aes_256_gcm']['client_write_key']}")


if __name__ == "__main__":
    main()
