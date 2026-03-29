#!/usr/bin/env python3
"""
Generate test vectors for TLS cipher decryption.

This script generates deterministic test vectors for:
1. TLS 1.3 AEAD decryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
2. TLS 1.2 AEAD decryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)

Uses fixed keys and IVs for reproducibility.
"""

import json
import os
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def encrypt_tls13_aes_gcm(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    aad: bytes,
    sequence_number: int = 0
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using TLS 1.3 AES-GCM.

    TLS 1.3 nonce = iv XOR sequence_number (right-aligned)

    Returns (ciphertext, tag) - these are concatenated in TLS records.
    """
    # Calculate nonce: iv XOR sequence_number
    nonce = bytearray(iv)
    seq_bytes = sequence_number.to_bytes(8, 'big')
    for i in range(8):
        nonce[i + 4] ^= seq_bytes[i]

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(bytes(nonce), plaintext, aad)

    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def encrypt_tls13_chacha20_poly1305(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    aad: bytes,
    sequence_number: int = 0
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using TLS 1.3 ChaCha20-Poly1305.

    TLS 1.3 nonce = iv XOR sequence_number (right-aligned)

    Returns (ciphertext, tag).
    """
    # Calculate nonce: iv XOR sequence_number
    nonce = bytearray(iv)
    seq_bytes = sequence_number.to_bytes(8, 'big')
    for i in range(8):
        nonce[i + 4] ^= seq_bytes[i]

    chacha = ChaCha20Poly1305(key)
    ciphertext_with_tag = chacha.encrypt(bytes(nonce), plaintext, aad)

    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def encrypt_tls12_aes_gcm(
    plaintext: bytes,
    key: bytes,
    salt: bytes,
    aad: bytes,
    sequence_number: int = 0
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt data using TLS 1.2 AES-GCM.

    TLS 1.2 nonce = salt (4 bytes) || explicit_nonce (8 bytes)
    explicit_nonce is typically the sequence number.

    Returns (explicit_nonce, ciphertext, tag).
    """
    # explicit_nonce is the sequence number as 8-byte big-endian
    explicit_nonce = sequence_number.to_bytes(8, 'big')

    # Full nonce = salt || explicit_nonce
    full_nonce = salt + explicit_nonce

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(full_nonce, plaintext, aad)

    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return explicit_nonce, ciphertext, tag


def encrypt_tls12_chacha20_poly1305(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    aad: bytes,
    sequence_number: int = 0
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using TLS 1.2 ChaCha20-Poly1305 (RFC 7905).

    TLS 1.2 ChaCha20-Poly1305 nonce construction is the same as TLS 1.3:
    nonce = iv XOR sequence_number

    Returns (ciphertext, tag).
    """
    # Calculate nonce: iv XOR sequence_number
    nonce = bytearray(iv)
    seq_bytes = sequence_number.to_bytes(8, 'big')
    for i in range(8):
        nonce[i + 4] ^= seq_bytes[i]

    chacha = ChaCha20Poly1305(key)
    ciphertext_with_tag = chacha.encrypt(bytes(nonce), plaintext, aad)

    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def generate_tls13_aes_128_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.3 AES-128-GCM."""
    # Fixed test values
    key = bytes([
        0xa4, 0x49, 0x8d, 0x4d, 0x54, 0x64, 0xa6, 0xf7,
        0x9c, 0xec, 0xf2, 0xcd, 0x89, 0x67, 0xb8, 0x96
    ])
    iv = bytes([
        0x9d, 0x87, 0xf3, 0x55, 0x6a, 0x66, 0x01, 0xcf,
        0x45, 0xbc, 0xab, 0xb3
    ])
    plaintext = b"Hello, TLS 1.3 AES-128-GCM!"

    # TLS 1.3 record header (Content Type: 0x17, Version: 0x0303, Length: variable)
    # For AAD, we use the actual record header
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x2c])

    ciphertext, tag = encrypt_tls13_aes_gcm(plaintext, key, iv, aad, 0)

    # Full ciphertext for decryption = ciphertext || tag
    full_ciphertext = ciphertext + tag

    return {
        "description": "TLS 1.3 AES-128-GCM basic decryption test",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "cipher_suite_id": "0x1301",
        "key": bytes_to_hex(key),
        "iv": bytes_to_hex(iv),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": 0,
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_tls13_aes_256_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.3 AES-256-GCM."""
    key = bytes([
        0x7c, 0x6b, 0x21, 0x67, 0x01, 0x09, 0x03, 0x74,
        0xb5, 0xd4, 0x73, 0xfb, 0x65, 0xd7, 0xbe, 0x66,
        0xba, 0x04, 0xb5, 0xda, 0x92, 0x1a, 0x74, 0x4a,
        0x4e, 0x15, 0xb5, 0x4a, 0x1e, 0xfb, 0x5a, 0x95
    ])
    iv = bytes([
        0x71, 0x83, 0xc6, 0xce, 0xbe, 0xd6, 0x4f, 0x9f,
        0x7e, 0xf7, 0x43, 0xb0
    ])
    plaintext = b"Hello, TLS 1.3 AES-256-GCM!"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x2c])

    ciphertext, tag = encrypt_tls13_aes_gcm(plaintext, key, iv, aad, 0)
    full_ciphertext = ciphertext + tag

    return {
        "description": "TLS 1.3 AES-256-GCM basic decryption test",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_suite_id": "0x1302",
        "key": bytes_to_hex(key),
        "iv": bytes_to_hex(iv),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": 0,
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_tls13_chacha20_poly1305_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.3 ChaCha20-Poly1305."""
    key = bytes([
        0x1e, 0x54, 0x37, 0x17, 0x1a, 0x18, 0x07, 0xf7,
        0x12, 0x97, 0x58, 0x14, 0x57, 0x87, 0x45, 0x02,
        0x83, 0x46, 0x72, 0xc3, 0x2a, 0xa5, 0xf1, 0x16,
        0x3b, 0xcf, 0x2b, 0x4c, 0x23, 0x72, 0x66, 0xee
    ])
    iv = bytes([
        0x92, 0x7e, 0x5a, 0x95, 0x2e, 0x7f, 0x92, 0x54,
        0xeb, 0x97, 0xdd, 0xd6
    ])
    plaintext = b"Hello, TLS 1.3 ChaCha20-Poly1305!"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x32])

    ciphertext, tag = encrypt_tls13_chacha20_poly1305(
        plaintext, key, iv, aad, 0)
    full_ciphertext = ciphertext + tag

    return {
        "description": "TLS 1.3 ChaCha20-Poly1305 basic decryption test",
        "tls_version": "1.3",
        "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256",
        "cipher_suite_id": "0x1303",
        "key": bytes_to_hex(key),
        "iv": bytes_to_hex(iv),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": 0,
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_tls12_rsa_aes_128_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.2 RSA WITH AES-128-GCM-SHA256."""
    key = bytes([
        0x06, 0x21, 0xb2, 0x62, 0xdc, 0xcd, 0x5d, 0x44,
        0x3d, 0x7c, 0x67, 0xe2, 0x60, 0x2f, 0x07, 0x74
    ])
    salt = bytes([0x03, 0xf2, 0x9c, 0xc6])  # 4-byte salt
    plaintext = b"Hello, TLS 1.2 RSA AES-128-GCM!"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x37])
    sequence_number = 0

    explicit_nonce, ciphertext, tag = encrypt_tls12_aes_gcm(
        plaintext, key, salt, aad, sequence_number
    )

    # TLS 1.2 ciphertext format: explicit_nonce || ciphertext || tag
    full_ciphertext = explicit_nonce + ciphertext + tag

    return {
        "description": "TLS 1.2 RSA AES-128-GCM basic decryption test",
        "tls_version": "1.2",
        "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "cipher_suite_id": "0x009C",
        "key": bytes_to_hex(key),
        "salt": bytes_to_hex(salt),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": sequence_number,
        "explicit_nonce": bytes_to_hex(explicit_nonce),
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_tls12_rsa_aes_256_gcm_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.2 RSA WITH AES-256-GCM-SHA384."""
    key = bytes([
        0xcc, 0x8d, 0x96, 0xc9, 0xe8, 0x3c, 0xf0, 0xff,
        0x3d, 0xb9, 0x02, 0xe8, 0x8f, 0x16, 0x10, 0xd7,
        0xc8, 0xdb, 0x40, 0x4a, 0x1e, 0x89, 0xd8, 0xb9,
        0xe4, 0xe2, 0x35, 0xb9, 0x30, 0x88, 0x2c, 0xdc
    ])
    salt = bytes([0x4b, 0xeb, 0x4c, 0xf2])  # 4-byte salt
    plaintext = b"Hello, TLS 1.2 RSA AES-256-GCM!"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x37])
    sequence_number = 0

    explicit_nonce, ciphertext, tag = encrypt_tls12_aes_gcm(
        plaintext, key, salt, aad, sequence_number
    )

    full_ciphertext = explicit_nonce + ciphertext + tag

    return {
        "description": "TLS 1.2 RSA AES-256-GCM basic decryption test",
        "tls_version": "1.2",
        "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "cipher_suite_id": "0x009D",
        "key": bytes_to_hex(key),
        "salt": bytes_to_hex(salt),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": sequence_number,
        "explicit_nonce": bytes_to_hex(explicit_nonce),
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_tls12_ecdhe_chacha20_poly1305_test_vector() -> Dict[str, Any]:
    """Generate test vector for TLS 1.2 ECDHE WITH CHACHA20-POLY1305-SHA256."""
    key = bytes([
        0x49, 0x35, 0xbd, 0xf7, 0xcf, 0x7e, 0x25, 0x56,
        0xe7, 0x26, 0xf9, 0x96, 0x81, 0xd7, 0xae, 0x3e,
        0x97, 0xf3, 0x02, 0xef, 0xb1, 0xe9, 0x58, 0x56,
        0xf3, 0x95, 0xa1, 0x3c, 0xd4, 0x04, 0x2f, 0x06
    ])
    iv = bytes([
        0x6a, 0x7a, 0xc4, 0x93, 0x6f, 0x65, 0xdc, 0x97,
        0x17, 0xfc, 0xff, 0x04
    ])
    plaintext = b"Hello, TLS 1.2 ECDHE ChaCha20-Poly1305!"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x37])
    sequence_number = 0

    ciphertext, tag = encrypt_tls12_chacha20_poly1305(
        plaintext, key, iv, aad, sequence_number
    )

    # TLS 1.2 ChaCha20-Poly1305 ciphertext format: ciphertext || tag
    # (no explicit nonce prefix)
    full_ciphertext = ciphertext + tag

    return {
        "description": "TLS 1.2 ECDHE ChaCha20-Poly1305 basic decryption test",
        "tls_version": "1.2",
        "cipher_suite": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "cipher_suite_id": "0xCCA8",
        "key": bytes_to_hex(key),
        "iv": bytes_to_hex(iv),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": sequence_number,
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_sequence_number_test_vector() -> Dict[str, Any]:
    """
    Generate test vector for sequence number handling.

    Tests that the nonce is correctly calculated with non-zero sequence numbers.
    """
    key = bytes([
        0xa4, 0x49, 0x8d, 0x4d, 0x54, 0x64, 0xa6, 0xf7,
        0x9c, 0xec, 0xf2, 0xcd, 0x89, 0x67, 0xb8, 0x96
    ])
    iv = bytes([
        0x9d, 0x87, 0xf3, 0x55, 0x6a, 0x66, 0x01, 0xcf,
        0x45, 0xbc, 0xab, 0xb3
    ])
    plaintext = b"Sequence number test message"
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x21])
    sequence_number = 100  # Non-zero sequence number

    ciphertext, tag = encrypt_tls13_aes_gcm(
        plaintext, key, iv, aad, sequence_number)
    full_ciphertext = ciphertext + tag

    return {
        "description": "TLS 1.3 AES-128-GCM with non-zero sequence number",
        "tls_version": "1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "cipher_suite_id": "0x1301",
        "key": bytes_to_hex(key),
        "iv": bytes_to_hex(iv),
        "plaintext": bytes_to_hex(plaintext),
        "aad": bytes_to_hex(aad),
        "sequence_number": sequence_number,
        "ciphertext": bytes_to_hex(ciphertext),
        "tag": bytes_to_hex(tag),
        "full_ciphertext": bytes_to_hex(full_ciphertext),
    }


def generate_edge_cases() -> Dict[str, Any]:
    """Generate edge case test vectors."""
    key = bytes([
        0xa4, 0x49, 0x8d, 0x4d, 0x54, 0x64, 0xa6, 0xf7,
        0x9c, 0xec, 0xf2, 0xcd, 0x89, 0x67, 0xb8, 0x96
    ])
    iv = bytes([
        0x9d, 0x87, 0xf3, 0x55, 0x6a, 0x66, 0x01, 0xcf,
        0x45, 0xbc, 0xab, 0xb3
    ])

    # Empty plaintext
    aad = bytes([0x17, 0x03, 0x03, 0x00, 0x10])
    ciphertext, tag = encrypt_tls13_aes_gcm(b"", key, iv, aad, 0)
    empty_ciphertext = ciphertext + tag

    return {
        "empty_plaintext": {
            "description": "Empty plaintext decryption test",
            "tls_version": "1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "cipher_suite_id": "0x1301",
            "key": bytes_to_hex(key),
            "iv": bytes_to_hex(iv),
            "plaintext": "",
            "aad": bytes_to_hex(aad),
            "sequence_number": 0,
            "full_ciphertext": bytes_to_hex(empty_ciphertext),
        }
    }


def main():
    """Generate all test vectors and save to JSON file."""
    test_vectors = {
        "version": "1.0",
        "description": "Test vectors for TLS cipher decryption",
        "tls13_tests": {
            "aes_128_gcm_basic": generate_tls13_aes_128_gcm_test_vector(),
            "aes_256_gcm_basic": generate_tls13_aes_256_gcm_test_vector(),
            "chacha20_poly1305_basic": generate_tls13_chacha20_poly1305_test_vector(),
        },
        "tls12_tests": {
            "rsa_aes_128_gcm_basic": generate_tls12_rsa_aes_128_gcm_test_vector(),
            "rsa_aes_256_gcm_basic": generate_tls12_rsa_aes_256_gcm_test_vector(),
            "ecdhe_chacha20_poly1305_basic": generate_tls12_ecdhe_chacha20_poly1305_test_vector(),
        },
        "advanced_tests": {
            "sequence_number_test": generate_sequence_number_test_vector(),
            "edge_cases": generate_edge_cases(),
        }
    }

    # Ensure output directory exists
    os.makedirs("tests/cipher", exist_ok=True)

    # Save to JSON file
    output_file = "tests/cipher/test_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(test_vectors, f, indent=2)

    print(f"Test vectors generated and saved to {output_file}")
    print(f"\nSummary:")
    print(f"  - TLS 1.3 tests: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305")
    print(f"  - TLS 1.2 tests: RSA AES-128-GCM, RSA AES-256-GCM, ECDHE ChaCha20-Poly1305")
    print(f"  - Advanced tests: sequence number handling, edge cases")

    # Print samples for verification
    print(f"\nSample (TLS 1.3 AES-128-GCM):")
    print(f"  Key: {test_vectors['tls13_tests']['aes_128_gcm_basic']['key']}")
    print(f"  IV: {test_vectors['tls13_tests']['aes_128_gcm_basic']['iv']}")
    print(
        f"  Plaintext: {test_vectors['tls13_tests']['aes_128_gcm_basic']['plaintext']}")
    print(
        f"  Ciphertext: {test_vectors['tls13_tests']['aes_128_gcm_basic']['full_ciphertext']}")


if __name__ == "__main__":
    main()
