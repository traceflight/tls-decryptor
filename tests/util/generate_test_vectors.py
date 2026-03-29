#!/usr/bin/env python3
"""
Generate test vectors for TLS decryptor util module.

This script generates deterministic test vectors for:
1. ECDHE shared secret computation (P-256, P-384, P-521, X25519)
2. TLS 1.2 ECDHE pre-master secret computation
3. TLS 1.3 shared secret computation

Uses fixed private keys for reproducibility.
"""

import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def generate_p256_test_vector() -> dict:
    """Generate test vector for P-256 curve."""
    # Use fixed private keys for reproducibility
    # These are just example values, not from any real session
    server_private_bytes = bytes([
        0xc6, 0xef, 0x9e, 0x8f, 0x2a, 0x5b, 0x6d, 0x4c,
        0x8e, 0x3f, 0x7a, 0x1b, 0x9c, 0x4d, 0x2e, 0x5f,
        0x6a, 0x7b, 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b,
        0x4c, 0x5d, 0x6e, 0x7f, 0x8a, 0x9b, 0xac, 0xbd
    ])

    client_private_bytes = bytes([
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xf0, 0x01, 0x12, 0x23
    ])

    # Load private keys
    server_private = ec.derive_private_key(
        int.from_bytes(server_private_bytes, 'big'),
        ec.SECP256R1(),
        default_backend()
    )

    client_private = ec.derive_private_key(
        int.from_bytes(client_private_bytes, 'big'),
        ec.SECP256R1(),
        default_backend()
    )

    # Get public keys
    server_public = server_private.public_key()
    client_public = client_private.public_key()

    # Serialize public keys (uncompressed)
    server_public_bytes = server_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    client_public_bytes = client_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    # Compute shared secrets from both sides
    server_shared = server_private.exchange(ec.ECDH(), client_public)
    client_shared = client_private.exchange(ec.ECDH(), server_public)

    # Verify both sides compute the same shared secret
    assert server_shared == client_shared, "Shared secrets do not match!"

    return {
        "curve": "P-256",
        "curve_id": "0x0017",
        "server_private_key": bytes_to_hex(server_private_bytes),
        "client_private_key": bytes_to_hex(client_private_bytes),
        "server_public_key": bytes_to_hex(server_public_bytes),
        "client_public_key": bytes_to_hex(client_public_bytes),
        "shared_secret": bytes_to_hex(server_shared),
        "shared_secret_length": len(server_shared)
    }


def generate_p384_test_vector() -> dict:
    """Generate test vector for P-384 curve."""
    server_private_bytes = bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    ])

    client_private_bytes = bytes([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ])

    server_private = ec.derive_private_key(
        int.from_bytes(server_private_bytes, 'big'),
        ec.SECP384R1(),
        default_backend()
    )

    client_private = ec.derive_private_key(
        int.from_bytes(client_private_bytes, 'big'),
        ec.SECP384R1(),
        default_backend()
    )

    server_public = server_private.public_key()
    client_public = client_private.public_key()

    server_public_bytes = server_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    client_public_bytes = client_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    server_shared = server_private.exchange(ec.ECDH(), client_public)
    client_shared = client_private.exchange(ec.ECDH(), server_public)

    assert server_shared == client_shared, "Shared secrets do not match!"

    return {
        "curve": "P-384",
        "curve_id": "0x0018",
        "server_private_key": bytes_to_hex(server_private_bytes),
        "client_private_key": bytes_to_hex(client_private_bytes),
        "server_public_key": bytes_to_hex(server_public_bytes),
        "client_public_key": bytes_to_hex(client_public_bytes),
        "shared_secret": bytes_to_hex(server_shared),
        "shared_secret_length": len(server_shared)
    }


def generate_p521_test_vector() -> dict:
    """Generate test vector for P-521 curve with 66-byte private keys."""
    # P-521 private key is 66 bytes (521 bits = 65.125 bytes, rounded up to 66)
    # We need to ensure the private key value actually uses all 66 bytes
    # by using a value >= 2^520 (i.e., with high bit set in byte 0)
    # Use values that are within valid range [1, n-1] where n is the curve order
    # P-521 order is approximately 2^521, so we use values starting with 0x01 to ensure 66 bytes
    server_private_bytes = bytes([0x01] + [0x23] * 65)
    client_private_bytes = bytes([0x01] + [0x45] * 65)

    return _generate_p521_vector_from_bytes(server_private_bytes, client_private_bytes, "P-521", "0x0019")


def generate_p521_65byte_test_vector() -> dict:
    """Generate test vector for P-521 curve with 65-byte private keys.

    This tests the case where the private key can be represented in 65 bytes
    because the leading bit is 0.
    """
    # Use values that fit in 65 bytes (i.e., < 2^520)
    # Start with 0x00 to ensure the key fits in 65 bytes when leading zeros are stripped
    server_private_bytes = bytes([0x00] + [0xab] * 64)  # 65 bytes total
    client_private_bytes = bytes([0x00] + [0xcd] * 64)  # 65 bytes total

    return _generate_p521_vector_from_bytes(server_private_bytes, client_private_bytes, "P-521-65", "0x0019")


def _generate_p521_vector_from_bytes(server_private_bytes: bytes, client_private_bytes: bytes,
                                     curve_name: str, curve_id: str) -> dict:
    """Internal function to generate P-521 test vector from given private key bytes."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    server_private = ec.derive_private_key(
        int.from_bytes(server_private_bytes, 'big'),
        ec.SECP521R1(),
        default_backend()
    )

    client_private = ec.derive_private_key(
        int.from_bytes(client_private_bytes, 'big'),
        ec.SECP521R1(),
        default_backend()
    )

    server_public = server_private.public_key()
    client_public = client_private.public_key()

    server_public_bytes = server_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    client_public_bytes = client_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    server_shared = server_private.exchange(ec.ECDH(), client_public)
    client_shared = client_private.exchange(ec.ECDH(), server_public)

    assert server_shared == client_shared, "Shared secrets do not match!"

    return {
        "curve": curve_name,
        "curve_id": curve_id,
        "server_private_key": server_private_bytes.hex(),
        "client_private_key": client_private_bytes.hex(),
        "server_public_key": server_public_bytes.hex(),
        "client_public_key": client_public_bytes.hex(),
        "shared_secret": server_shared.hex(),
        "shared_secret_length": len(server_shared),
        "private_key_length": len(server_private_bytes)
    }

    server_private = ec.derive_private_key(
        int.from_bytes(server_private_bytes, 'big'),
        ec.SECP521R1(),
        default_backend()
    )

    client_private = ec.derive_private_key(
        int.from_bytes(client_private_bytes, 'big'),
        ec.SECP521R1(),
        default_backend()
    )

    server_public = server_private.public_key()
    client_public = client_private.public_key()

    server_public_bytes = server_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    client_public_bytes = client_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    server_shared = server_private.exchange(ec.ECDH(), client_public)
    client_shared = client_private.exchange(ec.ECDH(), server_public)

    assert server_shared == client_shared, "Shared secrets do not match!"

    return {
        "curve": "P-521",
        "curve_id": "0x0019",
        "server_private_key": bytes_to_hex(server_private_bytes),
        "client_private_key": bytes_to_hex(client_private_bytes),
        "server_public_key": bytes_to_hex(server_public_bytes),
        "client_public_key": bytes_to_hex(client_public_bytes),
        "shared_secret": bytes_to_hex(server_shared),
        "shared_secret_length": len(server_shared)
    }


def generate_x25519_test_vector() -> dict:
    """Generate test vector for X25519 curve."""
    # X25519 private keys are 32 bytes
    server_private_bytes = bytes([
        0xa5, 0x46, 0xee, 0x3b, 0xf5, 0x34, 0x78, 0x17,
        0x83, 0xb5, 0x2a, 0x5a, 0x89, 0x14, 0x00, 0x29,
        0xc7, 0x85, 0x32, 0x1a, 0x90, 0x5c, 0x1f, 0x5a,
        0x28, 0x24, 0x44, 0x5e, 0x1d, 0x72, 0x18, 0x16
    ])

    client_private_bytes = bytes([
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    ])

    server_private = x25519.X25519PrivateKey.from_private_bytes(
        server_private_bytes)
    client_private = x25519.X25519PrivateKey.from_private_bytes(
        client_private_bytes)

    server_public = server_private.public_key()
    client_public = client_private.public_key()

    server_public_bytes = server_public.public_bytes_raw()
    client_public_bytes = client_public.public_bytes_raw()

    server_shared = server_private.exchange(client_public)
    client_shared = client_private.exchange(server_public)

    assert server_shared == client_shared, "Shared secrets do not match!"

    return {
        "curve": "X25519",
        "curve_id": "0x001D",
        "server_private_key": bytes_to_hex(server_private_bytes),
        "client_private_key": bytes_to_hex(client_private_bytes),
        "server_public_key": bytes_to_hex(server_public_bytes),
        "client_public_key": bytes_to_hex(client_public_bytes),
        "shared_secret": bytes_to_hex(server_shared),
        "shared_secret_length": len(server_shared)
    }


def generate_tls12_ecdhe_test_vector() -> dict:
    """
    Generate TLS 1.2 ECDHE test vector.

    In TLS 1.2 ECDHE:
    1. Server sends ServerKeyExchange with its ephemeral public key
    2. Client sends ClientKeyExchange with its ephemeral public key
    3. Both sides compute pre-master secret using ECDH
    """
    # Generate P-256 keys
    p256_vector = generate_p256_test_vector()

    # Simulate ServerKeyExchange structure (RFC 4492):
    # curve_type (1) + named_group (2) + public_key_length (1) + public_key
    curve_type = 0x03  # named_group
    named_group = 0x0017  # secp256r1
    public_key = bytes.fromhex(p256_vector["server_public_key"])

    server_key_exchange = bytes([curve_type]) + \
        named_group.to_bytes(2, 'big') + \
        bytes([len(public_key)]) + \
        public_key

    # Simulate ClientKeyExchange structure (RFC 4492):
    # public_key_length (1) + public_key
    client_public_key = bytes.fromhex(p256_vector["client_public_key"])
    client_key_exchange = bytes([len(client_public_key)]) + client_public_key

    # Server's private key
    server_private_key = bytes.fromhex(p256_vector["server_private_key"])

    return {
        "description": "TLS 1.2 ECDHE with P-256",
        "tls_version": "1.2",
        "key_exchange": "ECDHE",
        "curve": p256_vector["curve"],
        "curve_id": p256_vector["curve_id"],
        "server_private_key": p256_vector["server_private_key"],
        "server_key_exchange": bytes_to_hex(server_key_exchange),
        "client_key_exchange": bytes_to_hex(client_key_exchange),
        "expected_pre_master_secret": p256_vector["shared_secret"]
    }


def generate_tls13_test_vector() -> dict:
    """
    Generate TLS 1.3 test vector.

    In TLS 1.3:
    1. Client sends ClientHello with key_share extension
    2. Server sends ServerHello with key_share extension
    3. Both sides compute shared secret using ECDH
    4. Shared secret is used in HKDF key derivation
    """
    # Generate P-256 keys
    p256_vector = generate_p256_test_vector()

    # Simulate key_share extension data
    # KeyShareEntry: group (2) + key_exchange_length (2) + key_exchange
    # curve_id is "0x0017" format, need to convert to bytes
    curve_id_bytes = bytes.fromhex(
        p256_vector["curve_id"][2:])  # Remove "0x" prefix

    # Client's key share
    client_public_key = bytes.fromhex(p256_vector["client_public_key"])
    client_key_share_entry = \
        curve_id_bytes + \
        len(client_public_key).to_bytes(2, 'big') + \
        client_public_key

    # Server's key share
    server_public_key = bytes.fromhex(p256_vector["server_public_key"])
    server_key_share_entry = \
        curve_id_bytes + \
        len(server_public_key).to_bytes(2, 'big') + \
        server_public_key

    # Server's private key (for computing shared secret)
    server_private_key = bytes.fromhex(p256_vector["server_private_key"])

    return {
        "description": "TLS 1.3 with P-256 key share",
        "tls_version": "1.3",
        "key_exchange": "ECDHE",
        "curve": p256_vector["curve"],
        "curve_id": p256_vector["curve_id"],
        "server_private_key": p256_vector["server_private_key"],
        "client_key_share_entry": bytes_to_hex(client_key_share_entry),
        "server_key_share_entry": bytes_to_hex(server_key_share_entry),
        "expected_shared_secret": p256_vector["shared_secret"]
    }


def main():
    """Generate all test vectors and save to JSON file."""
    test_vectors = {
        "version": "1.0",
        "description": "Test vectors for TLS decryptor util module",
        "ecdhe_test_vectors": {
            "p256": generate_p256_test_vector(),
            "p384": generate_p384_test_vector(),
            "p521": generate_p521_test_vector(),
            "p521_65byte": generate_p521_65byte_test_vector(),
            "x25519": generate_x25519_test_vector()
        },
        "tls12_test_vectors": {
            "ecdhe_p256": generate_tls12_ecdhe_test_vector()
        },
        "tls13_test_vectors": {
            "ecdhe_p256": generate_tls13_test_vector()
        }
    }

    # Save to JSON file
    output_file = "tests/util/test_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(test_vectors, f, indent=2)

    print(f"Test vectors generated and saved to {output_file}")
    print(f"\nSummary:")
    print(f"  - ECDHE test vectors: P-256, P-384, P-521 (66-byte), P-521 (65-byte), X25519")
    print(f"  - TLS 1.2 test vectors: ECDHE with P-256")
    print(f"  - TLS 1.3 test vectors: ECDHE with P-256")

    # Print a sample for verification
    print(f"\nSample (P-256 shared secret):")
    print(f"  {test_vectors['ecdhe_test_vectors']['p256']['shared_secret']}")

    # Print P-521 65-byte key info
    p521_65 = test_vectors['ecdhe_test_vectors']['p521_65byte']
    print(f"\nP-521 65-byte test vector:")
    print(f"  Private key length: {p521_65['private_key_length']} bytes")
    print(f"  Shared secret: {p521_65['shared_secret']}")


if __name__ == "__main__":
    main()
