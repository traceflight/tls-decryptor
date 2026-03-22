#!/usr/bin/env python3
"""
TLS 解密测试数据生成器

生成用于验证 Rust TLS 解密逻辑正确性的测试用例，覆盖所有已实现的加密套件。
包括 TLS 1.2 和 TLS 1.3 的完整密钥派生和数据加密/解密测试。

运行：python3 tests/testdata/generate_tls_decrypt_test_data.py
"""

import hashlib
import hmac
import json
import struct
from typing import List, Tuple, Dict, Any

# =============================================================================
# 加密原语实现
# =============================================================================


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256"""
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha384(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA384"""
    return hmac.new(key, data, hashlib.sha384).digest()


def sha256(data: bytes) -> bytes:
    """SHA-256 哈希"""
    return hashlib.sha256(data).digest()


def sha384(data: bytes) -> bytes:
    """SHA-384 哈希"""
    return hashlib.sha384(data).digest()


# =============================================================================
# TLS 1.2 PRF 密钥派生
# =============================================================================

def p_hash(secret: bytes, seed: bytes, output_len: int, hash_func: str = 'sha256') -> bytes:
    """
    P_hash 函数 (TLS 1.2 PRF 的基础)
    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
    A(0) = seed
    A(i) = HMAC_hash(secret, A(i-1))
    """
    if hash_func == 'sha256':
        hmac_func = hmac_sha256
        hash_len = 32
    else:  # sha384
        hmac_func = hmac_sha384
        hash_len = 48

    result = b''
    a = seed

    while len(result) < output_len:
        a = hmac_func(secret, a)
        result += hmac_func(secret, a + seed)

    return result[:output_len]


def prf_tls12(secret: bytes, label: bytes, seed: bytes, output_len: int, hash_func: str = 'sha256') -> bytes:
    """
    TLS 1.2 PRF 函数
    PRF(secret, label, seed) = P_hash(secret, label + seed)
    """
    return p_hash(secret, label + seed, output_len, hash_func)


def derive_keys_tls12(
    pre_master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    cipher_suite: str
) -> dict:
    """
    TLS 1.2 密钥派生
    """
    # 1. 计算 Master Secret
    seed = client_random + server_random
    master_secret = prf_tls12(pre_master_secret, b"master secret", seed, 48)

    # 2. 根据加密套件确定密钥和 IV 长度
    if cipher_suite in ['TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256']:
        key_len, iv_len = 16, 4
    elif cipher_suite in ['TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']:
        key_len, iv_len = 32, 4
    elif cipher_suite == 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256':
        key_len, iv_len = 32, 12
    else:
        key_len, iv_len = 16, 4

    # 3. 计算 Key Block
    key_expansion_seed = server_random + client_random
    key_block_len = 2 * key_len + 2 * iv_len
    key_block = prf_tls12(master_secret, b"key expansion",
                          key_expansion_seed, key_block_len)

    # 4. 提取密钥和 IV
    offset = 0
    client_write_key = key_block[offset:offset + key_len]
    offset += key_len
    server_write_key = key_block[offset:offset + key_len]
    offset += key_len
    client_write_iv = key_block[offset:offset + iv_len]
    offset += iv_len
    server_write_iv = key_block[offset:offset + iv_len]

    return {
        'master_secret': master_secret,
        'client_write_key': client_write_key,
        'server_write_key': server_write_key,
        'client_write_iv': client_write_iv,
        'server_write_iv': server_write_iv,
    }


# =============================================================================
# TLS 1.3 HKDF 密钥派生
# =============================================================================

def hkdf_extract(salt: bytes, ikm: bytes, hash_func: str = 'sha256') -> bytes:
    """
    HKDF-Extract (RFC 5869)
    PRK = HMAC-Hash(salt, IKM)
    """
    if hash_func == 'sha256':
        return hmac_sha256(salt if salt else b'\x00' * 32, ikm)
    else:  # sha384
        return hmac_sha384(salt if salt else b'\x00' * 48, ikm)


def hkdf_expand(prk: bytes, info: bytes, output_len: int, hash_func: str = 'sha256') -> bytes:
    """
    HKDF-Expand (RFC 5869)
    T(1) = HMAC-Hash(PRK, info | 0x01)
    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    ...
    """
    if hash_func == 'sha256':
        hash_len = 32
        hmac_func = hmac_sha256
    else:  # sha384
        hash_len = 48
        hmac_func = hmac_sha384

    n = (output_len + hash_len - 1) // hash_len
    t = b''
    okm = b''

    for i in range(1, n + 1):
        t = hmac_func(prk, t + info + bytes([i]))
        okm += t

    return okm[:output_len]


def build_tls13_label(label: bytes, context: bytes, output_len: int) -> bytes:
    """
    构建 TLS 1.3 HKDF Label
    Label = length || "TLS 1.3, " || label || 0x00 || context_length || context
    """
    result = output_len.to_bytes(2, 'big')
    result += b'TLS 1.3, ' + label
    result += bytes([len(context)]) + context
    return result


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, output_len: int, hash_func: str = 'sha256') -> bytes:
    """
    HKDF-Expand-Label (RFC 8446)
    """
    hkdf_label = build_tls13_label(label, context, output_len)
    return hkdf_expand(secret, hkdf_label, output_len, hash_func)


def derive_keys_tls13(
    shared_secret: bytes,
    handshake_hash: bytes,
    cipher_suite: str
) -> dict:
    """
    TLS 1.3 密钥派生 (RFC 8446 Section 7.1)
    """
    # 根据加密套件确定哈希函数
    if cipher_suite in ['TLS13_AES_128_GCM_SHA256', 'TLS13_CHACHA20_POLY1305_SHA256']:
        hash_func = 'sha256'
        hash_len = 32
    else:  # TLS13_AES_256_GCM_SHA384
        hash_func = 'sha384'
        hash_len = 48

    # 1. 计算 handshake_secret
    zeros = b'\x00' * hash_len
    handshake_secret = hkdf_extract(zeros, shared_secret, hash_func)

    # 2. 计算 master_secret
    master_secret = hkdf_extract(zeros, handshake_secret, hash_func)

    # 3. 计算 client_application_traffic_secret
    client_app_label = build_tls13_label(
        b"c ap traffic", handshake_hash, hash_len)
    client_app_traffic_secret = hkdf_expand(
        master_secret, client_app_label, hash_len, hash_func)

    # 4. 计算 server_application_traffic_secret
    server_app_label = build_tls13_label(
        b"s ap traffic", handshake_hash, hash_len)
    server_app_traffic_secret = hkdf_expand(
        master_secret, server_app_label, hash_len, hash_func)

    # 5. 根据加密套件确定密钥和 IV 长度
    if cipher_suite == 'TLS13_AES_128_GCM_SHA256':
        key_len, iv_len = 16, 12
    elif cipher_suite == 'TLS13_AES_256_GCM_SHA384':
        key_len, iv_len = 32, 12
    elif cipher_suite == 'TLS13_CHACHA20_POLY1305_SHA256':
        key_len, iv_len = 32, 12
    else:
        key_len, iv_len = 16, 12

    # 6. 从 traffic secret 派生实际的密钥和 IV
    client_write_key = hkdf_expand_label(
        client_app_traffic_secret, b"key", b"", key_len, hash_func)
    client_write_iv = hkdf_expand_label(
        client_app_traffic_secret, b"iv", b"", iv_len, hash_func)
    server_write_key = hkdf_expand_label(
        server_app_traffic_secret, b"key", b"", key_len, hash_func)
    server_write_iv = hkdf_expand_label(
        server_app_traffic_secret, b"iv", b"", iv_len, hash_func)

    return {
        'handshake_secret': handshake_secret,
        'master_secret': master_secret,
        'client_application_traffic_secret': client_app_traffic_secret,
        'server_application_traffic_secret': server_app_traffic_secret,
        'client_write_key': client_write_key,
        'server_write_key': server_write_key,
        'client_write_iv': client_write_iv,
        'server_write_iv': server_write_iv,
    }


# =============================================================================
# AES-GCM 加密实现 (用于生成测试密文)
# =============================================================================

def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    AES-GCM 加密 (使用 Python cryptography 库)
    返回 (ciphertext, tag)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    # TLS 1.2: IV = salt(4B) + explicit_nonce(8B)
    # TLS 1.3: IV = static_iv XOR sequence_number
    nonce = iv
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    # 最后 16 字节是 tag
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    AES-GCM 解密
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    nonce = iv
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
    return plaintext


# =============================================================================
# ChaCha20-Poly1305 加密实现
# =============================================================================

def chacha20_poly1305_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    ChaCha20-Poly1305 加密
    返回 (ciphertext, tag)
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    chacha = ChaCha20Poly1305(key)
    nonce = iv
    ciphertext_with_tag = chacha.encrypt(nonce, plaintext, aad)

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return ciphertext, tag


def chacha20_poly1305_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    ChaCha20-Poly1305 解密
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    chacha = ChaCha20Poly1305(key)
    nonce = iv
    plaintext = chacha.decrypt(nonce, ciphertext + tag, aad)
    return plaintext


# =============================================================================
# TLS 记录构建
# =============================================================================

def build_tls12_record_header(content_type: int, version: bytes, length: int) -> bytes:
    """构建 TLS 1.2 记录头 (5 字节)"""
    return bytes([content_type]) + version + length.to_bytes(2, 'big')


def build_tls13_record_header(content_type: int, length: int) -> bytes:
    """构建 TLS 1.3 记录头 (5 字节)"""
    # TLS 1.3 版本固定为 0x0303
    return bytes([content_type]) + b'\x03\x03' + length.to_bytes(2, 'big')


def generate_tls12_gcm_record(
    write_key: bytes,
    write_iv: bytes,
    sequence_number: int,
    plaintext: bytes,
    content_type: int = 0x17  # application_data
) -> dict:
    """
    生成 TLS 1.2 AEAD 记录 (AES-GCM)

    TLS 1.2 GCM nonce 构造: salt(4B) + explicit_nonce(8B)
    explicit_nonce 作为记录的前缀
    """
    # 生成 8 字节 explicit nonce (使用序列号)
    explicit_nonce = sequence_number.to_bytes(8, 'big')

    # 完整 nonce = static_iv(4B) + explicit_nonce(8B)
    full_nonce = write_iv + explicit_nonce

    # 构建记录头 (用于 AAD)
    # 长度 = explicit_nonce(8) + ciphertext + tag(16)
    inner_plaintext_length = len(plaintext) + 16  # ciphertext + tag
    total_length = 8 + inner_plaintext_length
    header = build_tls12_record_header(content_type, b'\x03\x03', total_length)

    # AAD 就是记录头
    aad = header

    # 加密
    ciphertext, tag = aes_gcm_encrypt(write_key, full_nonce, plaintext, aad)

    # TLS 记录 = header + explicit_nonce + ciphertext + tag
    record = header + explicit_nonce + ciphertext + tag

    return {
        'record': record.hex(),
        'header': header.hex(),
        'explicit_nonce': explicit_nonce.hex(),
        'ciphertext': (ciphertext + tag).hex(),
        'plaintext': plaintext.hex(),
        'sequence_number': sequence_number,
    }


def generate_tls12_chacha20_record(
    write_key: bytes,
    write_iv: bytes,
    sequence_number: int,
    plaintext: bytes,
    content_type: int = 0x17
) -> dict:
    """
    生成 TLS 1.2 ChaCha20-Poly1305 记录

    ChaCha20-Poly1305 的 nonce 是 12 字节，直接使用 write_iv XOR sequence_number
    """
    # TLS 1.2 ChaCha20 nonce = static_iv XOR (0x00...00 || sequence_number)
    seq_bytes = sequence_number.to_bytes(12, 'big')
    nonce = bytes(a ^ b for a, b in zip(write_iv, seq_bytes))

    # 构建记录头
    inner_plaintext_length = len(plaintext) + 16  # ciphertext + tag
    total_length = inner_plaintext_length
    header = build_tls12_record_header(content_type, b'\x03\x03', total_length)

    aad = header

    # 加密
    ciphertext, tag = chacha20_poly1305_encrypt(
        write_key, nonce, plaintext, aad)

    # TLS 记录 = header + ciphertext + tag
    record = header + ciphertext + tag

    return {
        'record': record.hex(),
        'header': header.hex(),
        'ciphertext': (ciphertext + tag).hex(),
        'plaintext': plaintext.hex(),
        'sequence_number': sequence_number,
        'nonce': nonce.hex(),
    }


def generate_tls13_record(
    write_key: bytes,
    write_iv: bytes,
    sequence_number: int,
    plaintext: bytes,
    content_type: int = 0x17
) -> dict:
    """
    生成 TLS 1.3 记录

    TLS 1.3:
    - nonce = static_iv XOR (0x00...00 || sequence_number)
    - 内层 plaintext = plaintext + content_type + padding(可选)
    """
    # TLS 1.3 nonce = static_iv XOR sequence_number (右对齐)
    seq_bytes = sequence_number.to_bytes(12, 'big')
    nonce = bytes(a ^ b for a, b in zip(write_iv, seq_bytes))

    # TLS 1.3 内层 plaintext = 应用数据 + content_type(1 字节)
    inner_plaintext = plaintext + bytes([content_type])

    # 构建记录头
    # 长度 = inner_plaintext_length + tag(16)
    total_length = len(inner_plaintext) + 16
    header = build_tls13_record_header(
        0x17, total_length)  # 外层始终是 application_data

    aad = header

    # 加密 (使用对应的加密算法)
    if len(write_key) == 32:
        # ChaCha20-Poly1305 或 AES-256-GCM
        if write_iv == write_iv:  # 无法区分，需要外部信息
            ciphertext, tag = chacha20_poly1305_encrypt(
                write_key, nonce, inner_plaintext, aad)
        else:
            ciphertext, tag = aes_gcm_encrypt(
                write_key, nonce, inner_plaintext, aad)
    else:
        # AES-128-GCM
        ciphertext, tag = aes_gcm_encrypt(
            write_key, nonce, inner_plaintext, aad)

    # TLS 记录 = header + ciphertext + tag
    record = header + ciphertext + tag

    return {
        'record': record.hex(),
        'header': header.hex(),
        'ciphertext_with_tag': (ciphertext + tag).hex(),
        'inner_plaintext': inner_plaintext.hex(),
        'plaintext': plaintext.hex(),
        'sequence_number': sequence_number,
        'nonce': nonce.hex(),
    }


def generate_tls13_record_with_cipher(
    write_key: bytes,
    write_iv: bytes,
    sequence_number: int,
    plaintext: bytes,
    cipher_type: str,  # 'aes_gcm' or 'chacha20'
    content_type: int = 0x17
) -> dict:
    """
    生成 TLS 1.3 记录 (明确指定加密算法)
    """
    # TLS 1.3 nonce = static_iv XOR sequence_number (右对齐)
    seq_bytes = sequence_number.to_bytes(12, 'big')
    nonce = bytes(a ^ b for a, b in zip(write_iv, seq_bytes))

    # TLS 1.3 内层 plaintext = 应用数据 + content_type(1 字节)
    inner_plaintext = plaintext + bytes([content_type])

    # 构建记录头
    total_length = len(inner_plaintext) + 16
    header = build_tls13_record_header(0x17, total_length)

    aad = header

    # 加密
    if cipher_type == 'chacha20':
        ciphertext, tag = chacha20_poly1305_encrypt(
            write_key, nonce, inner_plaintext, aad)
    else:  # aes_gcm
        ciphertext, tag = aes_gcm_encrypt(
            write_key, nonce, inner_plaintext, aad)

    record = header + ciphertext + tag

    return {
        'record': record.hex(),
        'header': header.hex(),
        'ciphertext_with_tag': (ciphertext + tag).hex(),
        'inner_plaintext': inner_plaintext.hex(),
        'plaintext': plaintext.hex(),
        'sequence_number': sequence_number,
        'nonce': nonce.hex(),
    }


# =============================================================================
# 测试用例生成
# =============================================================================

def bytes_to_hex(data: bytes) -> str:
    """将字节转换为十六进制字符串"""
    return data.hex()


def generate_test_cases() -> List[Dict[str, Any]]:
    """生成所有测试用例"""
    test_cases = []

    # =========================================================================
    # TLS 1.2 测试用例
    # =========================================================================

    # -------------------------------------------------------------------------
    # 测试用例 1: TLS 1.2 RSA AES-128-GCM
    # -------------------------------------------------------------------------
    client_random = bytes.fromhex(
        '20bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '35c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    pre_master_secret = bytes.fromhex(
        '03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e')

    keys = derive_keys_tls12(pre_master_secret, client_random,
                             server_random, 'TLS_RSA_WITH_AES_128_GCM_SHA256')

    # 生成客户端到服务器端的加密记录
    plaintext = b"Hello, TLS 1.2 RSA AES-128-GCM!"
    client_record = generate_tls12_gcm_record(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext
    )

    # 生成服务器端到客户端的加密记录
    server_plaintext = b"Response from server!"
    server_record = generate_tls12_gcm_record(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext
    )

    test_cases.append({
        "name": "tls12_rsa_aes128gcm_basic",
        "version": "TLS12",
        "key_exchange": "RSA",
        "cipher_suite": "0x009C",
        "cipher_suite_name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "description": "TLS 1.2 RSA 密钥交换，AES-128-GCM 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    # -------------------------------------------------------------------------
    # 测试用例 2: TLS 1.2 RSA AES-256-GCM
    # -------------------------------------------------------------------------
    client_random = bytes.fromhex(
        '21bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '36c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    pre_master_secret = bytes.fromhex(
        '03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e')

    keys = derive_keys_tls12(pre_master_secret, client_random,
                             server_random, 'TLS_RSA_WITH_AES_256_GCM_SHA384')

    plaintext = b"Hello, TLS 1.2 RSA AES-256-GCM!"
    client_record = generate_tls12_gcm_record(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext
    )

    server_plaintext = b"Response from server with AES-256-GCM!"
    server_record = generate_tls12_gcm_record(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext
    )

    test_cases.append({
        "name": "tls12_rsa_aes256gcm_basic",
        "version": "TLS12",
        "key_exchange": "RSA",
        "cipher_suite": "0x009D",
        "cipher_suite_name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "description": "TLS 1.2 RSA 密钥交换，AES-256-GCM 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    # -------------------------------------------------------------------------
    # 测试用例 3: TLS 1.2 ECDHE ChaCha20-Poly1305
    # -------------------------------------------------------------------------
    client_random = bytes.fromhex(
        '22bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '37c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    pre_master_secret = bytes.fromhex(
        '04a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a596877869504132231400a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140')

    keys = derive_keys_tls12(pre_master_secret, client_random,
                             server_random, 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256')

    plaintext = b"Hello, TLS 1.2 ECDHE ChaCha20-Poly1305!"
    client_record = generate_tls12_chacha20_record(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext
    )

    server_plaintext = b"Response with ChaCha20-Poly1305!"
    server_record = generate_tls12_chacha20_record(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext
    )

    test_cases.append({
        "name": "tls12_ecdhe_chacha20poly1305_basic",
        "version": "TLS12",
        "key_exchange": "ECDHE",
        "cipher_suite": "0xCCA8",
        "cipher_suite_name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "description": "TLS 1.2 ECDHE 密钥交换，ChaCha20-Poly1305 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    # =========================================================================
    # TLS 1.3 测试用例
    # =========================================================================

    # -------------------------------------------------------------------------
    # 测试用例 4: TLS 1.3 AES-128-GCM
    # -------------------------------------------------------------------------
    client_hello_random = bytes.fromhex(
        '23bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '38c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    shared_secret = bytes.fromhex(
        'b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0')
    handshake_hash = sha256(b"fake handshake messages for testing")

    keys = derive_keys_tls13(
        shared_secret, handshake_hash, 'TLS13_AES_128_GCM_SHA256')

    plaintext = b"Hello, TLS 1.3 AES-128-GCM!"
    client_record = generate_tls13_record_with_cipher(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext,
        cipher_type='aes_gcm'
    )

    server_plaintext = b"Response from TLS 1.3 server!"
    server_record = generate_tls13_record_with_cipher(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext,
        cipher_type='aes_gcm'
    )

    test_cases.append({
        "name": "tls13_aes128gcm_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1301",
        "cipher_suite_name": "TLS13_AES_128_GCM_SHA256",
        "description": "TLS 1.3 AES-128-GCM 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(keys['handshake_secret']),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(keys['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(keys['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    # -------------------------------------------------------------------------
    # 测试用例 5: TLS 1.3 AES-256-GCM
    # -------------------------------------------------------------------------
    client_hello_random = bytes.fromhex(
        '24bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '39c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    shared_secret = bytes.fromhex(
        'c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0')
    handshake_hash = sha384(
        b"fake handshake messages for testing tls13 aes-256-gcm")

    keys = derive_keys_tls13(
        shared_secret, handshake_hash, 'TLS13_AES_256_GCM_SHA384')

    plaintext = b"Hello, TLS 1.3 AES-256-GCM!"
    client_record = generate_tls13_record_with_cipher(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext,
        cipher_type='aes_gcm'
    )

    server_plaintext = b"Response from TLS 1.3 with AES-256-GCM!"
    server_record = generate_tls13_record_with_cipher(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext,
        cipher_type='aes_gcm'
    )

    test_cases.append({
        "name": "tls13_aes256gcm_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1302",
        "cipher_suite_name": "TLS13_AES_256_GCM_SHA384",
        "description": "TLS 1.3 AES-256-GCM 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(keys['handshake_secret']),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(keys['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(keys['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    # -------------------------------------------------------------------------
    # 测试用例 6: TLS 1.3 ChaCha20-Poly1305
    # -------------------------------------------------------------------------
    client_hello_random = bytes.fromhex(
        '25bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '3ac5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    shared_secret = bytes.fromhex(
        'd1e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0')
    handshake_hash = sha256(
        b"fake handshake messages for testing tls13 chacha20")

    keys = derive_keys_tls13(
        shared_secret, handshake_hash, 'TLS13_CHACHA20_POLY1305_SHA256')

    plaintext = b"Hello, TLS 1.3 ChaCha20-Poly1305!"
    client_record = generate_tls13_record_with_cipher(
        keys['client_write_key'],
        keys['client_write_iv'],
        sequence_number=0,
        plaintext=plaintext,
        cipher_type='chacha20'
    )

    server_plaintext = b"Response from TLS 1.3 with ChaCha20!"
    server_record = generate_tls13_record_with_cipher(
        keys['server_write_key'],
        keys['server_write_iv'],
        sequence_number=0,
        plaintext=server_plaintext,
        cipher_type='chacha20'
    )

    test_cases.append({
        "name": "tls13_chacha20poly1305_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1303",
        "cipher_suite_name": "TLS13_CHACHA20_POLY1305_SHA256",
        "description": "TLS 1.3 ChaCha20-Poly1305 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(keys['handshake_secret']),
        "master_secret": bytes_to_hex(keys['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(keys['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(keys['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(keys['client_write_key']),
        "server_write_key": bytes_to_hex(keys['server_write_key']),
        "client_write_iv": bytes_to_hex(keys['client_write_iv']),
        "server_write_iv": bytes_to_hex(keys['server_write_iv']),
        "client_to_server": {
            "plaintext": plaintext.decode('utf-8'),
            "sequence_number": 0,
            **client_record
        },
        "server_to_client": {
            "plaintext": server_plaintext.decode('utf-8'),
            "sequence_number": 0,
            **server_record
        }
    })

    return test_cases


def main():
    """主函数"""
    print("生成 TLS 解密测试数据...")

    try:
        test_cases = generate_test_cases()

        # 生成 JSON 文件
        with open('tls_decrypt_test_cases.json', 'w', encoding='utf-8') as f:
            json.dump(test_cases, f, indent=4, ensure_ascii=False)

        print(f"测试数据已生成到 tests/testdata/tls_decrypt_test_cases.json")
        print(f"共 {len(test_cases)} 个测试用例")

        # 打印摘要
        print("\n测试用例摘要:")
        for case in test_cases:
            print(f"\n  {case['name']}:")
            print(f"    版本：{case['version']}")
            print(f"    套件：{case['cipher_suite_name']}")
            print(f"    描述：{case['description']}")
            if 'client_to_server' in case:
                print(f"    C->S 明文：{case['client_to_server']['plaintext']}")
                print(f"    S->C 明文：{case['server_to_client']['plaintext']}")

        print("\n测试数据生成完成!")

    except ImportError as e:
        print(f"错误：缺少必要的 Python 库 - {e}")
        print("请安装 cryptography 库：pip install cryptography")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
