#!/usr/bin/env python3
"""
TLS 测试数据生成器

使用 Python 的 cryptography 和 hashlib 库实现 TLS 1.2 和 TLS 1.3 的密钥派生逻辑，
生成真实的测试数据用于验证 Rust 实现。

运行：python3 tests/testdata/generate_test_data.py
"""

import hashlib
import hmac
import json
from typing import List, Tuple


def bytes_to_hex(data: bytes) -> str:
    """将字节转换为十六进制字符串"""
    return data.hex()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256"""
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha384(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA384"""
    return hmac.new(key, data, hashlib.sha384).digest()


def p_hash(secret: bytes, seed: bytes, output_len: int, hash_func='sha256') -> bytes:
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
        # A(i) = HMAC(secret, A(i-1))
        a = hmac_func(secret, a)
        # HMAC(secret, A(i) + seed)
        result += hmac_func(secret, a + seed)

    return result[:output_len]


def prf_tls12(secret: bytes, label: bytes, seed: bytes, output_len: int) -> bytes:
    """
    TLS 1.2 PRF 函数
    PRF(secret, label, seed) = P_hash(secret, label + seed)
    """
    return p_hash(secret, label + seed, output_len)


def hkdf_extract(salt: bytes, ikm: bytes, hash_func='sha256') -> bytes:
    """
    HKDF-Extract (RFC 5869)
    PRK = HMAC-Hash(salt, IKM)
    """
    if hash_func == 'sha256':
        return hmac_sha256(salt if salt else b'\x00' * 32, ikm)
    else:  # sha384
        return hmac_sha384(salt if salt else b'\x00' * 48, ikm)


def hkdf_expand(prk: bytes, info: bytes, output_len: int, hash_func='sha256') -> bytes:
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


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, output_len: int, hash_func='sha256') -> bytes:
    """
    HKDF-Expand-Label (RFC 8446)
    """
    hkdf_label = build_tls13_label(label, context, output_len)
    return hkdf_expand(secret, hkdf_label, output_len, hash_func)


def derive_keys_tls12(
    client_random: bytes,
    server_random: bytes,
    pre_master_secret: bytes,
    cipher_suite: str
) -> dict:
    """
    TLS 1.2 密钥派生
    """
    # 1. 计算 Master Secret
    # master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
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
    # key_block = PRF(master_secret, "key expansion", server_random + client_random)
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


def derive_keys_tls13(
    client_hello_random: bytes,
    server_hello_random: bytes,
    shared_secret: bytes,
    cipher_suite: str,
    handshake_hash: bytes
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
    # handshake_secret = HKDF-Extract(0, shared_secret)
    zeros = b'\x00' * hash_len
    handshake_secret = hkdf_extract(zeros, shared_secret, hash_func)

    # 2. 计算 client_handshake_traffic_secret
    # client_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", handshake_hash)
    client_label = build_tls13_label(b"c hs traffic", handshake_hash, hash_len)
    client_handshake_traffic_secret = hkdf_expand(
        handshake_secret, client_label, hash_len, hash_func)

    # 3. 计算 server_handshake_traffic_secret
    server_label = build_tls13_label(b"s hs traffic", handshake_hash, hash_len)
    server_handshake_traffic_secret = hkdf_expand(
        handshake_secret, server_label, hash_len, hash_func)

    # 4. 计算 master_secret
    # master_secret = HKDF-Extract(0, handshake_secret)
    master_secret = hkdf_extract(zeros, handshake_secret, hash_func)

    # 5. 计算 client_application_traffic_secret
    # client_application_traffic_secret_0 = HKDF-Expand-Label(master_secret, "c ap traffic", handshake_hash)
    client_app_label = build_tls13_label(
        b"c ap traffic", handshake_hash, hash_len)
    client_app_traffic_secret = hkdf_expand(
        master_secret, client_app_label, hash_len, hash_func)

    # 6. 计算 server_application_traffic_secret
    server_app_label = build_tls13_label(
        b"s ap traffic", handshake_hash, hash_len)
    server_app_traffic_secret = hkdf_expand(
        master_secret, server_app_label, hash_len, hash_func)

    # 7. 根据加密套件确定密钥和 IV 长度
    if cipher_suite == 'TLS13_AES_128_GCM_SHA256':
        key_len, iv_len = 16, 12
    elif cipher_suite == 'TLS13_AES_256_GCM_SHA384':
        key_len, iv_len = 32, 12
    elif cipher_suite == 'TLS13_CHACHA20_POLY1305_SHA256':
        key_len, iv_len = 32, 12
    else:
        key_len, iv_len = 16, 12

    # 8. 从 traffic secret 派生实际的密钥和 IV
    # key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
    # iv = HKDF-Expand-Label(traffic_secret, "iv", "", iv_length)
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
        'client_handshake_traffic_secret': client_handshake_traffic_secret,
        'server_handshake_traffic_secret': server_handshake_traffic_secret,
        'master_secret': master_secret,
        'client_application_traffic_secret': client_app_traffic_secret,
        'server_application_traffic_secret': server_app_traffic_secret,
        'client_write_key': client_write_key,
        'server_write_key': server_write_key,
        'client_write_iv': client_write_iv,
        'server_write_iv': server_write_iv,
    }


def main():
    test_cases = []

    # =========================================================================
    # TLS 1.2 测试用例
    # =========================================================================

    # 测试用例 1: TLS 1.2 RSA AES-128-GCM
    client_random = bytes.fromhex(
        '20bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '35c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    # TLS 1.2 RSA: pre_master_secret = 0x0303 || 46 random bytes
    pre_master_secret = bytes.fromhex(
        '03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e')

    result = derive_keys_tls12(
        client_random, server_random, pre_master_secret, 'TLS_RSA_WITH_AES_128_GCM_SHA256')

    test_cases.append({
        "name": "tls12_rsa_aes128gcm_basic",
        "version": "TLS12",
        "key_exchange": "RSA",
        "cipher_suite": "0x009C",
        "description": "TLS 1.2 RSA 密钥交换，AES-128-GCM 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # 测试用例 2: TLS 1.2 RSA AES-256-GCM
    client_random = bytes.fromhex(
        '21bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '36c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    pre_master_secret = bytes.fromhex(
        '03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e')

    result = derive_keys_tls12(
        client_random, server_random, pre_master_secret, 'TLS_RSA_WITH_AES_256_GCM_SHA384')

    test_cases.append({
        "name": "tls12_rsa_aes256gcm_basic",
        "version": "TLS12",
        "key_exchange": "RSA",
        "cipher_suite": "0x009D",
        "description": "TLS 1.2 RSA 密钥交换，AES-256-GCM 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # 测试用例 3: TLS 1.2 ECDHE AES-128-GCM
    client_random = bytes.fromhex(
        '22bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_random = bytes.fromhex(
        '37c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    # ECDHE: pre_master_secret = shared secret (对于 P-256，是 65 字节的未压缩公钥格式)
    pre_master_secret = bytes.fromhex(
        '04a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a596877869504132231400a1b2c3d4e5f6071829304a5b6c7d8e9ff0e1d2c3b4a59687786950413223140')

    result = derive_keys_tls12(client_random, server_random,
                               pre_master_secret, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')

    test_cases.append({
        "name": "tls12_ecdhe_aes128gcm_basic",
        "version": "TLS12",
        "key_exchange": "ECDHE",
        "cipher_suite": "0xC02B",
        "description": "TLS 1.2 ECDHE 密钥交换，AES-128-GCM 加密",
        "client_random": bytes_to_hex(client_random),
        "server_random": bytes_to_hex(server_random),
        "pre_master_secret": bytes_to_hex(pre_master_secret),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # =========================================================================
    # TLS 1.3 测试用例
    # =========================================================================

    # 测试用例 4: TLS 1.3 AES-128-GCM
    client_hello_random = bytes.fromhex(
        '23bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '38c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    # TLS 1.3: shared secret 是 ECDHE 共享密钥 (32 字节)
    shared_secret = bytes.fromhex(
        'b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0')
    # handshake_hash 是握手消息的 SHA-256 哈希
    handshake_hash = bytes.fromhex(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

    result = derive_keys_tls13(client_hello_random, server_hello_random,
                               shared_secret, 'TLS13_AES_128_GCM_SHA256', handshake_hash)

    test_cases.append({
        "name": "tls13_aes128gcm_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1301",
        "description": "TLS 1.3 AES-128-GCM 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(result['handshake_secret']),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(result['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(result['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # 测试用例 5: TLS 1.3 AES-256-GCM
    client_hello_random = bytes.fromhex(
        '24bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '39c5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    shared_secret = bytes.fromhex(
        'c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0')
    # TLS 1.3 AES-256-GCM 使用 SHA-384
    handshake_hash = bytes.fromhex(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

    result = derive_keys_tls13(client_hello_random, server_hello_random,
                               shared_secret, 'TLS13_AES_256_GCM_SHA384', handshake_hash)

    test_cases.append({
        "name": "tls13_aes256gcm_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1302",
        "description": "TLS 1.3 AES-256-GCM 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(result['handshake_secret']),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(result['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(result['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # 测试用例 6: TLS 1.3 ChaCha20-Poly1305
    client_hello_random = bytes.fromhex(
        '25bdc2efb8386b8b00594c755b4f9e2d0a9e9c7f5e8d3c2b1a0f9e8d7c6b5a49')
    server_hello_random = bytes.fromhex(
        '3ac5e5f5a5b5c5d5e5f505152535455565758595a5b5c5d5e5f5051525354555')
    shared_secret = bytes.fromhex(
        'd1e2f30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0')
    handshake_hash = bytes.fromhex(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

    result = derive_keys_tls13(client_hello_random, server_hello_random,
                               shared_secret, 'TLS13_CHACHA20_POLY1305_SHA256', handshake_hash)

    test_cases.append({
        "name": "tls13_chacha20poly1305_basic",
        "version": "TLS13",
        "key_exchange": "ECDHE",
        "cipher_suite": "0x1303",
        "description": "TLS 1.3 ChaCha20-Poly1305 加密",
        "client_hello_random": bytes_to_hex(client_hello_random),
        "server_hello_random": bytes_to_hex(server_hello_random),
        "shared_secret": bytes_to_hex(shared_secret),
        "handshake_hash": bytes_to_hex(handshake_hash),
        "handshake_secret": bytes_to_hex(result['handshake_secret']),
        "master_secret": bytes_to_hex(result['master_secret']),
        "client_application_traffic_secret": bytes_to_hex(result['client_application_traffic_secret']),
        "server_application_traffic_secret": bytes_to_hex(result['server_application_traffic_secret']),
        "client_write_key": bytes_to_hex(result['client_write_key']),
        "server_write_key": bytes_to_hex(result['server_write_key']),
        "client_write_iv": bytes_to_hex(result['client_write_iv']),
        "server_write_iv": bytes_to_hex(result['server_write_iv']),
    })

    # 生成 JSON 文件
    with open('key_derivation_test_cases_real.json', 'w', encoding='utf-8') as f:
        json.dump(test_cases, f, indent=4, ensure_ascii=False)

    print("测试数据已生成到 tests/testdata/key_derivation_test_cases_real.json")
    print(f"共 {len(test_cases)} 个测试用例")

    # 打印摘要
    for case in test_cases:
        print(f"\n{case['name']}:")
        if 'client_write_key' in case:
            print(f"  client_write_key: {case['client_write_key']}")
        if 'server_write_key' in case:
            print(f"  server_write_key: {case['server_write_key']}")


if __name__ == '__main__':
    main()
