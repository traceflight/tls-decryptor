# TLS Decrypt

A Rust TLS decryption library (with private key) supporting TLS 1.2 and TLS 1.3 Application Data record decryption.

## Prerequisites

**Important:** This library requires access to the private key to derive session keys and decrypt TLS traffic. Specifically:

- **TLS 1.2 with RSA key exchange**: Requires the server's RSA private key to decrypt the Pre-Master Secret from the ClientKeyExchange message
- **TLS 1.2 with ECDHE key exchange**: Requires the ECDHE private key to compute the shared secret
- **TLS 1.3**: Requires the ECDHE private key to compute the shared secret

Without the corresponding private key, this library cannot derive the session keys needed for decryption.

## Features

- 🔐 Derive TLS session keys from private keys and handshake parameters
- 📦 Decrypt individual TLS Application Data records using session keys
- 🔧 Support for multiple cipher suites (AES-GCM, ChaCha20-Poly1305)
- 🧩 Extensible cipher suite architecture
- ✅ Comprehensive test coverage with test data verified by Python scripts

## Supported Cipher Suites

### TLS 1.2
| Cipher Suite Name | ID | Key Exchange | Encryption |
|------------------|-----|--------------|------------|
| TLS_RSA_WITH_AES_128_GCM_SHA256 | 0x009C | RSA | AES-128-GCM |
| TLS_RSA_WITH_AES_256_GCM_SHA384 | 0x009D | RSA | AES-256-GCM |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | 0xCCA8 | ECDHE | ChaCha20-Poly1305 |

### TLS 1.3
| Cipher Suite Name | ID | Encryption |
|------------------|-----|------------|
| TLS13_AES_128_GCM_SHA256 | 0x1301 | AES-128-GCM |
| TLS13_AES_256_GCM_SHA384 | 0x1302 | AES-256-GCM |
| TLS13_CHACHA20_POLY1305_SHA256 | 0x1303 | ChaCha20-Poly1305 |

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
tls-decrypt = "0.1.0"
```

## Quick Start

### TLS 1.2 RSA Key Exchange

```rust
use tls_decrypt::{
    TlsDecrypter, SessionKey, Direction,
    key_derivation::{derive_keys_tls12, decrypt_pre_master_secret_rsa},
    types::TlsVersion,
};
use rustls::CipherSuite;

fn main() -> Result<(), tls_decrypt::DecryptError> {
    // 1. Decrypt Pre-Master Secret using private key
    let private_key_pem = std::fs::read_to_string("server_key.pem")?;
    let encrypted_pms = /* extracted from ClientKeyExchange message */;
    let pre_master_secret = decrypt_pre_master_secret_rsa(&private_key_pem, &encrypted_pms)?;

    // 2. Derive session keys
    let client_random = /* extracted from ClientHello (32 bytes) */;
    let server_random = /* extracted from ServerHello (32 bytes) */;
    let cipher_suite = CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256;

    let session_key = derive_keys_tls12(
        &client_random,
        &server_random,
        &pre_master_secret,
        cipher_suite,
    )?;

    // 3. Create decrypter and decrypt
    let mut decrypter = TlsDecrypter::new(session_key)?;
    let encrypted_record = /* TLS Application Data record */;
    
    let plaintext = decrypter.decrypt_application_data(
        &encrypted_record,
        Direction::ServerToClient,
    )?;

    println!("Decrypted: {:?}", String::from_utf8_lossy(&plaintext));
    
    Ok(())
}
```

### TLS 1.3 ECDHE Key Exchange

```rust
use tls_decrypt::{
    TlsDecrypter, Direction,
    key_derivation::derive_keys_tls13,
};
use rustls::CipherSuite;

fn main() -> Result<(), tls_decrypt::DecryptError> {
    // 1. Compute ECDHE shared secret
    let shared_secret = /* ECDHE shared secret */;

    // 2. Derive session keys
    let cipher_suite = CipherSuite::TLS13_AES_128_GCM_SHA256;
    let handshake_hash = /* hash of handshake messages */;

    let session_key = derive_keys_tls13(
        &shared_secret,
        cipher_suite,
        &handshake_hash,
    )?;

    // 3. Create decrypter and decrypt
    let mut decrypter = TlsDecrypter::new(session_key)?;
    let encrypted_record = /* TLS Application Data record */;
    
    let plaintext = decrypter.decrypt_application_data(
        &encrypted_record,
        Direction::ClientToServer,
    )?;

    println!("Decrypted: {:?}", String::from_utf8_lossy(&plaintext));
    
    Ok(())
}
```

### Decrypt with Known Session Keys

If you already have the session keys (e.g., exported from Wireshark or other tools), you can directly create a `SessionKey`:

```rust
use tls_decrypt::{TlsDecrypter, SessionKey, Direction};
use tls_decrypt::types::TlsVersion;
use rustls::CipherSuite;

fn main() -> Result<(), tls_decrypt::DecryptError> {
    // Directly create session key
    let session_key = SessionKey::new(
        TlsVersion::Tls13,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        vec![0u8; 16], // client_write_key
        vec![0u8; 16], // server_write_key
        vec![0u8; 12], // client_write_iv
        vec![0u8; 12], // server_write_iv
    );

    let mut decrypter = TlsDecrypter::new(session_key)?;
    
    // Decrypt data
    let encrypted_record = hex::decode("170303002c...")?;
    let plaintext = decrypter.decrypt_application_data(
        &encrypted_record,
        Direction::ServerToClient,
    )?;

    Ok(())
}
```

## API Reference

### Core Types

#### `TlsDecrypter`
TLS record decrypter responsible for decrypting TLS Application Data records.

```rust
// Create decrypter
let decrypter = TlsDecrypter::new(session_key)?;

// Create decrypter with initial sequence numbers
let decrypter = TlsDecrypter::with_sequence_numbers(
    session_key,
    client_to_server_seq,
    server_to_client_seq,
)?;

// Decrypt Application Data record
let plaintext = decrypter.decrypt_application_data(&encrypted_record, direction)?;

// Manage sequence numbers
decrypter.set_sequence_number(Direction::ClientToServer, 100);
decrypter.reset_sequence_numbers();
```

#### `SessionKey`
Session key material containing all keys required to decrypt TLS records.

```rust
let session_key = SessionKey::new(
    version,        // TlsVersion
    cipher_suite,   // CipherSuite
    client_write_key,
    server_write_key,
    client_write_iv,
    server_write_iv,
);
```

#### `Direction`
Data flow direction enum.

```rust
enum Direction {
    ClientToServer,  // Client to server
    ServerToClient,  // Server to client
}
```

### Key Derivation Functions

#### `derive_keys_tls12`
TLS 1.2 key derivation function using PRF (Pseudo-Random Function).

```rust
pub fn derive_keys_tls12(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    pre_master_secret: &[u8],
    cipher_suite: CipherSuite,
) -> Result<SessionKey>
```

#### `derive_keys_tls13`
TLS 1.3 key derivation function using HKDF (HMAC-based Key Derivation Function).

```rust
pub fn derive_keys_tls13(
    shared_secret: &[u8],
    cipher_suite: CipherSuite,
    handshake_hash: &[u8],
) -> Result<SessionKey>
```

## Architecture

### Cipher Suite Architecture

The library uses an extensible cipher suite architecture:

1. **[`CipherContext`](src/cipher/trait_def.rs)** - Trait defining the cipher suite interface
2. **[`CipherRegistry`](src/cipher/registry.rs)** - Global registry (singleton pattern)
3. **[`suites/`](src/cipher/suites/)** - Concrete suite implementations

Adding a new cipher suite:
1. Create a new file in `src/cipher/suites/`
2. Implement the `CipherContext` trait
3. Add `pub mod` declaration in [`suites/mod.rs`](src/cipher/suites/mod.rs)
4. Register in [`registry.rs`](src/cipher/registry.rs) `register_builtins()`

## Technical Details

### TLS 1.2 Key Derivation

```
master_secret = PRF(pre_master_secret, "master secret", 
                    ClientHello.random + ServerHello.random)

key_block = PRF(master_secret, "key expansion",
                ServerHello.random + ClientHello.random)

key_block = client_write_key | server_write_key | 
            client_write_IV | server_write_IV
```

### TLS 1.3 Key Derivation

```
handshake_secret = HKDF-Extract(0, shared_secret)
master_secret = HKDF-Extract(0, handshake_secret)

client_application_traffic_secret = 
    HKDF-Expand-Label(master_secret, "c ap traffic", handshake_hash)

key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
iv = HKDF-Expand-Label(traffic_secret, "iv", "", iv_length)
```

### AEAD Additional Data

The Additional Authenticated Data (AAD) used for AEAD decryption must be the 5-byte TLS record header:
```
AAD = content_type (1) || version (2) || length (2)
```

### Sequence Number Management

- `TlsDecrypter` maintains sequence numbers for both directions internally
- Each direction counts independently
- Wraps around to 0 on overflow

## Contributing

Issues and Pull Requests are welcome!

## Related Links

- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [rustls](https://github.com/rustls/rustls)

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)