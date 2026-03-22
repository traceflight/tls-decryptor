# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview

Rust TLS decryption utility library supporting TLS 1.2 and TLS 1.3 Application Data record decryption.

## Build/Test Commands

```bash
cargo build          # Build
cargo test           # Run tests
cargo check          # Quick check
cargo clippy         # Lint
cargo fmt --check    # Format check
cargo fmt            # Format
```

## Code Architecture

- [`src/lib.rs`](src/lib.rs) - Library entry point, public API exports
- [`src/decrypter.rs`](src/decrypter.rs) - `TlsDecrypter` core decryption logic, manages sequence numbers
- [`src/key_derivation.rs`](src/key_derivation.rs) - TLS 1.2 PRF / TLS 1.3 HKDF key derivation
- [`src/types.rs`](src/types.rs) - `SessionKey`, `TlsVersion`, `Direction`, `RecordHeader`
- [`src/error.rs`](src/error.rs) - `DecryptError` error type
- [`src/cipher/`](src/cipher/) - Pluggable cipher suite architecture
  - [`trait_def.rs`](src/cipher/trait_def.rs) - `CipherContext` trait
  - [`registry.rs`](src/cipher/registry.rs) - Global registry (singleton)
  - [`suites/`](src/cipher/suites/) - Concrete suite implementations

## Code Style

- **Import order**: Standard library → External crates → Internal modules
- **Error handling**: Uses `thiserror`, uniformly returns `Result<T, DecryptError>`
- **Naming**: Rust snake_case for functions/variables, PascalCase for structs
- **Documentation**: Public APIs must have `///` doc comments

## Cipher Suite Implementation Specifications

When adding a new suite:
1. Create a file in [`src/cipher/suites/`](src/cipher/suites/) using rustls enum naming (lowercase snake_case)
2. Implement the [`CipherContext`](src/cipher/trait_def.rs) trait
3. Add `pub mod` and re-export in [`suites/mod.rs`](src/cipher/suites/mod.rs)
4. Register in `register_builtins()` of [`registry.rs`](src/cipher/registry.rs)

## Key Considerations

- **TLS 1.2 nonce**: salt(4B) + explicit_nonce(8B), explicit_nonce prefixed to ciphertext
- **TLS 1.3 nonce**: static_iv XOR sequence_number (right-aligned)
- **Sequence number management**: Maintained internally by `TlsDecrypter`, wraps to 0 on overflow
- **AEAD additional data**: Must be 5-byte record header
