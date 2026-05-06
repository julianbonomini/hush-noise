# hush-noise

A Rust implementation of the [Noise Protocol Framework](https://noiseprotocol.org) — the secure channel layer underneath WireGuard and Signal.

TLS is designed for the web: certificate authorities, domain names, server-authenticates-client. Noise is designed for peers: no CA, no PKI, both sides authenticate each other with keypairs they own. `hush-noise` is part of the [hush](https://github.com/julianbonomini) stack — a set of primitives built on the belief that privacy should be invisible infrastructure, not a feature you configure.

Compiles to iOS, Android, macOS, Linux, and WASM. Exposes native Swift and Kotlin bindings via [UniFFI](https://github.com/mozilla/uniffi-rs).

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
hush-noise = { git = "https://github.com/julianbonomini/hush-noise" }
```

```rust
use hush_noise::{keypair::generate_keypair, session::{dial, accept}};

// Each peer generates a long-term keypair once and persists it.
let initiator_kp = generate_keypair();
let responder_kp = generate_keypair();

// Any Read + Write + Send works — TCP, Unix socket, in-memory pipe, etc.
let (i_conn, r_conn) = make_transport_pair();

// Handshake runs concurrently on both sides.
let r_kp = keypair::Keypair::new(responder_kp.private(), responder_kp.public_key);
let r_handle = std::thread::spawn(move || accept(r_conn, r_kp));
let i_session = dial(i_conn, initiator_kp).expect("dial failed");
let r_session = r_handle.join().unwrap().expect("accept failed");

// Send and receive encrypted messages.
i_session.send(b"hello").unwrap();
let msg = r_session.receive().unwrap();
assert_eq!(msg, b"hello");
```

## Security properties

- **Mutual authentication** — both peers prove ownership of their static keypair during the handshake. Neither side can be impersonated.
- **Forward secrecy** — session keys are derived from ephemeral Diffie-Hellman values. Compromising a long-term keypair does not decrypt past sessions.
- **Remote identity** — after the handshake, `session.remote_public_key()` returns the authenticated static public key of the peer. What you do with that key — whether to accept or reject the connection — is your responsibility. The library guarantees the cryptographic identity; trust policy is yours.
- **Cipher suite** — `Noise_XX_25519_ChaChaPoly_BLAKE2s`. ChaCha20-Poly1305 for constant-time encryption on all platforms; no timing side-channels without hardware AES.

## Correctness

Verified against the official [cacophony test vectors](https://github.com/rweather/noise-c/blob/master/tests/vector/cacophony.txt) for `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Passing the vectors proves spec-compliance and cross-implementation interoperability, not just self-consistency.

All cryptographic primitives come from [RustCrypto](https://github.com/RustCrypto) — no C dependencies, no `ring`.

## Swift and Kotlin bindings

Bindings are generated automatically via UniFFI. To generate:

```sh
cargo build
cargo run --bin uniffi-bindgen -- generate \
  --library target/debug/libhush_noise.dylib \
  --language swift \
  --out-dir bindings/swift

cargo run --bin uniffi-bindgen -- generate \
  --library target/debug/libhush_noise.dylib \
  --language kotlin \
  --out-dir bindings/kotlin
```

The transport abstraction (`NoiseTransport` callback interface) lets callers supply any I/O implementation from Swift or Kotlin without writing FFI glue by hand.
