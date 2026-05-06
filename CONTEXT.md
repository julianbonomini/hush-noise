# hush-noise

A Rust implementation of the Noise Protocol Framework — a reusable encrypted transport primitive. The Rust crate is the canonical portable implementation: it compiles to every platform (iOS, Android, macOS, Linux, WASM) and enables Swift/Kotlin bindings via UniFFI. It implements `Noise_XX_25519_ChaChaPoly_BLAKE2s`, verified against the official cacophony test vectors. The Rust crate is named `hush-noise` (not yet published to crates.io).

## Language

**Portable Implementation**:
The Rust crate (`rust/`). Compiles to iOS, Android, macOS, Linux, and WASM as a static library. Exposes Swift and Kotlin bindings via UniFFI. Verified against the official Test Vectors for `Noise_XX_25519_ChaChaPoly_BLAKE2s`.
_Avoid_: mobile implementation, cross-platform version

**UniFFI**:
Mozilla's cross-language binding tool for Rust. Generates Swift and Kotlin bindings from the Rust crate automatically, enabling the Portable Implementation to be consumed natively in iOS and Android apps without hand-written FFI glue.
_Avoid_: bindings generator, FFI layer

**Cipher Suite**:
The combination of cryptographic primitives backing the handshake: X25519 for Diffie-Hellman, ChaCha20-Poly1305 for symmetric encryption, and BLAKE2s for hashing (`Noise_XX_25519_ChaChaPoly_BLAKE2s`). ChaCha20-Poly1305 is chosen for constant-time software execution — no timing side-channels without hardware AES acceleration.
_Avoid_: algorithm, crypto params

**Handshake Pattern**:
A named sequence of Diffie-Hellman and message steps that determines the security properties of a session — who authenticates whom, and when. This library implements the `XX` pattern exclusively: no pre-shared knowledge required, both peers end up mutually authenticated.
_Avoid_: pattern, mode, variant

**Keypair**:
A static X25519 public/private key pair representing a peer's long-term identity. Generated and stored by the caller (e.g. `hush-sync`); passed into the library at dial/accept time. The library never generates or persists keypairs.
_Avoid_: identity, credentials, keys

**Framing**:
A 2-byte big-endian length prefix prepended to every encrypted message by the library. Required because Noise encryption is per-message — without framing, a stream receiver cannot determine message boundaries and cannot decrypt. The caller never sees framing; it is an internal concern of the library. Maximum message size is 65535 bytes (the Noise spec hard cap); chunking larger payloads is the caller's responsibility.
_Avoid_: length-prefix, header, envelope

**Expected Failure**:
A runtime error the caller should handle: I/O errors, malformed handshake messages, connection drops. Returned as `Result<_, String>` from `dial`, `accept`, `send`, or `receive`. Recoverable — the caller may retry or surface to the user.
_Avoid_: error, exception

**Invariant Violation**:
A condition that should be impossible given correct library code: e.g. sending before the handshake completes, a nonce counter overflow. Indicates a bug, not a runtime condition. The library panics — crashing loudly is safer than silently continuing with broken crypto.
_Avoid_: internal error, fatal error

**Session**:
A fully negotiated, bidirectional encrypted channel between two peers, produced by completing a Handshake Pattern. Exposes `send`, `receive`, `remote_public_key`, and `close`. Concurrent-safe: `send` and `receive` use independent locks (Noise uses separate cipher states per direction), so callers may use them from different threads freely. Sessions are not resumable — if the transport dies, the session is dead and the caller must establish a new one with a fresh handshake. The library guarantees the cryptographic identity of the remote peer; trust policy (whether to accept that identity) is the caller's responsibility.
_Avoid_: connection, tunnel, pipe

**Initiator**:
The peer that calls `dial(conn, keypair)` — sends the first handshake message.
_Avoid_: client, sender, caller

**Responder**:
The peer that calls `accept(conn, keypair)` — receives the first handshake message.
_Avoid_: server, receiver, listener

**Test Vectors**:
The official Noise Protocol test vectors (published as JSON at noiseprotocol.org) used to verify correctness of the state machine implementation. Passing the vectors for `Noise_XX_25519_ChaChaPoly_BLAKE2s` is the correctness baseline — they prove spec-compliance, not just self-consistency. Unit tests cover the public API (`Dial`/`Accept`, `Send`/`Receive` round-trips) separately.
_Avoid_: golden tests, snapshot tests

## Relationships

- A **Handshake Pattern** is executed between an **Initiator** and a **Responder** to produce a **Session**

## Flagged ambiguities

_(none yet)_
