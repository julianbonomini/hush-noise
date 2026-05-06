# hush-noise

A Go implementation of the Noise Protocol Framework — a reusable encrypted transport primitive. Written in Go for simplicity and portability. Module path: `github.com/julianbonomini/hush-noise`. Single `noise` package at the root. Implemented from scratch against the Noise spec; `golang.org/x/crypto` provides the raw primitives (X25519, ChaCha20-Poly1305, BLAKE2s) but the Noise state machine is not delegated to a third-party library. It is not an application; it is the engine that other hush components pull in to establish secure, authenticated channels between peers.

## Language

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
A runtime error the caller should handle: I/O errors, malformed handshake messages, connection drops. Returned as a plain `error` from `Dial`, `Accept`, `Send`, or `Receive`. Recoverable — the caller may retry or surface to the user.
_Avoid_: error, exception

**Invariant Violation**:
A condition that should be impossible given correct library code: e.g. sending before the handshake completes, a nonce counter overflow. Indicates a bug, not a runtime condition. The library panics — crashing loudly is safer than silently continuing with broken crypto.
_Avoid_: internal error, fatal error

**Session**:
A fully negotiated, bidirectional encrypted channel between two peers, produced by completing a Handshake Pattern. Exposes `Send`, `Receive`, `RemotePublicKey`, and `Close`. Concurrent-safe: `Send` and `Receive` hold independent locks (Noise uses separate cipher states per direction), so callers may use them from different goroutines freely. Sessions are not resumable — if the transport dies, the session is dead and the caller must establish a new one with a fresh handshake. The library guarantees the cryptographic identity of the remote peer; trust policy (whether to accept that identity) is the caller's responsibility.
_Avoid_: connection, tunnel, pipe

**Initiator**:
The peer that calls `Dial(ctx, conn, keypair)` — sends the first handshake message.
_Avoid_: client, sender, caller

**Responder**:
The peer that calls `Accept(ctx, conn, keypair)` — receives the first handshake message.
_Avoid_: server, receiver, listener

**Test Vectors**:
The official Noise Protocol test vectors (published as JSON at noiseprotocol.org) used to verify correctness of the state machine implementation. Passing the vectors for `Noise_XX_25519_ChaChaPoly_BLAKE2s` is the correctness baseline — they prove spec-compliance, not just self-consistency. Unit tests cover the public API (`Dial`/`Accept`, `Send`/`Receive` round-trips) separately.
_Avoid_: golden tests, snapshot tests

## Relationships

- A **Handshake Pattern** is executed between an **Initiator** and a **Responder** to produce a **Session**

## Flagged ambiguities

_(none yet)_
