# Noise_NK support via separate session_nk module; SessionNk has no remote_public_key

We added Noise_NK_25519_ChaChaPoly_BLAKE2s as a second supported pattern alongside Noise_XX.

**Why a separate module, not a generic Session.** The two patterns have different post-handshake surfaces: XX authenticates both peers so the responder can call `remote_public_key()` to obtain the initiator's static key; NK does not — the initiator's identity is intentionally hidden. Representing this with an `Option<[u8; 32]>` or a trait method that panics on NK would push an invariant into caller code and bury the distinction in runtime behaviour. Instead, `session_xx::Session` and `session_nk::Session` are distinct types. The absence of `remote_public_key()` on `SessionNk` is enforced at compile time, which is the earliest possible point.

**Why not a trait with pattern-specific methods.** A shared `Session` trait with `remote_public_key()` would either force `SessionNk` to implement it (wrong) or omit it from the trait and require a downcast (unsafe, unhelpful). The duplication of `send`, `receive`, and `close` across two concrete types is minimal; both delegate to the shared `SessionInner<T>` in `session.rs`, so there is no logic duplication.

**FFI surface.** The split is reflected in the UDL: `SessionXx` and `SessionNk` are distinct `interface` types. `SessionXx` declares `remote_public_key()`; `SessionNk` does not. This means Swift and Kotlin callers also get a compile-time guarantee — the type system, not documentation, communicates the capability difference.

**dial_nk takes remote_static explicitly.** The NK initiator must know the responder's static public key before dialing; it is not negotiated. Passing it as an explicit `[u8; 32]` argument (not a config struct, not a builder) makes the dependency visible at the call site and keeps the API consistent with `dial_xx`, which takes a keypair rather than any out-of-band state.
