# High-level Dial/Accept API, not a raw state machine

The library exposes a `Dial` / `Accept` interface that owns the handshake internally and returns an opaque `Session`. The low-level alternative — exposing `HandshakeState` and `CipherState` directly — gives callers maximum control but makes misuse trivially easy (sending before the handshake completes, skipping steps). Since the purpose of this library is to be a safe, reusable primitive for other trueseal components, a misuse-resistant API is non-negotiable. Complexity lives inside the library; the call site stays simple.
