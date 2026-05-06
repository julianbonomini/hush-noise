# Go is the reference implementation; Rust port planned for platform portability

The Go implementation of hush-noise is the reference: written first, spec-compliant against official test vectors, and used by hush-relay (a Go server binary that is never ported).

A Rust port is planned to serve as the canonical portable implementation for the hush client stack. The driver is hush-sync: the client library must run on iOS, Android, macOS, and Linux. Go cannot compile to iOS (CGo is prohibited on iOS, and Go's runtime requires dynamic linking which Apple's App Store disallows). Rust compiles to all target platforms as a static library and supports automatic Swift and Kotlin binding generation via UniFFI (Mozilla's cross-language binding tool).

The Rust port implements the same spec (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), verified against the same official test vectors. Correctness is language-agnostic — the test vectors are the contract. Raw primitives come from `ring` or `RustCrypto` (X25519, ChaCha20-Poly1305, BLAKE2s), mirroring the Go implementation's use of `golang.org/x/crypto`.

The Go implementation is not deprecated — it remains the reference and powers hush-relay indefinitely.
