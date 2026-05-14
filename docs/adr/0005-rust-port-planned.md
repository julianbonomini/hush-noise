# Go is the reference implementation; Rust port planned for platform portability

The Go implementation of trueseal-noise is the reference: written first, spec-compliant against official test vectors, and used by trueseal-relay (a Go server binary that is never ported).

A Rust port is planned to serve as the canonical portable implementation for the trueseal client stack. The driver is trueseal-sync: the client library must run on iOS, Android, macOS, and Linux. Go cannot compile to iOS (CGo is prohibited on iOS, and Go's runtime requires dynamic linking which Apple's App Store disallows). Rust compiles to all target platforms as a static library and supports automatic Swift and Kotlin binding generation via UniFFI (Mozilla's cross-language binding tool).

The Rust port implements the same spec (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), verified against the same official test vectors. Correctness is language-agnostic — the test vectors are the contract. Raw primitives come from the RustCrypto family (`x25519-dalek`, `chacha20poly1305`, `blake2`), mirroring the Go implementation's use of `golang.org/x/crypto`. RustCrypto is chosen over `ring` for pure-Rust cross-compilation: no C toolchain dependency, no `cmake`/`nasm` requirement, and reliable compilation to all target platforms (iOS, Android, WASM).

## Repository layout

Both implementations live in the same repo, structured as:

```
go/     ← Go reference implementation; module path github.com/julianbonomini/trueseal-noise/go
rust/   ← Rust portable implementation; crate name trueseal-noise (crates.io)
```

`testdata/cacophony.json` (the official test vectors) is the shared correctness contract. Both implementations reference it. Co-location is intentional — keeping the vectors in one place eliminates drift. The repo can be split into two independent repos later without breaking either implementation.

The Go module path is `github.com/julianbonomini/trueseal-noise/go`. The rename from the original root-level path happens while there are zero external consumers — the only moment this costs nothing.

The Rust crate is named `trueseal-noise` in `Cargo.toml` but is not published to crates.io until the implementation is complete and the project is open-sourced. The name is available and will be claimed on first publish.

The Go implementation is not deprecated — it remains the reference and powers trueseal-relay indefinitely.
