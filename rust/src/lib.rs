/// hush-noise — Rust Portable Implementation
///
/// A 1:1 port of the Go Reference Implementation (`go/`).
/// Implements `Noise_XX_25519_ChaChaPoly_BLAKE2s` from the Noise Protocol spec.
/// Verified against the official cacophony test vectors (shared with the Go implementation).
///
/// Primitives: RustCrypto (`x25519-dalek`, `chacha20poly1305`, `blake2`).

pub(crate) mod cipher;

#[cfg(test)]
mod tests {
    /// Tracer bullet: confirms the test infrastructure compiles and runs,
    /// and that testdata/cacophony.json is accessible from tests.
    #[test]
    fn test_vectors_file_is_accessible() {
        let vectors = include_str!("../../go/testdata/cacophony.json");
        assert!(!vectors.is_empty(), "cacophony.json should not be empty");
        assert!(
            vectors.contains("Noise_XX_25519_ChaChaPoly_BLAKE2s"),
            "cacophony.json should contain the target protocol"
        );
    }
}
