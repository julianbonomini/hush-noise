use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

pub(crate) const MAX_MESSAGE_SIZE: usize = 65535;
pub(crate) const TAG_SIZE: usize = 16;

/// CipherState implements the Noise CipherState object.
/// Wraps ChaCha20-Poly1305 and tracks the nonce counter.
/// Invariant: nonce must never overflow — overflow panics.
pub(crate) struct CipherState {
    k: [u8; 32],
    n: u64,
}

impl CipherState {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { k: key, n: 0 }
    }

    /// Encrypts plaintext with additional data, returning ciphertext+tag.
    pub(crate) fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        if self.n == u64::MAX {
            panic!("noise: CipherState nonce overflow");
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nonce = Self::make_nonce(self.n);
        self.n += 1;
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .expect("noise: ChaCha20Poly1305 encrypt failed")
    }

    /// Decrypts ciphertext with additional data, returning plaintext.
    /// Returns an error if authentication fails (Expected Failure).
    pub(crate) fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if self.n == u64::MAX {
            panic!("noise: CipherState nonce overflow");
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nonce = Self::make_nonce(self.n);
        self.n += 1;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| "noise: decrypt failed: authentication error".to_string())
    }

    /// Encodes n as a 12-byte little-endian nonce (per Noise spec §4).
    /// Bytes 0–3 are zero; bytes 4–11 are the counter in little-endian order.
    fn make_nonce(n: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        Nonce::from(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: encrypt then decrypt recovers the original plaintext.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0u8; 32];
        let mut cs = CipherState::new(key);
        let plaintext = b"hello noise";
        let ad = b"additional data";

        let ciphertext = cs.encrypt(ad, plaintext);

        let mut cs2 = CipherState::new(key);
        let recovered = cs2
            .decrypt(ad, &ciphertext)
            .expect("decrypt should succeed");

        assert_eq!(recovered, plaintext);
    }

    /// Wrong AD causes decryption to fail.
    #[test]
    fn decrypt_with_wrong_ad_fails() {
        let key = [1u8; 32];
        let mut cs_enc = CipherState::new(key);
        let ciphertext = cs_enc.encrypt(b"correct ad", b"secret");

        let mut cs_dec = CipherState::new(key);
        let result = cs_dec.decrypt(b"wrong ad", &ciphertext);
        assert!(result.is_err(), "decrypt with wrong AD should fail");
    }

    /// Nonce increments: two encryptions with the same key produce different ciphertexts.
    #[test]
    fn nonce_increments_between_encryptions() {
        let key = [2u8; 32];
        let mut cs = CipherState::new(key);
        let ct1 = cs.encrypt(b"", b"same plaintext");
        let ct2 = cs.encrypt(b"", b"same plaintext");
        assert_ne!(
            ct1, ct2,
            "successive encryptions should produce different ciphertexts"
        );
    }

    /// Nonce encoding: bytes 0-3 are zero, bytes 4-11 are the counter little-endian.
    #[test]
    fn nonce_encoding_matches_noise_spec() {
        let nonce = CipherState::make_nonce(1);
        let bytes = nonce.as_slice();
        assert_eq!(&bytes[0..4], &[0u8; 4], "first 4 bytes must be zero");
        assert_eq!(
            &bytes[4..12],
            &1u64.to_le_bytes(),
            "bytes 4-11 are counter LE"
        );
    }
}
