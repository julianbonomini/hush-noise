use blake2::{digest::Update, Blake2s256, Digest};

use crate::cipher::CipherState;

/// SymmetricState implements the Noise SymmetricState object.
/// Maintains the chaining key (ck), handshake hash (h), and an
/// embedded CipherState for encrypting/decrypting handshake payloads.
pub(crate) struct SymmetricState {
    pub(crate) ck: [u8; 32],
    pub(crate) h: [u8; 32],
    cs: Option<CipherState>,
}

impl SymmetricState {
    /// Initialises a SymmetricState with the protocol name.
    /// Per spec §5.2: if len(name) <= 32, h = name zero-padded; else h = HASH(name).
    pub(crate) fn new(protocol_name: &str) -> Self {
        let name = protocol_name.as_bytes();
        let mut h = [0u8; 32];
        if name.len() <= 32 {
            h[..name.len()].copy_from_slice(name);
        } else {
            h = blake2s256(name);
        }
        Self { ck: h, h, cs: None }
    }

    /// Updates the chaining key and initialises a new CipherState.
    /// Per spec §5.2 MixKey.
    pub(crate) fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck.copy_from_slice(&ck);
        let mut key = [0u8; 32];
        key.copy_from_slice(&k);
        self.cs = Some(CipherState::new(key));
    }

    /// Updates the handshake hash.
    /// Per spec §5.2 MixHash: h = HASH(h || data).
    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(32 + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = blake2s256(&buf);
    }

    /// Encrypts plaintext (or passes through if no key yet),
    /// mixes ciphertext into h, and returns the ciphertext.
    pub(crate) fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = if let Some(cs) = self.cs.as_mut() {
            cs.encrypt(&self.h, plaintext)
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        ciphertext
    }

    /// Decrypts ciphertext (or passes through if no key yet),
    /// mixes ciphertext into h, and returns the plaintext.
    pub(crate) fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let plaintext = if let Some(cs) = self.cs.as_mut() {
            cs.decrypt(&self.h, ciphertext)
                .map_err(|e| format!("noise: SymmetricState decrypt: {}", e))?
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Returns two CipherStates for post-handshake transport.
    /// fromInitiator carries initiator→responder traffic.
    /// fromResponder carries responder→initiator traffic.
    /// Per spec §5.2 Split.
    pub(crate) fn split(self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        let mut k1key = [0u8; 32];
        let mut k2key = [0u8; 32];
        k1key.copy_from_slice(&k1);
        k2key.copy_from_slice(&k2);
        // k2 → fromInitiator, k1 → fromResponder (matches Go reference implementation)
        (CipherState::new(k2key), CipherState::new(k1key))
    }
}

/// Returns the BLAKE2s-256 hash of data.
pub(crate) fn blake2s256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Update::update(&mut hasher, data);
    hasher.finalize().into()
}

/// Derives two 32-byte output keys from a chaining key and input key material.
/// Per Noise Protocol spec §4:
///   temp_key = HMAC-BLAKE2s(ck, ikm)
///   output1  = HMAC-BLAKE2s(temp_key, 0x01)
///   output2  = HMAC-BLAKE2s(temp_key, output1 || 0x02)
pub(crate) fn hkdf2(ck: &[u8], ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let temp_key = hmac_blake2s(ck, ikm);
    let out1 = hmac_blake2s(&temp_key, &[0x01]);
    let mut out2_input = out1.clone();
    out2_input.push(0x02);
    let out2 = hmac_blake2s(&temp_key, &out2_input);
    (out1, out2)
}

/// Computes HMAC-BLAKE2s-256(key, data) per RFC 2104.
/// BLAKE2s block size is 64 bytes.
pub(crate) fn hmac_blake2s(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;

    let mut k = key.to_vec();
    if k.len() > BLOCK_SIZE {
        k = blake2s256(&k).to_vec();
    }
    k.resize(BLOCK_SIZE, 0);

    let mut ipad = vec![0u8; BLOCK_SIZE + data.len()];
    let mut opad = vec![0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    ipad[BLOCK_SIZE..].copy_from_slice(data);

    let inner = blake2s256(&ipad);
    let mut outer_input = opad;
    outer_input.extend_from_slice(&inner);
    blake2s256(&outer_input).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: encrypt_and_hash followed by decrypt_and_hash recovers plaintext.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let mut enc = SymmetricState::new("Noise_XX_25519_ChaChaPoly_BLAKE2s");
        let mut dec = SymmetricState::new("Noise_XX_25519_ChaChaPoly_BLAKE2s");

        // Both sides must mix the same key to have a CipherState.
        let ikm = [42u8; 32];
        enc.mix_key(&ikm);
        dec.mix_key(&ikm);

        let plaintext = b"hello symmetric";
        let ct = enc.encrypt_and_hash(plaintext);
        // mix_hash must have been called on enc; do the same on dec manually.
        // But encrypt_and_hash already calls mix_hash internally — dec.decrypt_and_hash
        // calls mix_hash with the ciphertext too, keeping them in sync.
        let recovered = dec.decrypt_and_hash(&ct).expect("decrypt should succeed");
        assert_eq!(recovered, plaintext);
    }

    /// Before any mix_key, encrypt_and_hash is a pass-through.
    #[test]
    fn encrypt_and_hash_passthrough_before_key() {
        let mut ss = SymmetricState::new("Noise_XX_25519_ChaChaPoly_BLAKE2s");
        let data = b"plaintext";
        let out = ss.encrypt_and_hash(data);
        assert_eq!(out, data, "no key yet — should pass through unchanged");
    }

    /// split() produces two different CipherStates (different keys).
    #[test]
    fn split_produces_two_cipher_states() {
        let mut ss = SymmetricState::new("Noise_XX_25519_ChaChaPoly_BLAKE2s");
        ss.mix_key(&[1u8; 32]);
        let (mut fi, mut fr) = ss.split();
        // Encrypting the same plaintext with different keys produces different ciphertext.
        let ct_i = fi.encrypt(b"", b"test");
        let ct_r = fr.encrypt(b"", b"test");
        assert_ne!(
            ct_i, ct_r,
            "fromInitiator and fromResponder should have different keys"
        );
    }

    /// HMAC-BLAKE2s is not native keyed BLAKE2s — verify with a known test.
    /// HMAC(key=0x0b*20, data="Hi There") from RFC 2104 adapted to BLAKE2s.
    /// We verify self-consistency: hmac_blake2s output changes when key changes.
    #[test]
    fn hmac_blake2s_is_key_dependent() {
        let data = b"test data";
        let out1 = hmac_blake2s(&[0x01u8; 32], data);
        let out2 = hmac_blake2s(&[0x02u8; 32], data);
        assert_ne!(
            out1, out2,
            "different keys must produce different HMAC outputs"
        );
    }

    /// hkdf2 produces two distinct outputs.
    #[test]
    fn hkdf2_produces_two_distinct_outputs() {
        let (out1, out2) = hkdf2(&[0u8; 32], &[0u8; 32]);
        assert_ne!(out1, out2, "hkdf2 outputs must be distinct");
        assert_eq!(out1.len(), 32);
        assert_eq!(out2.len(), 32);
    }
}
