use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Keypair is a static X25519 public/private key pair representing a peer's
/// long-term identity. Generated and stored by the caller; passed into dial
/// and accept. The library never generates or persists keypairs.
///
/// `public_key` is public — safe to share. The private key is accessible
/// only via `private()` to reduce accidental exposure.
pub(crate) struct Keypair {
    private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Keypair {
    /// Constructs a Keypair from raw private and public key bytes.
    /// Use this when restoring a previously serialised keypair.
    pub(crate) fn new(priv_key: [u8; 32], pub_key: [u8; 32]) -> Self {
        Self {
            private_key: priv_key,
            public_key: pub_key,
        }
    }

    /// Returns the raw private key bytes.
    /// Handle with care — sensitive key material.
    pub(crate) fn private(&self) -> [u8; 32] {
        self.private_key
    }
}

/// Generates a fresh X25519 Keypair from a cryptographically secure random source.
/// Applies RFC 7748 clamping. Callers are responsible for persisting the result.
pub(crate) fn generate_keypair() -> Keypair {
    let mut priv_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut priv_bytes);

    // RFC 7748 clamping — matches the Go reference implementation exactly.
    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;

    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    Keypair {
        private_key: priv_bytes,
        public_key: *public.as_bytes(),
    }
}

/// Performs X25519 Diffie-Hellman: DH(private_key, public_key).
pub(crate) fn dh(priv_key: [u8; 32], pub_key: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(priv_key);
    let public = PublicKey::from(pub_key);
    *secret.diffie_hellman(&public).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: generate_keypair returns a non-zero public key.
    #[test]
    fn generate_keypair_produces_valid_keys() {
        let kp = generate_keypair();
        assert_ne!(
            kp.public_key, [0u8; 32],
            "public key should not be all-zero"
        );
        assert_ne!(
            kp.private_key, [0u8; 32],
            "private key should not be all-zero"
        );
    }

    /// RFC 7748 clamping is applied: specific bits of the private key are set/cleared.
    #[test]
    fn generated_private_key_is_clamped() {
        let kp = generate_keypair();
        let priv_key = kp.private();
        assert_eq!(priv_key[0] & 7, 0, "low 3 bits of byte 0 must be 0");
        assert_eq!(priv_key[31] & 128, 0, "high bit of byte 31 must be 0");
        assert_eq!(
            priv_key[31] & 64,
            64,
            "second-high bit of byte 31 must be 1"
        );
    }

    /// new_keypair restores a keypair from raw bytes: private() returns the stored private key.
    #[test]
    fn new_keypair_restores_from_bytes() {
        let kp = generate_keypair();
        let priv_bytes = kp.private();
        let pub_bytes = kp.public_key;

        let restored = Keypair::new(priv_bytes, pub_bytes);
        assert_eq!(restored.private(), priv_bytes);
        assert_eq!(restored.public_key, pub_bytes);
    }

    /// DH is commutative: DH(a_priv, b_pub) == DH(b_priv, a_pub).
    #[test]
    fn dh_is_commutative() {
        let a = generate_keypair();
        let b = generate_keypair();

        let shared_ab = dh(a.private(), b.public_key);
        let shared_ba = dh(b.private(), a.public_key);

        assert_eq!(shared_ab, shared_ba, "DH should be commutative");
    }
}
