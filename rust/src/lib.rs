/// hush-noise — Rust Portable Implementation
///
/// A 1:1 port of the Go Reference Implementation (`go/`).
/// Implements `Noise_XX_25519_ChaChaPoly_BLAKE2s` from the Noise Protocol spec.
/// Verified against the official cacophony test vectors (shared with the Go implementation).
///
/// Primitives: RustCrypto (`x25519-dalek`, `chacha20poly1305`, `blake2`).
pub(crate) mod cipher;
pub(crate) mod framing;
pub(crate) mod handshake;
pub(crate) mod keypair;
pub(crate) mod symmetric;

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex;
    use serde::Deserialize;

    use crate::{handshake::HandshakeState, keypair::Keypair};

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

    #[derive(Deserialize)]
    struct CacophonyFile {
        vectors: Vec<CacophonyVector>,
    }

    #[derive(Deserialize)]
    struct CacophonyVector {
        protocol_name: String,
        init_prologue: String,
        init_static: String,
        init_ephemeral: String,
        resp_static: String,
        resp_ephemeral: String,
        handshake_hash: String,
        messages: Vec<Message>,
    }

    #[derive(Deserialize)]
    struct Message {
        payload: String,
        ciphertext: String,
    }

    fn keypair_from_priv_hex(priv_hex: &str) -> Keypair {
        let priv_bytes = hex::decode(priv_hex).expect("hex decode private key");
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(&priv_bytes);

        // Derive public key via X25519 basepoint multiplication — mirrors Go reference.
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(priv_arr);
        let public = PublicKey::from(&secret);
        Keypair::new(priv_arr, *public.as_bytes())
    }

    /// TestSpecVectors: verifies the Rust Portable Implementation against the official
    /// cacophony test vectors for Noise_XX_25519_ChaChaPoly_BLAKE2s.
    /// Passing these vectors proves spec-compliance, not just self-consistency.
    #[test]
    fn test_spec_vectors() {
        let raw = include_str!("../../go/testdata/cacophony.json");
        let file: CacophonyFile = serde_json::from_str(raw).expect("parse cacophony.json");
        assert!(
            !file.vectors.is_empty(),
            "cacophony.json contains no vectors"
        );

        for vec in &file.vectors {
            run_cacophony_vector(vec);
        }
    }

    fn run_cacophony_vector(vec: &CacophonyVector) {
        let init_static = keypair_from_priv_hex(&vec.init_static);
        let init_ephemeral = keypair_from_priv_hex(&vec.init_ephemeral);
        let resp_static = keypair_from_priv_hex(&vec.resp_static);
        let resp_ephemeral = keypair_from_priv_hex(&vec.resp_ephemeral);
        let prologue = hex::decode(&vec.init_prologue).expect("decode prologue");

        let payload0 = hex::decode(&vec.messages[0].payload).unwrap();
        let payload1 = hex::decode(&vec.messages[1].payload).unwrap();
        let payload2 = hex::decode(&vec.messages[2].payload).unwrap();

        // --- Initiator side ---
        let mut hs_i = HandshakeState::new_fixed(init_static, init_ephemeral, &prologue);

        // msg0: -> e
        let mut msg0 = Vec::new();
        hs_i.write_msg0(&mut msg0, &payload0).expect("write_msg0");

        // --- Responder side ---
        let mut hs_r = HandshakeState::new_fixed(resp_static, resp_ephemeral, &prologue);
        hs_r.read_msg0(&mut Cursor::new(&msg0)).expect("read_msg0");

        // msg1: <- e, ee, s, es
        let mut msg1 = Vec::new();
        hs_r.write_msg1(&mut msg1, &payload1).expect("write_msg1");
        hs_i.read_msg1(&mut Cursor::new(&msg1)).expect("read_msg1");

        // msg2: -> s, se
        let mut msg2 = Vec::new();
        let (mut i_fi, mut i_fr, i_hash) =
            hs_i.write_msg2(&mut msg2, &payload2).expect("write_msg2");
        let (mut r_fi, mut r_fr, r_hash) =
            hs_r.read_msg2(&mut Cursor::new(&msg2)).expect("read_msg2");

        // Assert handshake hash matches for both sides.
        let want_hash = hex::decode(&vec.handshake_hash).expect("decode handshake_hash");
        assert_eq!(
            i_hash.as_ref(),
            want_hash.as_slice(),
            "[{}] initiator handshake_hash mismatch",
            vec.protocol_name
        );
        assert_eq!(
            r_hash.as_ref(),
            want_hash.as_slice(),
            "[{}] responder handshake_hash mismatch",
            vec.protocol_name
        );

        // Post-handshake messages:
        // msg[3]: initiator→responder (initiator sends on fromInitiator)
        // msg[4]: responder→initiator (responder sends on fromResponder)
        // msg[5]: initiator→responder (initiator sends on fromInitiator)
        for (idx, msg) in vec.messages[3..].iter().enumerate() {
            let payload = hex::decode(&msg.payload).unwrap();
            let want_ct = hex::decode(&msg.ciphertext).unwrap();

            let got_ct = if idx % 2 == 0 {
                // even: initiator sends on fromInitiator
                i_fi.encrypt(&[], &payload)
            } else {
                // odd: responder sends on fromResponder
                r_fr.encrypt(&[], &payload)
            };

            assert_eq!(
                got_ct,
                want_ct,
                "[{}] message[{}] ciphertext mismatch",
                vec.protocol_name,
                idx + 3
            );
        }

        // Suppress unused warnings
        let _ = (i_fr, r_fi);
    }
}
