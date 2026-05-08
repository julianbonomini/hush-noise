/// hush-noise — Noise_XX_25519_ChaChaPoly_BLAKE2s and Noise_NK_25519_ChaChaPoly_BLAKE2s
///
/// Implements the Noise Protocol Framework using RustCrypto primitives.
/// Verified against the official cacophony test vectors.
///
/// The `ffi` module exposes the public API to Swift and Kotlin via UniFFI.
pub(crate) mod cipher;
pub mod ffi;
pub(crate) mod framing;
pub(crate) mod handshake;
pub mod keypair;
pub(crate) mod session; // SessionInner + RetryConn — shared internals
pub mod session_nk;
pub mod session_xx;
pub(crate) mod symmetric;

#[cfg(test)]
pub(crate) mod test_helpers;

// Re-export all FFI symbols at the crate root so the UniFFI-generated
// scaffolding (which calls crate::generate_keypair, crate::dial, etc.) can
// find them without qualification.
pub use ffi::*;

uniffi::include_scaffolding!("hush_noise");

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use hex;
    use serde::Deserialize;

    use crate::{
        handshake::{HandshakeState, HandshakeStateNk},
        keypair::Keypair,
    };

    /// Tracer bullet: confirms the test infrastructure compiles and runs,
    /// and that testdata/cacophony.json is accessible from tests.
    #[test]
    fn test_vectors_file_is_accessible() {
        let vectors = include_str!("../testdata/cacophony.json");
        assert!(!vectors.is_empty(), "cacophony.json should not be empty");
        assert!(
            vectors.contains("Noise_XX_25519_ChaChaPoly_BLAKE2s"),
            "cacophony.json should contain XX protocol"
        );
        assert!(
            vectors.contains("Noise_NK_25519_ChaChaPoly_BLAKE2s"),
            "cacophony.json should contain NK protocol"
        );
    }

    // ── XX vector structs ──────────────────────────────────────────────────────

    #[derive(Deserialize)]
    struct CacophonyFile {
        vectors: Vec<serde_json::Value>,
    }

    #[derive(Deserialize)]
    struct XxVector {
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
    struct NkVector {
        protocol_name: String,
        init_prologue: String,
        init_ephemeral: String,
        init_remote_static: String,
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
        let raw = include_str!("../testdata/cacophony.json");
        let file: CacophonyFile = serde_json::from_str(raw).expect("parse cacophony.json");
        assert!(
            !file.vectors.is_empty(),
            "cacophony.json contains no vectors"
        );

        for val in &file.vectors {
            if val["protocol_name"] == "Noise_XX_25519_ChaChaPoly_BLAKE2s" {
                let vec: XxVector = serde_json::from_value(val.clone()).expect("parse XX vector");
                run_cacophony_xx_vector(&vec);
            }
        }
    }

    /// TestNkSpecVectors: verifies HandshakeStateNk against the official
    /// cacophony test vectors for Noise_NK_25519_ChaChaPoly_BLAKE2s.
    #[test]
    fn test_nk_spec_vectors() {
        let raw = include_str!("../testdata/cacophony.json");
        let file: CacophonyFile = serde_json::from_str(raw).expect("parse cacophony.json");

        let mut found = false;
        for val in &file.vectors {
            if val["protocol_name"] == "Noise_NK_25519_ChaChaPoly_BLAKE2s" {
                let vec: NkVector = serde_json::from_value(val.clone()).expect("parse NK vector");
                run_cacophony_nk_vector(&vec);
                found = true;
            }
        }
        assert!(
            found,
            "no Noise_NK_25519_ChaChaPoly_BLAKE2s vector found in cacophony.json"
        );
    }

    fn run_cacophony_xx_vector(vec: &XxVector) {
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
        let (mut i_fi, i_fr, i_hash, _) =
            hs_i.write_msg2(&mut msg2, &payload2).expect("write_msg2");
        let (r_fi, mut r_fr, r_hash, _) =
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
        for (idx, msg) in vec.messages[3..].iter().enumerate() {
            let payload = hex::decode(&msg.payload).unwrap();
            let want_ct = hex::decode(&msg.ciphertext).unwrap();

            let got_ct = if idx % 2 == 0 {
                i_fi.encrypt(&[], &payload)
            } else {
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

        let _ = (i_fr, r_fi);
    }

    fn run_cacophony_nk_vector(vec: &NkVector) {
        let init_ephemeral = keypair_from_priv_hex(&vec.init_ephemeral);
        let resp_static = keypair_from_priv_hex(&vec.resp_static);
        let resp_ephemeral = keypair_from_priv_hex(&vec.resp_ephemeral);
        let prologue = hex::decode(&vec.init_prologue).expect("decode prologue");

        // The initiator knows the responder's static public key (init_remote_static).
        // Verify it matches resp_static's derived public key.
        let init_remote_static_bytes =
            hex::decode(&vec.init_remote_static).expect("decode init_remote_static");
        let mut init_rs = [0u8; 32];
        init_rs.copy_from_slice(&init_remote_static_bytes);

        // Use a dummy local static for the initiator — NK does not authenticate the initiator.
        use crate::keypair::generate_keypair;
        let init_static = generate_keypair();

        let payload0 = hex::decode(&vec.messages[0].payload).unwrap();
        let payload1 = hex::decode(&vec.messages[1].payload).unwrap();

        // ── Initiator: write msg0 (-> e, es [payload]) ─────────────────────────
        let mut hs_i =
            HandshakeStateNk::new_fixed(init_static, init_ephemeral, Some(init_rs), &prologue);
        let mut msg0 = Vec::new();
        hs_i.write_msg0_raw(&mut msg0, &payload0);

        let want_ct0 = hex::decode(&vec.messages[0].ciphertext).unwrap();
        assert_eq!(
            msg0, want_ct0,
            "[{}] msg0 ciphertext mismatch",
            vec.protocol_name
        );

        // ── Responder: read msg0, write msg1 (<- e, ee [payload]) ──────────────
        let mut hs_r = HandshakeStateNk::new_fixed(
            Keypair::new(resp_static.private(), resp_static.public_key),
            resp_ephemeral,
            None,
            &prologue,
        );
        hs_r.read_msg0_raw(&msg0).expect("responder read_msg0_raw");

        let mut msg1 = Vec::new();
        hs_r.write_msg1_raw(&mut msg1, &payload1);

        let want_ct1 = hex::decode(&vec.messages[1].ciphertext).unwrap();
        assert_eq!(
            msg1, want_ct1,
            "[{}] msg1 ciphertext mismatch",
            vec.protocol_name
        );

        // ── Both sides derive cipher states ────────────────────────────────────
        let (i_fi, mut i_fr, i_hash) = hs_i.read_msg1_raw(&msg1).expect("initiator read_msg1_raw");
        let (mut r_fi, r_fr, r_hash) = hs_r.split_responder();

        // Assert handshake hash matches.
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

        // Post-handshake messages (msg[2..]):
        // NK ends with the responder's message, so per Noise spec §7.3:
        //   initiator sends on c2 = split()[1] = i_fr
        //   responder sends on c1 = split()[0] = r_fi
        // even index → initiator sends (i_fr)
        // odd index  → responder sends (r_fi)
        for (idx, msg) in vec.messages[2..].iter().enumerate() {
            let payload = hex::decode(&msg.payload).unwrap();
            let want_ct = hex::decode(&msg.ciphertext).unwrap();

            let got_ct = if idx % 2 == 0 {
                i_fr.encrypt(&[], &payload)
            } else {
                r_fi.encrypt(&[], &payload)
            };

            assert_eq!(
                got_ct,
                want_ct,
                "[{}] message[{}] ciphertext mismatch",
                vec.protocol_name,
                idx + 2
            );
        }

        let _ = (i_fi, r_fr);
    }
}
