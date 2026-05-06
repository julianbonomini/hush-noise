use std::io::{Read, Write};

use crate::{
    cipher::{CipherState, TAG_SIZE},
    framing::{read_frame, write_frame},
    keypair::{dh, generate_keypair, Keypair},
    symmetric::SymmetricState,
};

const PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// HandshakeState implements the Noise XX handshake pattern:
///
///   msg0: -> e
///   msg1: <- e, ee, s, es
///   msg2: -> s, se
///
/// The Initiator writes msg0, reads msg1, writes msg2.
/// The Responder reads msg0, writes msg1, reads msg2.
pub(crate) struct HandshakeState {
    pub(crate) ss: SymmetricState,
    s: Keypair,   // local static keypair
    e: Keypair,   // local ephemeral keypair
    rs: [u8; 32], // remote static public key
    re: [u8; 32], // remote ephemeral public key
}

impl HandshakeState {
    /// Production constructor — generates a fresh ephemeral keypair.
    pub(crate) fn new(s: Keypair) -> Self {
        let e = generate_keypair();
        Self::new_fixed(s, e, &[])
    }

    /// Deterministic constructor for spec vector tests — accepts fixed keys and prologue.
    pub(crate) fn new_fixed(s: Keypair, e: Keypair, prologue: &[u8]) -> Self {
        let mut ss = SymmetricState::new(PROTOCOL_NAME);
        ss.mix_hash(prologue);
        Self {
            ss,
            s,
            e,
            rs: [0u8; 32],
            re: [0u8; 32],
        }
    }

    /// Sends: -> e [payload]
    pub(crate) fn write_msg0(&mut self, w: &mut dyn Write, payload: &[u8]) -> std::io::Result<()> {
        self.ss.mix_hash(&self.e.public_key);
        let enc_payload = self.ss.encrypt_and_hash(payload);
        let mut msg = self.e.public_key.to_vec();
        msg.extend_from_slice(&enc_payload);
        write_frame(w, &msg)
    }

    /// Receives: -> e [payload]
    pub(crate) fn read_msg0(&mut self, r: &mut dyn Read) -> Result<(), String> {
        let msg = read_frame(r).map_err(|e| format!("noise: read msg0: {}", e))?;
        if msg.len() < 32 {
            return Err(format!("noise: msg0 too short: got {} bytes", msg.len()));
        }
        self.re.copy_from_slice(&msg[..32]);
        self.ss.mix_hash(&self.re.clone());
        self.ss
            .decrypt_and_hash(&msg[32..])
            .map_err(|e| format!("noise: msg0 payload: {}", e))?;
        Ok(())
    }

    /// Sends: <- e, ee, s, es [payload]
    pub(crate) fn write_msg1(&mut self, w: &mut dyn Write, payload: &[u8]) -> Result<(), String> {
        self.ss.mix_hash(&self.e.public_key);

        let ee_dh = dh(self.e.private(), self.re);
        self.ss.mix_key(&ee_dh);

        let enc_s = self.ss.encrypt_and_hash(&self.s.public_key);

        // es: responder's static × initiator's ephemeral
        let es_dh = dh(self.s.private(), self.re);
        self.ss.mix_key(&es_dh);

        let enc_payload = self.ss.encrypt_and_hash(payload);

        let mut msg = self.e.public_key.to_vec();
        msg.extend_from_slice(&enc_s);
        msg.extend_from_slice(&enc_payload);

        write_frame(w, &msg).map_err(|e| format!("noise: write msg1: {}", e))
    }

    /// Receives: <- e, ee, s, es [payload]
    pub(crate) fn read_msg1(&mut self, r: &mut dyn Read) -> Result<(), String> {
        let msg = read_frame(r).map_err(|e| format!("noise: read msg1: {}", e))?;
        if msg.len() < 32 {
            return Err("noise: msg1 too short".to_string());
        }

        self.re.copy_from_slice(&msg[..32]);
        self.ss.mix_hash(&self.re.clone());
        let msg = &msg[32..];

        // ee: initiator's ephemeral × responder's ephemeral
        let ee_dh = dh(self.e.private(), self.re);
        self.ss.mix_key(&ee_dh);

        // s: 32 bytes plaintext + 16 bytes tag
        if msg.len() < 32 + TAG_SIZE {
            return Err("noise: msg1 missing encrypted static key".to_string());
        }
        let rs_enc = &msg[..32 + TAG_SIZE];
        let msg = &msg[32 + TAG_SIZE..];
        let rs_bytes = self.ss.decrypt_and_hash(rs_enc)?;
        self.rs.copy_from_slice(&rs_bytes);

        // es: initiator's ephemeral × responder's static
        let es_dh = dh(self.e.private(), self.rs);
        self.ss.mix_key(&es_dh);

        self.ss.decrypt_and_hash(msg)?;
        Ok(())
    }

    /// Sends: -> s, se [payload]
    /// Returns (fromInitiator, fromResponder, handshake_hash, remote_static) on success.
    pub(crate) fn write_msg2(
        mut self,
        w: &mut dyn Write,
        payload: &[u8],
    ) -> Result<(CipherState, CipherState, [u8; 32], [u8; 32]), String> {
        let enc_s = self.ss.encrypt_and_hash(&self.s.public_key);

        // se: initiator's static × responder's ephemeral
        let se_dh = dh(self.s.private(), self.re);
        self.ss.mix_key(&se_dh);

        let enc_payload = self.ss.encrypt_and_hash(payload);

        let mut msg = enc_s;
        msg.extend_from_slice(&enc_payload);
        write_frame(w, &msg).map_err(|e| format!("noise: write msg2: {}", e))?;

        let hash = self.ss.h;
        let rs = self.rs;
        let (fi, fr) = self.ss.split();
        Ok((fi, fr, hash, rs))
    }

    /// Receives: -> s, se [payload]
    /// Returns (fromInitiator, fromResponder, handshake_hash, remote_static) on success.
    pub(crate) fn read_msg2(
        mut self,
        r: &mut dyn Read,
    ) -> Result<(CipherState, CipherState, [u8; 32], [u8; 32]), String> {
        let msg = read_frame(r).map_err(|e| format!("noise: read msg2: {}", e))?;

        if msg.len() < 32 + TAG_SIZE {
            return Err("noise: msg2 missing encrypted static key".to_string());
        }
        let rs_enc = &msg[..32 + TAG_SIZE];
        let msg = &msg[32 + TAG_SIZE..];
        let rs_bytes = self.ss.decrypt_and_hash(rs_enc)?;
        self.rs.copy_from_slice(&rs_bytes);

        // se: responder's ephemeral × initiator's static (= DH(e_R, s_I))
        let se_dh = dh(self.e.private(), self.rs);
        self.ss.mix_key(&se_dh);

        self.ss.decrypt_and_hash(msg)?;

        let hash = self.ss.h;
        let rs = self.rs;
        let (fi, fr) = self.ss.split();
        Ok((fi, fr, hash, rs))
    }

    #[allow(dead_code)]
    pub(crate) fn remote_static(&self) -> [u8; 32] {
        self.rs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Drives a full XX handshake using in-memory byte buffers as the transport.
    /// Returns (fromInitiator, fromResponder) for both sides.
    fn run_handshake(
        init_s: Keypair,
        resp_s: Keypair,
        init_e: Keypair,
        resp_e: Keypair,
        prologue: &[u8],
        payload0: &[u8],
        payload1: &[u8],
        payload2: &[u8],
    ) -> (
        [u8; 32],
        [u8; 32],
        CipherState,
        CipherState,
        CipherState,
        CipherState,
    ) {
        let mut hs_i = HandshakeState::new_fixed(init_s, init_e, prologue);
        let mut hs_r = HandshakeState::new_fixed(resp_s, resp_e, prologue);

        // msg0: initiator -> responder
        let mut msg0 = Vec::new();
        hs_i.write_msg0(&mut msg0, payload0).unwrap();
        hs_r.read_msg0(&mut Cursor::new(&msg0)).unwrap();

        // msg1: responder -> initiator
        let mut msg1 = Vec::new();
        hs_r.write_msg1(&mut msg1, payload1).unwrap();
        hs_i.read_msg1(&mut Cursor::new(&msg1)).unwrap();

        // msg2: initiator -> responder (produces cipher states)
        let mut msg2 = Vec::new();
        let (i_fi, i_fr, i_hash, _) = hs_i.write_msg2(&mut msg2, payload2).unwrap();
        let (r_fi, r_fr, r_hash, _) = hs_r.read_msg2(&mut Cursor::new(&msg2)).unwrap();

        (i_hash, r_hash, i_fi, i_fr, r_fi, r_fr)
    }

    /// Tracer bullet: full XX handshake completes and cipher states work.
    #[test]
    fn handshake_completes_and_cipher_states_work() {
        let init_s = generate_keypair();
        let resp_s = generate_keypair();
        let init_e = generate_keypair();
        let resp_e = generate_keypair();

        let (_, _, mut i_fi, mut i_fr, mut r_fi, mut r_fr) =
            run_handshake(init_s, resp_s, init_e, resp_e, &[], &[], &[], &[]);

        // Initiator sends on fromInitiator; responder receives on fromInitiator.
        let ct = i_fi.encrypt(&[], b"hello");
        let pt = r_fi.decrypt(&[], &ct).expect("decrypt failed");
        assert_eq!(pt, b"hello");

        // Responder sends on fromResponder; initiator receives on fromResponder.
        let ct2 = r_fr.encrypt(&[], b"world");
        let pt2 = i_fr.decrypt(&[], &ct2).expect("decrypt failed");
        assert_eq!(pt2, b"world");
    }
}
