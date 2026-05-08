use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::{
    keypair::Keypair,
    session::{RetryConn, SessionInner},
};

/// A fully negotiated, bidirectional encrypted channel produced by the XX
/// Handshake Pattern. `send` and `receive` are safe to call concurrently.
/// Sessions are not resumable after close.
///
/// `remote_public_key()` returns the authenticated static public key of the
/// remote peer unconditionally — mutual authentication is guaranteed by XX.
pub struct Session<T: Read + Write + Send> {
    inner: SessionInner<T>,
    remote_pub_key: [u8; 32],
}

impl<T: Read + Write + Send> Session<T> {
    fn new(
        conn: T,
        send_cs: crate::cipher::CipherState,
        recv_cs: crate::cipher::CipherState,
        remote_pub_key: [u8; 32],
    ) -> Self {
        Self {
            inner: SessionInner::new(conn, send_cs, recv_cs),
            remote_pub_key,
        }
    }

    /// Encrypts payload and writes it to the transport with a 2-byte
    /// big-endian length prefix.
    pub fn send(&self, payload: &[u8]) -> Result<(), String> {
        self.inner.send(payload)
    }

    /// Reads one framed message from the transport and decrypts it.
    pub fn receive(&self) -> Result<Vec<u8>, String> {
        self.inner.receive()
    }

    /// Returns the authenticated static public key of the remote peer,
    /// established during the XX handshake. Trust policy is the caller's
    /// responsibility.
    pub fn remote_public_key(&self) -> [u8; 32] {
        self.remote_pub_key
    }

    /// Closes the session. Subsequent send/receive return errors.
    /// Sessions are not resumable after close.
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

// ── dial / accept ─────────────────────────────────────────────────────────────

/// Performs the XX handshake as the Initiator over conn using the provided
/// Keypair. Returns a Session on success or an Expected Failure error.
pub fn dial<T: Read + Write + Send>(conn: T, keypair: Keypair) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, true)
}

/// Performs the XX handshake as the Responder over conn using the provided
/// Keypair. Returns a Session on success or an Expected Failure error.
pub fn accept<T: Read + Write + Send>(conn: T, keypair: Keypair) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, false)
}

fn do_handshake<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    initiator: bool,
) -> Result<Session<T>, String> {
    let mut hs = crate::handshake::HandshakeState::new(keypair);
    let mut rc = RetryConn(conn);

    let (send_cs, recv_cs, remote_pub_key) = if initiator {
        // -> e
        hs.write_msg0(&mut rc, &[])
            .map_err(|e| format!("noise: write_msg0: {}", e))?;
        // <- e, ee, s, es
        hs.read_msg1(&mut rc)?;
        // -> s, se
        let (fi, fr, _hash, rs) = hs.write_msg2(&mut rc, &[])?;
        (fi, fr, rs)
    } else {
        // <- e
        hs.read_msg0(&mut rc)?;
        // -> e, ee, s, es
        hs.write_msg1(&mut rc, &[])
            .map_err(|e| format!("noise: write_msg1: {}", e))?;
        // <- s, se
        let (fi, fr, _hash, rs) = hs.read_msg2(&mut rc)?;
        (fr, fi, rs)
    };

    Ok(Session::new(rc.0, send_cs, recv_cs, remote_pub_key))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;
    use crate::test_helpers::mem_pipe_pair;

    #[test]
    fn dial_accept_complete() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        i_session.send(b"hello").expect("send failed");
        let msg = r_session.receive().expect("receive failed");
        assert_eq!(msg, b"hello");
    }

    #[test]
    fn responder_sends_to_initiator() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        r_session.send(b"pong").expect("send failed");
        let msg = i_session.receive().expect("receive failed");
        assert_eq!(msg, b"pong");
    }

    #[test]
    fn remote_public_key_is_correct() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let i_pub = i_kp.public_key;
        let r_pub = r_kp.public_key;
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        assert_eq!(i_session.remote_public_key(), r_pub);
        assert_eq!(r_session.remote_public_key(), i_pub);
    }

    #[test]
    fn send_oversize_payload_fails() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");

        assert!(i_session.send(&vec![0u8; 65536]).is_err());
    }

    #[test]
    fn close_rejects_subsequent_send() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");

        i_session.close().expect("close failed");
        assert!(i_session.send(b"after close").is_err());
    }

    #[test]
    fn concurrent_send_and_receive_do_not_deadlock() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = Arc::new(dial(i_conn, i_kp).expect("dial failed"));
        let r_session = Arc::new(r_handle.join().unwrap().expect("accept failed"));

        let r_sess_clone = r_session.clone();
        let recv_handle = std::thread::spawn(move || r_sess_clone.receive());

        i_session
            .send(b"concurrent")
            .expect("send must not deadlock");
        let msg = recv_handle.join().unwrap().expect("receive failed");
        assert_eq!(msg, b"concurrent");
    }
}
