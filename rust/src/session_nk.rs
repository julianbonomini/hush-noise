use std::io::{self, Read, Write};

use crate::{
    keypair::Keypair,
    session::{RetryConn, SessionInner},
};

/// A fully negotiated, bidirectional encrypted channel produced by the NK
/// Handshake Pattern. `send` and `receive` are safe to call concurrently.
/// Sessions are not resumable after close.
///
/// The NK pattern is anonymous for the Initiator — the Responder never
/// learns the Initiator's static key. `remote_public_key()` is therefore
/// absent from this type entirely.
pub struct Session<T: Read + Write + Send> {
    inner: SessionInner<T>,
}

impl<T: Read + Write + Send> Session<T> {
    fn new(
        conn: T,
        send_cs: crate::cipher::CipherState,
        recv_cs: crate::cipher::CipherState,
    ) -> Self {
        Self {
            inner: SessionInner::new(conn, send_cs, recv_cs),
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

    /// Closes the session. Subsequent send/receive return errors.
    /// Sessions are not resumable after close.
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

// ── dial / accept ─────────────────────────────────────────────────────────────

/// Performs the NK handshake as the Initiator over conn.
/// `remote_static` is the Responder's known static public key — the Initiator
/// must have it before calling dial. Returns a Session on success.
pub fn dial<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    remote_static: [u8; 32],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, Some(remote_static))
}

/// Performs the NK handshake as the Responder over conn using the provided
/// Keypair. Returns a Session on success.
pub fn accept<T: Read + Write + Send>(conn: T, keypair: Keypair) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, None)
}

fn do_handshake<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    remote_static: Option<[u8; 32]>,
) -> Result<Session<T>, String> {
    let hs = crate::handshake::HandshakeStateNk::new(keypair, remote_static);
    let mut rc = RetryConn(conn);

    let (send_cs, recv_cs) = if remote_static.is_some() {
        // Initiator: -> e, es  then  <- e, ee
        let (fi, fr) = hs.do_initiator(&mut rc)?;
        (fi, fr)
    } else {
        // Responder: <- e, es  then  -> e, ee
        let (fi, fr) = hs.do_responder(&mut rc)?;
        (fr, fi)
    };

    Ok(Session::new(rc.0, send_cs, recv_cs))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;
    use crate::test_helpers::mem_pipe_pair;

    /// Tracer bullet: NK dial and accept complete and can exchange a message.
    #[test]
    fn dial_accept_complete() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp, r_pub).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        i_session.send(b"hello nk").expect("send failed");
        let msg = r_session.receive().expect("receive failed");
        assert_eq!(msg, b"hello nk");
    }

    #[test]
    fn responder_sends_to_initiator() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp, r_pub).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        r_session.send(b"pong nk").expect("send failed");
        let msg = i_session.receive().expect("receive failed");
        assert_eq!(msg, b"pong nk");
    }

    #[test]
    fn send_oversize_payload_fails() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp, r_pub).expect("dial failed");

        assert!(i_session.send(&vec![0u8; 65536]).is_err());
    }

    #[test]
    fn close_rejects_subsequent_send() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp, r_pub).expect("dial failed");

        i_session.close().expect("close failed");
        assert!(i_session.send(b"after close").is_err());
    }
}
