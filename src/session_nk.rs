use std::io::{self, Read, Write};

use crate::{
    framing::{read_frame, write_frame},
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
    fn new(conn: T, transport: snow::TransportState) -> Self {
        Self {
            inner: SessionInner::new(conn, transport),
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
    // Bind key bytes to locals with sufficient lifetime for the builder borrows.
    let priv_key = keypair.private();
    let rs_buf: Option<[u8; 32]> = remote_static;

    let mut builder = snow::Builder::new(
        "Noise_NK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| format!("noise: bad params: {:?}", e))?,
    )
    .local_private_key(&priv_key)
    .map_err(|e| format!("noise: set local key: {:?}", e))?;

    if let Some(ref rs) = rs_buf {
        builder = builder
            .remote_public_key(rs)
            .map_err(|e| format!("noise: set remote key: {:?}", e))?;
    }

    let mut hs = if remote_static.is_some() {
        builder
            .build_initiator()
            .map_err(|e| format!("noise: build initiator: {:?}", e))?
    } else {
        builder
            .build_responder()
            .map_err(|e| format!("noise: build responder: {:?}", e))?
    };

    let mut rc = RetryConn(conn);
    let mut buf = vec![0u8; 65535];

    if remote_static.is_some() {
        // Initiator: -> e, es
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg0: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg0: {}", e))?;

        // <- e, ee
        let msg1 = read_frame(&mut rc).map_err(|e| format!("noise: read msg1: {}", e))?;
        hs.read_message(&msg1, &mut buf)
            .map_err(|e| format!("noise: read msg1: {:?}", e))?;
    } else {
        // Responder: <- e, es
        let msg0 = read_frame(&mut rc).map_err(|e| format!("noise: read msg0: {}", e))?;
        hs.read_message(&msg0, &mut buf)
            .map_err(|e| format!("noise: read msg0: {:?}", e))?;

        // -> e, ee
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg1: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg1: {}", e))?;
    }

    let transport = hs
        .into_transport_mode()
        .map_err(|e| format!("noise: into_transport_mode: {:?}", e))?;

    Ok(Session::new(rc.0, transport))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;
    use crate::test_helpers::mem_pipe_pair;

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
