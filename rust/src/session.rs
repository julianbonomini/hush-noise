use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use crate::cipher::{CipherState, MAX_MESSAGE_SIZE};

// ── RetryConn ─────────────────────────────────────────────────────────────────

/// A Read+Write adapter that retries on WouldBlock/Interrupted, sleeping briefly.
/// Used during the handshake phase so transports that return WouldBlock when
/// data is not yet available work correctly with read_exact.
pub(crate) struct RetryConn<T: Read + Write>(pub(crate) T);

impl<T: Read + Write> Read for RetryConn<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.read(buf) {
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
                other => return other,
            }
        }
    }
}

impl<T: Read + Write> Write for RetryConn<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

// ── SessionInner ──────────────────────────────────────────────────────────────

/// Shared post-handshake state used by both `session_xx::Session` and
/// `session_nk::Session`. Holds the transport, the two per-direction
/// CipherStates, and the closed flag.
///
/// The handshake pattern affects how `SessionInner` is constructed; it does
/// not affect how it behaves afterwards.
pub(crate) struct SessionInner<T: Read + Write + Send> {
    conn: Arc<Mutex<T>>,
    send_cs: Mutex<CipherState>,
    recv_cs: Mutex<CipherState>,
    closed: Mutex<bool>,
}

impl<T: Read + Write + Send> SessionInner<T> {
    pub(crate) fn new(conn: T, send_cs: CipherState, recv_cs: CipherState) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            send_cs: Mutex::new(send_cs),
            recv_cs: Mutex::new(recv_cs),
            closed: Mutex::new(false),
        }
    }

    /// Read exactly `n` bytes, acquiring and releasing the conn mutex per
    /// `read()` call. Retries on WouldBlock/Interrupted, sleeping briefly to
    /// yield to other threads. This is the key to concurrent send/receive:
    /// send() can acquire conn between reads.
    pub(crate) fn read_exact_interruptible(&self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut filled = 0;
        while filled < n {
            match self.conn.lock().unwrap().read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(k) => filled += k,
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(buf)
    }

    /// Encrypts payload and writes it to the transport with a 2-byte
    /// big-endian length prefix.
    pub(crate) fn send(&self, payload: &[u8]) -> Result<(), String> {
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(format!(
                "noise: payload exceeds maximum message size ({} > {})",
                payload.len(),
                MAX_MESSAGE_SIZE
            ));
        }
        if *self.closed.lock().unwrap() {
            return Err("noise: session is closed".to_string());
        }
        let ciphertext = self.send_cs.lock().unwrap().encrypt(&[], payload);
        let mut framed = Vec::with_capacity(2 + ciphertext.len());
        framed.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        framed.extend_from_slice(&ciphertext);
        self.conn
            .lock()
            .unwrap()
            .write_all(&framed)
            .map_err(|e| format!("noise: send: {}", e))
    }

    /// Reads one framed message from the transport, decrypts it, and returns
    /// the plaintext. The conn mutex is released between individual read()
    /// calls so concurrent send() operations can interleave.
    pub(crate) fn receive(&self) -> Result<Vec<u8>, String> {
        if *self.closed.lock().unwrap() {
            return Err("noise: session is closed".to_string());
        }
        let header = self
            .read_exact_interruptible(2)
            .map_err(|e| format!("noise: receive header: {}", e))?;
        let size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let ciphertext = self
            .read_exact_interruptible(size)
            .map_err(|e| format!("noise: receive body: {}", e))?;
        self.recv_cs.lock().unwrap().decrypt(&[], &ciphertext)
    }

    /// Closes the session. Subsequent send/receive return errors.
    pub(crate) fn close(&self) -> io::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

// ── Session (XX) ──────────────────────────────────────────────────────────────

/// A fully negotiated, bidirectional encrypted channel produced by the XX
/// Handshake Pattern. `send` and `receive` are safe to call concurrently.
/// Sessions are not resumable after close.
pub struct Session<T: Read + Write + Send> {
    inner: SessionInner<T>,
    remote_pub_key: [u8; 32],
}

impl<T: Read + Write + Send> Session<T> {
    pub(crate) fn new(
        conn: T,
        send_cs: CipherState,
        recv_cs: CipherState,
        remote_pub_key: [u8; 32],
    ) -> Self {
        Self {
            inner: SessionInner::new(conn, send_cs, recv_cs),
            remote_pub_key,
        }
    }

    pub fn send(&self, payload: &[u8]) -> Result<(), String> {
        self.inner.send(payload)
    }

    pub fn receive(&self) -> Result<Vec<u8>, String> {
        self.inner.receive()
    }

    /// Returns the authenticated static public key of the remote peer,
    /// established during the XX handshake. Trust policy is the caller's
    /// responsibility.
    pub fn remote_public_key(&self) -> [u8; 32] {
        self.remote_pub_key
    }

    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

// ── dial / accept (XX) ────────────────────────────────────────────────────────

/// Performs the XX handshake as the Initiator over conn using the provided
/// Keypair. Returns a Session on success or an Expected Failure error.
pub fn dial<T: Read + Write + Send>(
    conn: T,
    keypair: crate::keypair::Keypair,
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, true)
}

/// Performs the XX handshake as the Responder over conn using the provided
/// Keypair. Returns a Session on success or an Expected Failure error.
pub fn accept<T: Read + Write + Send>(
    conn: T,
    keypair: crate::keypair::Keypair,
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, false)
}

fn do_handshake<T: Read + Write + Send>(
    conn: T,
    keypair: crate::keypair::Keypair,
    initiator: bool,
) -> Result<Session<T>, String> {
    let mut hs = crate::handshake::HandshakeState::new(keypair);
    let mut rc = RetryConn(conn);

    let (send_cs, recv_cs, remote_pub_key) = if initiator {
        hs.write_msg0(&mut rc, &[])
            .map_err(|e| format!("noise: write_msg0: {}", e))?;
        hs.read_msg1(&mut rc)?;
        let (fi, fr, _hash, rs) = hs.write_msg2(&mut rc, &[])?;
        (fi, fr, rs)
    } else {
        hs.read_msg0(&mut rc)?;
        hs.write_msg1(&mut rc, &[])
            .map_err(|e| format!("noise: write_msg1: {}", e))?;
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
    use std::sync::Arc;

    /// In-memory bidirectional pipe for testing.
    ///
    /// read() returns WouldBlock immediately when empty so that
    /// Session::read_exact_interruptible() releases the conn mutex between
    /// retries and allows concurrent send() to proceed.
    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for MemPipe {
        fn drop(&mut self) {
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl Read for MemPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut rb = self.read_buf.lock().unwrap();
            if !rb.is_empty() {
                let n = buf.len().min(rb.len());
                buf[..n].copy_from_slice(&rb[..n]);
                rb.drain(..n);
                return Ok(n);
            }
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(0);
            }
            Err(io::Error::new(ErrorKind::WouldBlock, "buffer empty"))
        }
    }

    impl Write for MemPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn mem_pipe_pair() -> (MemPipe, MemPipe) {
        let ab = Arc::new(Mutex::new(Vec::new()));
        let ba = Arc::new(Mutex::new(Vec::new()));
        let a_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let b_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            MemPipe {
                read_buf: ba.clone(),
                write_buf: ab.clone(),
                closed: b_closed.clone(),
            },
            MemPipe {
                read_buf: ab.clone(),
                write_buf: ba.clone(),
                closed: a_closed.clone(),
            },
        )
    }

    #[test]
    fn dial_accept_complete() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
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

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
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

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_pub);
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

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");

        let result = i_session.send(&vec![0u8; 65536]);
        assert!(result.is_err());
    }

    #[test]
    fn close_rejects_subsequent_send() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
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

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
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
