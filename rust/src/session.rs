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
