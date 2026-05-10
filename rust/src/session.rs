use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use crate::framing::MAX_PLAINTEXT_SIZE;

// ── RetryConn ─────────────────────────────────────────────────────────────────

/// Read+Write adapter that retries on WouldBlock/Interrupted, sleeping briefly.
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
/// `session_nk::Session`. Holds the transport, a snow TransportState, and
/// the closed flag.
///
/// snow::TransportState requires &mut self — all crypto ops are serialised
/// through a single Mutex. send and receive acquire the transport mutex
/// separately from the conn mutex so concurrent callers can at least overlap
/// I/O waits.
pub(crate) struct SessionInner<T: Read + Write + Send> {
    conn: Arc<Mutex<T>>,
    transport: Mutex<snow::TransportState>,
    closed: Mutex<bool>,
}

impl<T: Read + Write + Send> SessionInner<T> {
    pub(crate) fn new(conn: T, transport: snow::TransportState) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            transport: Mutex::new(transport),
            closed: Mutex::new(false),
        }
    }

    /// Read exactly `n` bytes, releasing the conn mutex between read() calls
    /// so concurrent send() can interleave.
    ///
    /// The guard is bound to a `let` so it drops at the `;` — before the
    /// match — ensuring the lock is never held across the WouldBlock sleep.
    pub(crate) fn read_exact_interruptible(&self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut filled = 0;
        while filled < n {
            // Lock, read, unlock (guard drops at `;` before match).
            let result = self.conn.lock().unwrap().read(&mut buf[filled..]);
            match result {
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
                    // Sleep without holding the lock so concurrent send() can proceed.
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
        if payload.len() > MAX_PLAINTEXT_SIZE {
            return Err(format!(
                "noise: payload exceeds maximum message size ({} > {})",
                payload.len(),
                MAX_PLAINTEXT_SIZE
            ));
        }
        if *self.closed.lock().unwrap() {
            return Err("noise: session is closed".to_string());
        }
        // Allocate ciphertext buffer: plaintext + 16-byte AEAD tag.
        let mut ciphertext = vec![0u8; payload.len() + 16];
        let len = self
            .transport
            .lock()
            .unwrap()
            .write_message(payload, &mut ciphertext)
            .map_err(|e| format!("noise: encrypt: {:?}", e))?;
        let mut framed = Vec::with_capacity(2 + len);
        framed.extend_from_slice(&(len as u16).to_be_bytes());
        framed.extend_from_slice(&ciphertext[..len]);
        self.conn
            .lock()
            .unwrap()
            .write_all(&framed)
            .map_err(|e| format!("noise: send: {}", e))
    }

    /// Reads one framed message from the transport, decrypts it, and returns
    /// the plaintext.
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
        let mut plaintext = vec![0u8; size];
        let len = self
            .transport
            .lock()
            .unwrap()
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| format!("noise: decrypt: {:?}", e))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Closes the session. Subsequent send/receive return errors.
    pub(crate) fn close(&self) -> io::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}
