use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use crate::{
    cipher::{CipherState, MAX_MESSAGE_SIZE},
    framing::read_frame,
    handshake::HandshakeState,
    keypair::Keypair,
};

/// Session is a fully negotiated, bidirectional encrypted channel between two peers.
/// `send` and `receive` are safe to call concurrently from different threads.
/// Sessions are not resumable — if the transport dies, establish a new Session
/// via `dial` or `accept`.
pub struct Session<T: Read + Write + Send> {
    conn: Arc<Mutex<T>>,
    send_cs: Mutex<CipherState>,
    recv_cs: Mutex<CipherState>,
    remote_pub_key: [u8; 32],
    closed: Mutex<bool>,
}

impl<T: Read + Write + Send> Session<T> {
    fn new(conn: T, send_cs: CipherState, recv_cs: CipherState, remote_pub_key: [u8; 32]) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            send_cs: Mutex::new(send_cs),
            recv_cs: Mutex::new(recv_cs),
            remote_pub_key,
            closed: Mutex::new(false),
        }
    }

    /// Encrypts payload and writes it to the transport with a 2-byte big-endian
    /// length prefix. Returns an Expected Failure error if payload exceeds 65535
    /// bytes or the transport fails.
    pub fn send(&self, payload: &[u8]) -> Result<(), String> {
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
        self.conn
            .lock()
            .unwrap()
            .write_all(&{
                // Build the framed message manually to avoid double-locking conn.
                let mut buf = Vec::with_capacity(2 + ciphertext.len());
                let len = ciphertext.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&ciphertext);
                buf
            })
            .map_err(|e| format!("noise: send: {}", e))
    }

    /// Reads one message from the transport, decrypts it, and returns the plaintext.
    /// Returns an Expected Failure error on I/O or decryption failure.
    pub fn receive(&self) -> Result<Vec<u8>, String> {
        if *self.closed.lock().unwrap() {
            return Err("noise: session is closed".to_string());
        }
        let ciphertext = {
            let mut conn = self.conn.lock().unwrap();
            read_frame(&mut *conn).map_err(|e| format!("noise: receive frame: {}", e))?
        };
        self.recv_cs.lock().unwrap().decrypt(&[], &ciphertext)
    }

    /// Returns the authenticated static public key of the remote peer,
    /// established during the handshake. Trust policy is the caller's responsibility.
    pub fn remote_public_key(&self) -> [u8; 32] {
        self.remote_pub_key
    }

    /// Closes the underlying transport. Subsequent send/receive return errors.
    /// Sessions are not resumable after close.
    pub fn close(&self) -> io::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }
}

/// Performs the XX handshake as the Initiator over conn using the provided Keypair.
/// Returns a Session on success or an Expected Failure error.
pub fn dial<T: Read + Write + Send>(conn: T, keypair: Keypair) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, true)
}

/// Performs the XX handshake as the Responder over conn using the provided Keypair.
/// Returns a Session on success or an Expected Failure error.
pub fn accept<T: Read + Write + Send>(conn: T, keypair: Keypair) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, false)
}

fn do_handshake<T: Read + Write + Send>(
    mut conn: T,
    keypair: Keypair,
    initiator: bool,
) -> Result<Session<T>, String> {
    let mut hs = HandshakeState::new(keypair);

    let (send_cs, recv_cs, remote_pub_key) = if initiator {
        // -> e
        hs.write_msg0(&mut conn, &[])
            .map_err(|e| format!("noise: write_msg0: {}", e))?;
        // <- e, ee, s, es
        hs.read_msg1(&mut conn)?;
        // -> s, se; rs was set during read_msg1 (responder's static)
        let (fi, fr, _hash, rs) = hs.write_msg2(&mut conn, &[])?;
        // Initiator sends on fromInitiator, receives on fromResponder
        (fi, fr, rs)
    } else {
        // <- e
        hs.read_msg0(&mut conn)?;
        // -> e, ee, s, es
        hs.write_msg1(&mut conn, &[])
            .map_err(|e| format!("noise: write_msg1: {}", e))?;
        // <- s, se; rs is set during read_msg2 (initiator's static)
        let (fi, fr, _hash, rs) = hs.read_msg2(&mut conn)?;
        // Responder sends on fromResponder, receives on fromInitiator
        (fr, fi, rs)
    };

    Ok(Session::new(conn, send_cs, recv_cs, remote_pub_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;

    /// In-memory bidirectional pipe for testing.
    /// Uses two shared Vec<u8> buffers — one per direction.
    use std::sync::{Arc, Mutex};

    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for MemPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut rb = self.read_buf.lock().unwrap();
                if !rb.is_empty() {
                    let n = buf.len().min(rb.len());
                    buf[..n].copy_from_slice(&rb[..n]);
                    rb.drain(..n);
                    return Ok(n);
                }
                drop(rb);
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
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

    fn mem_pipe_pair() -> (MemPipe, MemPipe) {
        let ab = Arc::new(Mutex::new(Vec::new()));
        let ba = Arc::new(Mutex::new(Vec::new()));
        (
            MemPipe {
                read_buf: ba.clone(),
                write_buf: ab.clone(),
            },
            MemPipe {
                read_buf: ab.clone(),
                write_buf: ba.clone(),
            },
        )
    }

    /// Tracer bullet: dial and accept complete the handshake and return Sessions.
    #[test]
    fn dial_accept_complete() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);

        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        // Initiator sends to responder.
        i_session.send(b"hello").expect("send failed");
        let msg = r_session.receive().expect("receive failed");
        assert_eq!(msg, b"hello");
    }

    /// Responder sends to initiator.
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

    /// remote_public_key returns the other peer's static public key.
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

        assert_eq!(
            i_session.remote_public_key(),
            r_pub,
            "initiator should see responder's pubkey"
        );
        assert_eq!(
            r_session.remote_public_key(),
            i_pub,
            "responder should see initiator's pubkey"
        );
    }

    /// send with payload > 65535 bytes returns an error.
    #[test]
    fn send_oversize_payload_fails() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");

        let oversized = vec![0u8; 65536];
        let result = i_session.send(&oversized);
        assert!(result.is_err(), "send with 65536-byte payload should fail");
    }

    /// close causes subsequent send to return an error.
    #[test]
    fn close_rejects_subsequent_send() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = crate::keypair::Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2));
        let i_session = dial(i_conn, i_kp).expect("dial failed");

        i_session.close().expect("close failed");
        let result = i_session.send(b"after close");
        assert!(result.is_err(), "send after close should fail");
    }
}
