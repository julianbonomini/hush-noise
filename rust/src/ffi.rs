/// ffi.rs — UniFFI FFI wrapper layer for hush-noise.
///
/// Bridges the transport-generic `session::Session<T>` to UniFFI's object
/// model, which requires `Arc`-wrapped types. The `NoiseTransport` callback
/// interface is wrapped in a `TransportWrapper` that implements `std::io::Read`
/// and `std::io::Write` so it can be passed directly into `dial`/`accept`.
use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::{
    keypair::{generate_keypair as core_generate_keypair, Keypair},
    session::{accept as core_accept, dial as core_dial, Session as CoreSession},
};

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("noise: transport error: {message}")]
    Transport { message: String },
    #[error("noise: handshake failed: {message}")]
    Handshake { message: String },
    #[error("noise: session is closed")]
    Closed {},
    #[error("noise: payload too large")]
    PayloadTooLarge {},
}

impl From<String> for NoiseError {
    fn from(s: String) -> Self {
        // Route closed / payload-size errors from the core session layer.
        if s.contains("closed") {
            NoiseError::Closed {}
        } else if s.contains("payload exceeds") {
            NoiseError::PayloadTooLarge {}
        } else if s.contains("handshake") || s.contains("decrypt") || s.contains("authenticate") {
            NoiseError::Handshake { message: s }
        } else {
            NoiseError::Transport { message: s }
        }
    }
}

// ── KeypairRecord ─────────────────────────────────────────────────────────────

/// Plain-data record — maps to UDL `dictionary KeypairRecord`.
pub struct KeypairRecord {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeypairRecord {
    fn to_keypair(&self) -> Keypair {
        let mut priv_arr = [0u8; 32];
        let mut pub_arr = [0u8; 32];
        priv_arr.copy_from_slice(&self.private_key[..32]);
        pub_arr.copy_from_slice(&self.public_key[..32]);
        Keypair::new(priv_arr, pub_arr)
    }
}

pub fn generate_keypair() -> KeypairRecord {
    let kp = core_generate_keypair();
    KeypairRecord {
        public_key: kp.public_key.to_vec(),
        private_key: kp.private().to_vec(),
    }
}

pub fn new_keypair(private_key: &[u8], public_key: &[u8]) -> KeypairRecord {
    KeypairRecord {
        public_key: public_key.to_vec(),
        private_key: private_key.to_vec(),
    }
}

// ── NoiseTransport callback ───────────────────────────────────────────────────

/// Callback interface — implemented by the caller in Swift / Kotlin.
/// Maps to UDL `[Trait, WithForeign] interface NoiseTransport`.
pub trait NoiseTransport: Send + Sync {
    fn read(&self, count: u64) -> Result<Vec<u8>, NoiseError>;
    fn write(&self, data: Vec<u8>) -> Result<(), NoiseError>;
}

/// Wraps a `Arc<dyn NoiseTransport>` so it satisfies `std::io::Read + Write`.
struct TransportWrapper {
    inner: Arc<dyn NoiseTransport>,
}

impl Read for TransportWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        let bytes = self
            .inner
            .read(n)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let len = bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}

impl Write for TransportWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .write(buf.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// FFI-visible session object. Maps to UDL `interface Session`.
/// Wraps the transport-generic `CoreSession` behind `Arc<Mutex<...>>` so
/// UniFFI can hand out reference-counted handles to callers.
pub struct Session {
    inner: Arc<CoreSession<TransportWrapper>>,
}

impl Session {
    pub fn send(&self, payload: &[u8]) -> Result<(), NoiseError> {
        self.inner.send(payload).map_err(NoiseError::from)
    }

    pub fn receive(&self) -> Result<Vec<u8>, NoiseError> {
        self.inner.receive().map_err(NoiseError::from)
    }

    pub fn remote_public_key(&self) -> Vec<u8> {
        self.inner.remote_public_key().to_vec()
    }

    pub fn close(&self) -> Result<(), NoiseError> {
        self.inner.close().map_err(|e| NoiseError::Transport {
            message: e.to_string(),
        })
    }
}

// ── dial / accept ─────────────────────────────────────────────────────────────

pub fn dial(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
) -> Result<Arc<Session>, NoiseError> {
    let wrapper = TransportWrapper { inner: transport };
    let core_session = core_dial(wrapper, keypair.to_keypair()).map_err(NoiseError::from)?;
    Ok(Arc::new(Session {
        inner: Arc::new(core_session),
    }))
}

pub fn accept(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
) -> Result<Arc<Session>, NoiseError> {
    let wrapper = TransportWrapper { inner: transport };
    let core_session = core_accept(wrapper, keypair.to_keypair()).map_err(NoiseError::from)?;
    Ok(Arc::new(Session {
        inner: Arc::new(core_session),
    }))
}
