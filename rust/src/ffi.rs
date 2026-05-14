/// ffi.rs — UniFFI FFI wrapper layer for hush-noise.
///
/// Bridges session_xx::Session and session_nk::Session to UniFFI's object
/// model, which requires Arc-wrapped types. The NoiseTransport callback
/// interface is wrapped in a TransportWrapper that implements Read+Write so
/// it can be passed into dial/accept.
use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::{
    keypair::{generate_keypair as core_generate_keypair, Keypair},
    session_nk::{accept as core_accept_nk, dial as core_dial_nk, Session as CoreSessionNk},
    session_xx::{accept as core_accept_xx, dial as core_dial_xx, Session as CoreSessionXx},
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
///
/// `private_key` is sensitive key material. The internal `Keypair` produced
/// by `to_keypair()` implements `ZeroizeOnDrop` so the crypto-active copy is
/// zeroed on drop. This record is a short-lived FFI transport struct and is
/// not itself zeroed (UniFFI dict destructuring precludes a `Drop` impl).
pub struct KeypairRecord {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeypairRecord {
    fn to_keypair(&self) -> Result<Keypair, NoiseError> {
        if self.private_key.len() != 32 {
            return Err(NoiseError::Transport {
                message: format!(
                    "noise: private_key must be 32 bytes, got {}",
                    self.private_key.len()
                ),
            });
        }
        if self.public_key.len() != 32 {
            return Err(NoiseError::Transport {
                message: format!(
                    "noise: public_key must be 32 bytes, got {}",
                    self.public_key.len()
                ),
            });
        }
        let mut priv_arr = [0u8; 32];
        let mut pub_arr = [0u8; 32];
        priv_arr.copy_from_slice(&self.private_key);
        pub_arr.copy_from_slice(&self.public_key);
        Ok(Keypair::new(priv_arr, pub_arr))
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

/// Wraps `Arc<dyn NoiseTransport>` so it satisfies `std::io::Read + Write`.
struct TransportWrapper {
    inner: Arc<dyn NoiseTransport>,
}

impl Read for TransportWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .inner
            .read(buf.len() as u64)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let len = bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}

impl Write for TransportWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .write(buf.to_vec())
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── SessionXx ─────────────────────────────────────────────────────────────────

/// FFI-visible XX session. Maps to UDL `interface SessionXx`.
pub struct SessionXx {
    inner: Arc<CoreSessionXx<TransportWrapper>>,
}

impl SessionXx {
    pub fn send(&self, payload: &[u8]) -> Result<(), NoiseError> {
        self.inner.send(payload).map_err(NoiseError::from)
    }

    pub fn receive(&self) -> Result<Vec<u8>, NoiseError> {
        self.inner.receive().map_err(NoiseError::from)
    }

    /// Returns the authenticated static public key of the remote peer.
    /// Always present — mutual authentication is guaranteed by XX.
    pub fn remote_public_key(&self) -> Vec<u8> {
        self.inner.remote_public_key().to_vec()
    }

    pub fn close(&self) -> Result<(), NoiseError> {
        self.inner.close().map_err(|e| NoiseError::Transport {
            message: e.to_string(),
        })
    }
}

// ── SessionNk ─────────────────────────────────────────────────────────────────

/// FFI-visible NK session. Maps to UDL `interface SessionNk`.
/// No remote_public_key() — initiator is anonymous, responder has no remote static.
pub struct SessionNk {
    inner: Arc<CoreSessionNk<TransportWrapper>>,
}

impl SessionNk {
    pub fn send(&self, payload: &[u8]) -> Result<(), NoiseError> {
        self.inner.send(payload).map_err(NoiseError::from)
    }

    pub fn receive(&self) -> Result<Vec<u8>, NoiseError> {
        self.inner.receive().map_err(NoiseError::from)
    }

    pub fn close(&self) -> Result<(), NoiseError> {
        self.inner.close().map_err(|e| NoiseError::Transport {
            message: e.to_string(),
        })
    }
}

// ── dial_xx / accept_xx ───────────────────────────────────────────────────────

pub fn dial_xx(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
) -> Result<Arc<SessionXx>, NoiseError> {
    let wrapper = TransportWrapper { inner: transport };
    let core = core_dial_xx(wrapper, keypair.to_keypair()?).map_err(NoiseError::from)?;
    Ok(Arc::new(SessionXx {
        inner: Arc::new(core),
    }))
}

pub fn accept_xx(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
) -> Result<Arc<SessionXx>, NoiseError> {
    let wrapper = TransportWrapper { inner: transport };
    let core = core_accept_xx(wrapper, keypair.to_keypair()?).map_err(NoiseError::from)?;
    Ok(Arc::new(SessionXx {
        inner: Arc::new(core),
    }))
}

// ── dial_nk / accept_nk ───────────────────────────────────────────────────────

pub fn dial_nk(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
    remote_static: Vec<u8>,
) -> Result<Arc<SessionNk>, NoiseError> {
    if remote_static.len() != 32 {
        return Err(NoiseError::Transport {
            message: format!(
                "noise: remote_static must be 32 bytes, got {}",
                remote_static.len()
            ),
        });
    }
    let mut rs = [0u8; 32];
    rs.copy_from_slice(&remote_static);
    let wrapper = TransportWrapper { inner: transport };
    let core = core_dial_nk(wrapper, keypair.to_keypair()?, rs).map_err(NoiseError::from)?;
    Ok(Arc::new(SessionNk {
        inner: Arc::new(core),
    }))
}

pub fn accept_nk(
    transport: Arc<dyn NoiseTransport>,
    keypair: KeypairRecord,
) -> Result<Arc<SessionNk>, NoiseError> {
    let wrapper = TransportWrapper { inner: transport };
    let core = core_accept_nk(wrapper, keypair.to_keypair()?).map_err(NoiseError::from)?;
    Ok(Arc::new(SessionNk {
        inner: Arc::new(core),
    }))
}

// ── FFI unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_keypair_rejects_short_private_key() {
        let bad = KeypairRecord {
            private_key: vec![0u8; 16], // too short
            public_key: vec![0u8; 32],
        };
        assert!(
            matches!(bad.to_keypair(), Err(NoiseError::Transport { .. })),
            "expected Transport error for short private_key"
        );
    }

    #[test]
    fn to_keypair_rejects_short_public_key() {
        let bad = KeypairRecord {
            private_key: vec![0u8; 32],
            public_key: vec![0u8; 10], // too short
        };
        assert!(
            matches!(bad.to_keypair(), Err(NoiseError::Transport { .. })),
            "expected Transport error for short public_key"
        );
    }

    #[test]
    fn to_keypair_rejects_long_keys() {
        let bad = KeypairRecord {
            private_key: vec![0u8; 33], // too long
            public_key: vec![0u8; 32],
        };
        assert!(
            matches!(bad.to_keypair(), Err(NoiseError::Transport { .. })),
            "expected Transport error for long private_key"
        );
    }

    #[test]
    fn to_keypair_accepts_valid_32_byte_keys() {
        let kp = generate_keypair();
        assert!(kp.to_keypair().is_ok(), "valid 32-byte keys must succeed");
    }
}
