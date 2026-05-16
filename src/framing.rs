use std::io::{self, Read, Write};

/// Max plaintext per snow transport message: 65535 (max frame) - 16 (AEAD tag).
pub(crate) const MAX_PLAINTEXT_SIZE: usize = 65519;

/// Writes data to w with a 2-byte big-endian length prefix.
pub(crate) fn write_frame(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    if data.len() > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("noise: frame too large: {} bytes", data.len()),
        ));
    }
    let len = data.len() as u16;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

/// Reads a 2-byte big-endian length prefix then the body from r.
pub(crate) fn read_frame(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    r.read_exact(&mut header)?;
    let size = u16::from_be_bytes(header) as usize;
    let mut body = vec![0u8; size];
    r.read_exact(&mut body)?;
    Ok(body)
}
