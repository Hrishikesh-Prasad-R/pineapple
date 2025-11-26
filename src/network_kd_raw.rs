use anyhow::Result;
use std::io::{Read, Write};
use std::net::TcpStream;

/// RAW AES-GCM messages:
///     [12-byte nonce][ciphertext...]
///
/// No length prefix. We use TCP packet boundaries directly.
/// Very simple, very fast.
pub fn send_raw(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

pub fn recv_raw(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read until EOF or until kernel returns available packet size.
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
