use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};
use std::net::TcpStream;
use std::io::{Read, Write};

pub fn send_json<T: Serialize>(stream: &mut TcpStream, data: &T) -> Result<()> {
    let encoded = serde_json::to_vec(data)?;
    let len = encoded.len() as u32;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&encoded)?;
    Ok(())
}

pub fn recv_json<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    Ok(serde_json::from_slice(&buf)?)
}
