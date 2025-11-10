use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::message::Message;

/// Maximum allowed serialized message size (512 KiB).
const MAX_FRAME_LEN: usize = 512 * 1024;

fn bincode_to_io_error(err: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Write a serialized `Message` preceded by a 4-byte length prefix.
pub async fn write_message(stream: &mut TcpStream, message: &Message) -> io::Result<()> {
    let payload =
        bincode::serialize(message).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    write_frame(stream, &payload).await
}

/// Read the next length-prefixed `Message` from the stream.
pub async fn read_message(stream: &mut TcpStream) -> io::Result<Message> {
    let payload = read_frame(stream).await?;
    bincode::deserialize(&payload).map_err(bincode_to_io_error)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot write empty frame",
        ));
    }
    if payload.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum length",
        ));
    }

    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}
