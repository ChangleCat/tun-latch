//! Four-byte big-endian length followed by UTF-8 JSON, bounded before allocating a payload.

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::IpcError;

/// Largest accepted payload; applies in both directions.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Read exactly one bounded message. EOF, zero length and malformed JSON are errors.
pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, IpcError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(IpcError::FrameSize(length));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Write one message, rejecting oversized output before sending any bytes.
pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), IpcError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameSize(payload.len()));
    }
    let length = u32::try_from(payload.len()).map_err(|_| IpcError::FrameSize(payload.len()))?;
    writer.write_u32(length).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_lengths_before_waiting_for_payload() -> Result<(), Box<dyn std::error::Error>>
    {
        for length in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
            let bytes = length.to_be_bytes();
            assert!(matches!(
                read::<_, serde_json::Value>(&mut bytes.as_slice()).await,
                Err(IpcError::FrameSize(_))
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_truncation_and_malformed_payloads() {
        for bytes in [vec![0, 0], vec![0, 0, 0, 5, b'{'], vec![0, 0, 0, 1, 0xff]] {
            assert!(
                read::<_, serde_json::Value>(&mut bytes.as_slice())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn handles_partial_reads() -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let value = serde_json::json!({"message": "bounded"});
        let (written, read) = tokio::join!(
            write(&mut writer, &value),
            read::<_, serde_json::Value>(&mut reader),
        );
        written?;
        assert_eq!(read?, value);
        Ok(())
    }
}
