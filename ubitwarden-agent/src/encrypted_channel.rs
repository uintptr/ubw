use std::{
    pin::Pin,
    task::{Context, Poll},
};

use log::info;
use orion::{
    aead,
    kex::{EphemeralClientSession, EphemeralServerSession, PublicKey, SessionKeys},
};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use ubitwarden::error::{Error, Result};

use crate::messages::{ChannelRequest, ChannelResponse};

use crate::channel::AgentChannelTrait;

#[derive(Debug)]
pub struct EncryptedChannel<S> {
    stream: S,
    session_keys: SessionKeys,
    read_buf: Vec<u8>,
    decrypted_buf: Vec<u8>,
    expected_len: Option<u32>,
}

impl<S> EncryptedChannel<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    pub async fn listen(mut stream: S) -> Result<Self> {
        let session_server = EphemeralServerSession::new()?;
        let server_public_key = session_server.public_key();

        let server_public_key_slice = server_public_key.to_bytes();

        //
        // read the client's public key
        //
        let req: ChannelRequest = ChannelRequest::read(&mut stream).await?;

        let ChannelRequest::Hello {
            public_key: peer_public_key,
        } = req
        else {
            return Err(Error::KeyAgreementFailure);
        };

        //
        // Send our public key
        //
        let resp = ChannelResponse::Hello {
            public_key: server_public_key_slice.to_vec(),
        };

        resp.write(&mut stream).await?;

        let client_public_key = PublicKey::from_slice(&peer_public_key)?;
        let session_keys: SessionKeys = session_server.establish_with_client(&client_public_key)?;

        info!("server handshake completed");

        Ok(Self {
            stream,
            session_keys,
            read_buf: Vec::new(),
            decrypted_buf: Vec::new(),
            expected_len: None,
        })
    }

    pub async fn connect(mut stream: S) -> Result<Self> {
        let session_client = EphemeralClientSession::new()?;
        let client_public_key = session_client.public_key().clone();

        let client_public_key_slice = client_public_key.to_bytes();

        //
        // Send out public key across
        //
        let msg = ChannelRequest::Hello {
            public_key: client_public_key_slice.to_vec(),
        };
        msg.write(&mut stream).await?;

        //
        // read the server's public key
        //
        let res: ChannelResponse = ChannelResponse::read(&mut stream).await?;

        let ChannelResponse::Hello {
            public_key: peer_public_key,
        } = res
        else {
            return Err(Error::KeyAgreementFailure);
        };

        let server_public_key = PublicKey::from_slice(&peer_public_key)?;
        let session_keys: SessionKeys = session_client.establish_with_server(&server_public_key)?;

        info!("client handshake completed");

        Ok(Self {
            stream,
            session_keys,
            read_buf: Vec::new(),
            decrypted_buf: Vec::new(),
            expected_len: None,
        })
    }
}

impl<S> AsyncWrite for EncryptedChannel<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let cipher = aead::seal(self.session_keys.transport(), buf).map_err(io::Error::other)?;

        let len: u32 = cipher.len().try_into().map_err(io::Error::other)?;

        let mut framed = Vec::with_capacity(cipher.len().saturating_add(4));
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&cipher);

        match Pin::new(&mut self.stream).poll_write(cx, &framed) {
            Poll::Ready(Ok(n)) if n == framed.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::other("partial write"))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S> AsyncRead for EncryptedChannel<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            // If we have decrypted data waiting, return it first
            if !self.decrypted_buf.is_empty() {
                let to_copy = std::cmp::min(buf.remaining(), self.decrypted_buf.len());
                if let Some(slice) = self.decrypted_buf.get(..to_copy) {
                    buf.put_slice(slice);
                    self.decrypted_buf.drain(..to_copy);
                    return Poll::Ready(Ok(()));
                }
            }

            // Try to parse length header if we don't have it yet
            if self.expected_len.is_none()
                && self.read_buf.len() >= 4
                && let Some(header) = self.read_buf.get(..4)
                && let Ok(len_bytes) = <[u8; 4]>::try_from(header)
            {
                self.expected_len = Some(u32::from_be_bytes(len_bytes));
                self.read_buf.drain(..4);
            }

            // Try to decrypt if we have enough data
            if let Some(expected_len) = self.expected_len
                && self.read_buf.len() >= expected_len as usize
            {
                let cipher_len = expected_len as usize;
                let Some(cipher) = self.read_buf.get(..cipher_len) else {
                    continue;
                };

                let plaintext = aead::open(self.session_keys.receiving(), cipher)
                    .map_err(|_| io::Error::other("decryption failed"))?;

                self.read_buf.drain(..cipher_len);
                self.expected_len = None;

                // Copy what we can to output, buffer the rest
                let to_copy = std::cmp::min(buf.remaining(), plaintext.len());
                if let Some(slice) = plaintext.get(..to_copy) {
                    buf.put_slice(slice);
                }
                if let Some(remaining) = plaintext.get(to_copy..)
                    && !remaining.is_empty()
                {
                    self.decrypted_buf.extend_from_slice(remaining);
                }

                return Poll::Ready(Ok(()));
            }

            // Need more data - read from the underlying stream
            let mut temp_buf = [0u8; 4096];
            let mut temp_read_buf = ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.stream).poll_read(cx, &mut temp_read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let bytes_read = temp_read_buf.filled();
                    if bytes_read.is_empty() {
                        // EOF
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.extend_from_slice(bytes_read);
                    // Loop back to try parsing/decrypting with new data
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rstaples::logging::StaplesLogger;
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn test_handshake() {
        StaplesLogger::new()
            .with_colors()
            .with_log_level(log::LevelFilter::Debug)
            .start();

        let (client_stream, server_stream) = duplex(1024);

        let (server, client) = tokio::join!(
            EncryptedChannel::listen(server_stream),
            EncryptedChannel::connect(client_stream)
        );

        assert!(client.is_ok());
        assert!(server.is_ok());

        let client = client.unwrap();
        let server = server.unwrap();

        assert_eq!(client.session_keys.receiving(), server.session_keys.transport());
        assert_eq!(client.session_keys.transport(), server.session_keys.receiving());
    }
}
