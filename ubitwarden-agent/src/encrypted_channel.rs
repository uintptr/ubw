use std::{
    pin::Pin,
    task::{Context, Poll},
};

use ring::{
    agreement,
    hkdf::{self, HKDF_SHA256, KeyType},
    rand,
};

use log::error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use ubitwarden::error::{Error, Result};

use crate::messages::{ChannelRequest, UBWChannelMessage};

use crate::channel::AgentChannelTrait;

const SESSION_KEY_LEN: usize = 32;

struct SessionKeyType;

impl KeyType for SessionKeyType {
    fn len(&self) -> usize {
        SESSION_KEY_LEN
    }
}

#[derive(Debug)]
pub struct EncryptedChannel<S> {
    stream: S,
    session_key: [u8; SESSION_KEY_LEN],
}

impl<S> EncryptedChannel<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    pub async fn listen(mut stream: S) -> Result<Self> {
        let rng = rand::SystemRandom::new();

        let my_private_key = match agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng) {
            Ok(v) => v,
            Err(e) => {
                error!("{e}");
                return Err(Error::KeyGenFailure);
            }
        };

        let my_public_key = my_private_key.compute_public_key().map_err(|_| Error::KeyGenFailure)?;

        //
        // read the client's public key
        //
        let req: UBWChannelMessage = UBWChannelMessage::read(&mut stream).await?;

        let ChannelRequest::Hello {
            public_key: peer_public_key_bytes,
        } = req.message
        else {
            return Err(Error::CommandInvalid);
        };

        //
        // send our public key
        //
        let hello = ChannelRequest::Hello {
            public_key: my_public_key.as_ref().into(),
        };

        UBWChannelMessage::new(hello).write(&mut stream).await?;

        //
        // derive session key
        //
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key_bytes.clone());

        let session_key = agreement::agree_ephemeral(my_private_key, &peer_public_key, |key_material| {
            // Role-based ordering: initiator's public key first, responder's second
            // We are the responder, so: initiator (peer) || responder (us)
            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(&peer_public_key_bytes);
            info.extend_from_slice(my_public_key.as_ref());

            let salt = hkdf::Salt::new(HKDF_SHA256, b"ubw-agent-channel");
            let prk = salt.extract(key_material);
            let info_refs: &[&[u8]] = &[&info];
            let okm = prk.expand(info_refs, SessionKeyType).expect("HKDF expand failed");

            let mut session_key = [0u8; SESSION_KEY_LEN];
            okm.fill(&mut session_key).expect("HKDF fill failed");

            session_key
        })
        .map_err(|_| Error::KeyAgreementFailure)?;

        Ok(EncryptedChannel { stream, session_key })
    }

    pub async fn connect(mut stream: S) -> Result<Self> {
        let rng = rand::SystemRandom::new();

        let my_private_key = match agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng) {
            Ok(v) => v,
            Err(e) => {
                error!("{e}");
                return Err(Error::KeyGenFailure);
            }
        };

        let my_public_key = my_private_key.compute_public_key().map_err(|_| Error::KeyGenFailure)?;

        //
        // send the hello message
        //
        let hello = ChannelRequest::Hello {
            public_key: my_public_key.as_ref().into(),
        };
        UBWChannelMessage::new(hello).write(&mut stream).await?;

        let res: UBWChannelMessage = UBWChannelMessage::read(&mut stream).await?;

        let ChannelRequest::Hello {
            public_key: peer_public_key_bytes,
        } = res.message
        else {
            return Err(Error::CommandInvalid);
        };

        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key_bytes.clone());

        let session_key = agreement::agree_ephemeral(my_private_key, &peer_public_key, |key_material| {
            // Role-based ordering: initiator's public key first, responder's second
            // We are the initiator, so: initiator (us) || responder (peer)
            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(my_public_key.as_ref());
            info.extend_from_slice(&peer_public_key_bytes);

            let salt = hkdf::Salt::new(HKDF_SHA256, b"ubw-agent-channel");
            let prk = salt.extract(key_material);
            let info_refs: &[&[u8]] = &[&info];
            let okm = prk.expand(info_refs, SessionKeyType).expect("HKDF expand failed");

            let mut session_key = [0u8; SESSION_KEY_LEN];
            okm.fill(&mut session_key).expect("HKDF fill failed");

            session_key
        })
        .map_err(|_| Error::KeyAgreementFailure)?;

        Ok(EncryptedChannel { stream, session_key })
    }
}

impl<S> AsyncWrite for EncryptedChannel<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // For a simple passthrough:
        Pin::new(&mut self.stream).poll_write(cx, buf)

        // For actual encryption, you'd:
        // 1. Encrypt the data in `buf`
        // 2. Write the encrypted data to the stream
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
        // For a simple passthrough (no encryption on raw reads):
        Pin::new(&mut self.stream).poll_read(cx, buf)

        // For actual encryption, you'd need to:
        // 1. Read encrypted data into an internal buffer
        // 2. Decrypt it
        // 3. Copy decrypted data to `buf`
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

        assert_eq!(client.session_key, server.session_key);
    }
}
