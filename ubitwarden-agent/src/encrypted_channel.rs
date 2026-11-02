use std::{
    cmp::min,
    io::{self, Read, Write},
};

use log::info;
use orion::{
    aead::{self, SecretKey},
    hazardous::kdf::hkdf::{Hkdf, SHA256},
    kem::{Ciphertext, EncapsulationKey, KP, KeyPair, SharedSecret},
};

use ubitwarden::error::{Error, Result};

use crate::messages::{ChannelRequest, ChannelResponse};

use crate::channel::AgentChannelTrait;

const KDF_SALT: &[u8] = b"ubitwarden-agent encrypted channel v2";
const CLIENT_TO_SERVER_INFO: &[u8] = b"client to server";
const SERVER_TO_CLIENT_INFO: &[u8] = b"server to client";

/// One key per direction, so the two peers never seal with the same key.
#[derive(Debug)]
struct SessionKeys {
    /// Key used to seal outgoing records.
    transport: SecretKey,
    /// Key used to open incoming records.
    receiving: SecretKey,
}

impl SessionKeys {
    fn derive_key(shared_secret: &SharedSecret, info: &[u8]) -> Result<SecretKey> {
        let mut key = [0u8; 32];
        Hkdf::<SHA256>::derive_key(KDF_SALT, shared_secret.unprotected_as_ref(), Some(info), &mut key)?;
        let key = SecretKey::try_from(&key)?;
        Ok(key)
    }

    fn client(shared_secret: &SharedSecret) -> Result<Self> {
        Ok(Self {
            transport: Self::derive_key(shared_secret, CLIENT_TO_SERVER_INFO)?,
            receiving: Self::derive_key(shared_secret, SERVER_TO_CLIENT_INFO)?,
        })
    }

    fn server(shared_secret: &SharedSecret) -> Result<Self> {
        Ok(Self {
            transport: Self::derive_key(shared_secret, SERVER_TO_CLIENT_INFO)?,
            receiving: Self::derive_key(shared_secret, CLIENT_TO_SERVER_INFO)?,
        })
    }

    const fn transport(&self) -> &SecretKey {
        &self.transport
    }

    const fn receiving(&self) -> &SecretKey {
        &self.receiving
    }
}

/// A stream where every [`Write::write`] call is sealed into one
/// length prefixed record, and every record is opened on the way back in.
#[derive(Debug)]
pub struct EncryptedChannel<S> {
    stream: S,
    session_keys: SessionKeys,
    /// Plaintext of the last record read that didn't fit in the caller's buffer.
    decrypted_buf: Vec<u8>,
}

//
// Handshake (X-Wing KEM, the hybrid ML-KEM-768 + X25519 replacement for the
// removed orion::kex):
//
//   client -> server  Hello { encapsulation_key }  fresh ephemeral key pair
//   server -> client  Hello { ciphertext }          encapsulated shared secret
//
// Both sides then derive one key per direction from the shared secret with HKDF-SHA256.
//
impl<S> EncryptedChannel<S>
where
    S: Read + Write,
{
    pub fn listen(mut stream: S) -> Result<Self> {
        //
        // read the client's encapsulation key
        //
        let req: ChannelRequest = ChannelRequest::read(&mut stream)?;

        let ChannelRequest::Hello { encapsulation_key } = req else {
            return Err(Error::KeyAgreementFailure);
        };

        let encapsulation_key = EncapsulationKey::try_from(encapsulation_key.as_slice())?;
        let (shared_secret, ciphertext) = encapsulation_key.encap()?;

        //
        // Send the ciphertext back so the client can decapsulate the same secret
        //
        let resp = ChannelResponse::Hello {
            ciphertext: ciphertext.as_ref().to_vec(),
        };

        resp.write(&mut stream)?;

        let session_keys = SessionKeys::server(&shared_secret)?;

        info!("server handshake completed");

        Ok(Self {
            stream,
            session_keys,
            decrypted_buf: Vec::new(),
        })
    }

    pub fn connect(mut stream: S) -> Result<Self> {
        let key_pair = KeyPair::generate()?;

        //
        // Send our encapsulation key across
        //
        let msg = ChannelRequest::Hello {
            encapsulation_key: key_pair.public().as_ref().to_vec(),
        };
        msg.write(&mut stream)?;

        //
        // read the server's ciphertext
        //
        let res: ChannelResponse = ChannelResponse::read(&mut stream)?;

        let ChannelResponse::Hello { ciphertext } = res else {
            return Err(Error::KeyAgreementFailure);
        };

        let ciphertext = Ciphertext::try_from(ciphertext.as_slice())?;
        let shared_secret = key_pair.decap(&ciphertext)?;
        let session_keys = SessionKeys::client(&shared_secret)?;

        info!("client handshake completed");

        Ok(Self {
            stream,
            session_keys,
            decrypted_buf: Vec::new(),
        })
    }
}

impl<S> Write for EncryptedChannel<S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let cipher = aead::seal(self.session_keys.transport(), buf).map_err(io::Error::other)?;

        let len: u32 = cipher.len().try_into().map_err(io::Error::other)?;

        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&cipher)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S> Read for EncryptedChannel<S>
where
    S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        //
        // Records can decrypt to more than the caller asked for, so serve
        // leftovers first and only pull a new record once we're empty.
        //
        while self.decrypted_buf.is_empty() {
            let mut len_buf = [0u8; 4];

            match self.stream.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }

            let len = usize::try_from(u32::from_be_bytes(len_buf)).map_err(io::Error::other)?;

            let mut cipher = vec![0u8; len];
            self.stream.read_exact(&mut cipher)?;

            self.decrypted_buf = aead::open(self.session_keys.receiving(), &cipher).map_err(|_| {
                io::Error::other("failed to decrypt message - possible data corruption or key mismatch")
            })?;
        }

        let to_copy = min(buf.len(), self.decrypted_buf.len());

        if let Some(dst) = buf.get_mut(..to_copy)
            && let Some(src) = self.decrypted_buf.get(..to_copy)
        {
            dst.copy_from_slice(src);
            self.decrypted_buf.drain(..to_copy);
            Ok(to_copy)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream, thread};

    use rstaples::logging::StaplesLogger;

    use super::*;

    #[test]
    fn test_handshake() {
        StaplesLogger::new()
            .with_colors()
            .with_log_level(log::LevelFilter::Debug)
            .start();

        let pair = UnixStream::pair();
        assert!(pair.is_ok(), "unable to create a socket pair");

        let Ok((client_stream, server_stream)) = pair else {
            return;
        };

        //
        // the handshake is a round trip, so the peers have to run concurrently
        //
        let spawned = thread::Builder::new()
            .name("handshake-server".into())
            .spawn(move || EncryptedChannel::listen(server_stream));
        assert!(spawned.is_ok(), "unable to spawn the server thread");

        let Ok(server_thread) = spawned else {
            return;
        };

        let client = EncryptedChannel::connect(client_stream);

        let joined = server_thread.join();
        assert!(joined.is_ok(), "server thread panicked");

        let Ok(server) = joined else {
            return;
        };

        assert!(client.is_ok());
        assert!(server.is_ok());

        let Ok(client) = client else {
            return;
        };

        let Ok(server) = server else {
            return;
        };

        assert_eq!(client.session_keys.receiving(), server.session_keys.transport());
        assert_eq!(client.session_keys.transport(), server.session_keys.receiving());
    }
}
