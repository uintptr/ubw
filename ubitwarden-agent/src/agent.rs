use std::{io, ops::Deref, path::PathBuf};

use std::os::unix::net::{UnixListener, UnixStream};
use ubitwarden::{
    api::BwApi,
    credentials::BwCredentials,
    error::{Error, Result},
    session::BwSession,
};

use crate::{
    channel::AgentChannelTrait,
    encrypted_channel::EncryptedChannel,
    messages::{ChannelRequest, ChannelResponse, send_message},
};
use log::{error, info, warn};

pub struct UBWAgent {
    stream: EncryptedChannel<UnixStream>,
}

/// Did the peer hang up on us?
///
/// A half read message reaches us as an unexpected EOF, and a peer that is
/// already gone shows up as a reset or a broken pipe.
#[must_use]
pub fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

pub const UBW_DATA_DIR: &str = env!("CARGO_PKG_NAME");

/// Where the credentials cache listens.
///
/// Linux gets an abstract socket, which lives in its own namespace rather than
/// on disk. That address can't be spelled as a path, so binding and connecting
/// are platform specific and live here rather than at the call sites.
#[cfg(target_os = "linux")]
mod socket {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    use std::path::PathBuf;

    use ubitwarden::error::Result;

    fn address() -> Result<SocketAddr> {
        let username = whoami::username()?;
        let name = format!("ubw_{username}");

        Ok(SocketAddr::from_abstract_name(name)?)
    }

    pub fn connect() -> Result<UnixStream> {
        Ok(UnixStream::connect_addr(&address()?)?)
    }

    pub fn bind() -> Result<UnixListener> {
        //
        // Nothing to unlink first: the kernel drops an abstract address as soon
        // as the last reference to it goes away.
        //
        Ok(UnixListener::bind_addr(&address()?)?)
    }

    //
    // Nothing to clean up: an abstract address has no file behind it. The
    // Result is here to match the other platform's signature.
    //
    #[allow(clippy::unnecessary_wraps)]
    pub fn cleanup_path() -> Result<Option<PathBuf>> {
        Ok(None)
    }
}

#[cfg(not(target_os = "linux"))]
mod socket {
    use std::fs;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    use ubitwarden::error::{Error, Result};

    use crate::agent::UBW_DATA_DIR;

    fn path() -> Result<PathBuf> {
        let data_dir = dirs::data_dir().ok_or(Error::BasenameError)?;

        let data_dir = data_dir.join(UBW_DATA_DIR);

        // create data dir if it doesn't exist
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)?;
        }

        let username = whoami::username()?;
        let socket_name = format!("ubw_{username}");
        let socket_path = data_dir.join(socket_name);

        Ok(socket_path)
    }

    pub fn connect() -> Result<UnixStream> {
        Ok(UnixStream::connect(path()?)?)
    }

    pub fn bind() -> Result<UnixListener> {
        let socket_path = path()?;

        //
        // A socket left behind by a previous run would make bind fail
        //
        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        Ok(UnixListener::bind(&socket_path)?)
    }

    pub fn cleanup_path() -> Result<Option<PathBuf>> {
        Ok(Some(path()?))
    }
}

/// Connect to the credentials cache.
pub fn connect_cache_socket() -> Result<UnixStream> {
    socket::connect()
}

/// Listen for credentials cache clients.
pub fn bind_cache_socket() -> Result<UnixListener> {
    socket::bind()
}

/// The socket file to remove once we stop listening, on platforms that use one.
pub fn cache_socket_cleanup_path() -> Result<Option<PathBuf>> {
    socket::cleanup_path()
}

impl UBWAgent {
    pub fn client() -> Result<Self> {
        let unix_stream = connect_cache_socket()?;
        let stream = EncryptedChannel::connect(unix_stream)?;

        Ok(Self { stream })
    }

    pub fn server(client: UnixStream) -> Result<Self> {
        let stream = EncryptedChannel::listen(client)?;

        Ok(Self { stream })
    }

    pub fn quit(&mut self) -> Result<bool> {
        let msg = ChannelRequest::Stop;

        //
        // The server acknowledges a stop by going away rather than by
        // answering. Our request made it out the door, otherwise the write
        // would have failed, so losing the connection here means it worked.
        //
        match send_message(&mut self.stream, &msg) {
            Ok(ChannelResponse::Status(success)) => Ok(success),
            Ok(_) => Err(Error::InvalidCommandResponse),
            Err(Error::Io(e)) if is_disconnect(&e) => {
                info!("server closed the connection ({})", e.kind());
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    //
    // Session
    //
    pub fn delete_session(&mut self) -> Result<bool> {
        let msg = ChannelRequest::SessionDelete;

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub fn session_fetch(&mut self) -> Result<BwSession> {
        let msg = ChannelRequest::SessionFetch;

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::SessionFetch(session_data) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        let session: BwSession = session_data.try_into()?;

        Ok(session)
    }

    pub fn session_store(&mut self, session: &BwSession) -> Result<bool> {
        let msg = ChannelRequest::SessionStore(session.deref().clone());

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub fn session_load(&mut self) -> Result<BwSession> {
        if let Ok(session) = self.session_fetch() {
            if session.expired()? {
                warn!("session expired");
                //
                // see if the session is still usable ( expired )
                //
            } else {
                return Ok(session);
            }
        }

        warn!("no session found");

        let creds = self.credentials_fetch()?;

        //
        // Either it didn't exist or it was expired. let's rejoin
        //
        let api = BwApi::new(&creds.email, &creds.server_url)?;

        let auth = api.auth(&creds.password)?;

        let session = BwSession::new(&creds, &auth)?;

        // best effort. not fatal since we got what we wanted
        if let Err(e) = self.session_store(&session) {
            error!("Unable to store session: ({e})");
        }

        Ok(session)
    }

    //
    // Credentials
    //
    pub fn credentials_delete(&mut self) -> Result<bool> {
        let msg = ChannelRequest::CredentialsDelete;

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub fn credentials_fetch(&mut self) -> Result<BwCredentials> {
        let msg = ChannelRequest::CredentialsFetch;

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::CredentialsFetch(credentials) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(credentials)
    }

    pub fn credentials_store<E, P, U>(&mut self, email: E, server_url: U, password: P) -> Result<bool>
    where
        E: Into<String>,
        U: Into<String>,
        P: Into<String>,
    {
        let creds = BwCredentials {
            email: email.into(),
            password: password.into(),
            server_url: server_url.into(),
        };

        let msg = ChannelRequest::CredentialsStore(creds);

        let res = send_message(&mut self.stream, &msg)?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub fn get_request(&mut self) -> Result<ChannelRequest> {
        ChannelRequest::read(&mut self.stream)
    }

    pub fn send_response(&mut self, resp: &ChannelResponse) -> Result<()> {
        resp.write(&mut self.stream)
    }
}
