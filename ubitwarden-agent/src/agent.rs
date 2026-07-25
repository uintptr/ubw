use std::{io, ops::Deref, path::PathBuf};

use std::os::unix::net::UnixStream;
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

#[cfg(target_os = "linux")]
pub fn create_socket_name() -> Result<PathBuf> {
    let username = whoami::username()?;
    let name = format!("\0ubw_{username}");
    Ok(PathBuf::from(name))
}

#[cfg(not(target_os = "linux"))]
pub fn create_socket_name() -> Result<PathBuf> {
    use std::fs;
    use ubitwarden::error::Error;

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

impl UBWAgent {
    pub fn client() -> Result<Self> {
        let socket_name = create_socket_name()?;

        let unix_stream = UnixStream::connect(socket_name)?;
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
