use std::{ops::Deref, path::PathBuf};

use tokio::net::UnixStream;
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
use log::{error, warn};

pub struct UBWAgent {
    stream: EncryptedChannel<UnixStream>,
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
    pub async fn client() -> Result<Self> {
        let socket_name = create_socket_name()?;

        let unix_stream = UnixStream::connect(socket_name).await?;
        let stream = EncryptedChannel::connect(unix_stream).await?;

        Ok(Self { stream })
    }

    pub async fn server(client: UnixStream) -> Result<Self> {
        let stream = EncryptedChannel::listen(client).await?;

        Ok(Self { stream })
    }

    pub async fn quit(&mut self) -> Result<bool> {
        let msg = ChannelRequest::Stop;

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    //
    // Session
    //
    pub async fn delete_session(&mut self) -> Result<bool> {
        let msg = ChannelRequest::SessionDelete;

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub async fn session_fetch(&mut self) -> Result<BwSession> {
        let msg = ChannelRequest::SessionFetch;

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::SessionFetch(session_data) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        let session: BwSession = session_data.try_into()?;

        Ok(session)
    }

    pub async fn session_store(&mut self, session: &BwSession) -> Result<bool> {
        let msg = ChannelRequest::SessionStore(session.deref().clone());

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub async fn session_load(&mut self) -> Result<BwSession> {
        if let Ok(session) = self.session_fetch().await {
            if session.expired()? {
                warn!("session expired");
                //
                // see if the session is still usable ( expired )
                //
            } else {
                return Ok(session);
            }
        }

        warn!("no session not found");

        let creds = self.credentials_fetch().await?;

        //
        // Either it didn't exist or it was expired. let's rejoin
        //
        let api = BwApi::new(&creds.email, &creds.server_url)?;

        let auth = api.auth(&creds.password).await?;

        let session = BwSession::new(&creds, &auth)?;

        // best effort. not fatal since we got what we wanted
        if let Err(e) = self.session_store(&session).await {
            error!("Unable to store session: ({e})");
        }

        Ok(session)
    }

    //
    // Credentials
    //
    pub async fn credentials_delete(&mut self) -> Result<bool> {
        let msg = ChannelRequest::CredentialsDelete;

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub async fn credentials_fetch(&mut self) -> Result<BwCredentials> {
        let msg = ChannelRequest::CredentialsFetch;

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::CredentialsFetch(credentials) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(credentials)
    }

    pub async fn credentials_store<E, P, U>(&mut self, email: E, server_url: U, password: P) -> Result<bool>
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

        let res = send_message(&mut self.stream, msg).await?;

        let ChannelResponse::Status(success) = res else {
            return Err(Error::InvalidCommandResponse);
        };

        Ok(success)
    }

    pub async fn get_request(&mut self) -> Result<ChannelRequest> {
        ChannelRequest::read(&mut self.stream).await
    }

    pub async fn send_response(&mut self, resp: ChannelResponse) -> Result<()> {
        resp.write(&mut self.stream).await
    }
}
