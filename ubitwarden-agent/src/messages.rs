use std::fmt::Display;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ubitwarden::{credentials::BwCredentials, error::Result, session::BwSessionData};

use crate::channel::AgentChannelTrait;

#[derive(Serialize, Deserialize)]
pub enum ChannelRequest {
    Hello { public_key: Vec<u8> },
    Stop,

    // session
    SessionDelete,
    SessionFetch,
    SessionStore(BwSessionData),

    // credentials
    CredentialsDelete,
    CredentialsFetch,
    CredentialsStore(BwCredentials),
}

impl Display for ChannelRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hello { .. } => write!(f, "Hello"),
            Self::Stop => write!(f, "Stop"),
            Self::SessionDelete => write!(f, "SessionDelete"),
            Self::SessionFetch => write!(f, "SessionFetch"),
            Self::SessionStore(_) => write!(f, "SessionStore"),
            Self::CredentialsDelete => write!(f, "CredentialsDelete"),
            Self::CredentialsFetch => write!(f, "CredentialsFetch"),
            Self::CredentialsStore(_) => write!(f, "CredentialsStore"),
        }
    }
}

impl AgentChannelTrait for ChannelRequest {}

#[derive(Serialize, Deserialize)]
pub enum ChannelResponse {
    Status(bool),
    Error(String),
    Hello { public_key: Vec<u8> },
    SessionFetch(BwSessionData),
    CredentialsFetch(BwCredentials),
}

impl Display for ChannelResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(f, "Status({status})"),
            Self::Error(err) => write!(f, "Error({err})"),
            Self::Hello { .. } => write!(f, "Hello"),
            Self::SessionFetch(_) => write!(f, "SessionFetch"),
            Self::CredentialsFetch(_) => write!(f, "CredentialsFetch"),
        }
    }
}

impl AgentChannelTrait for ChannelResponse {}

pub async fn send_message<S>(stream: &mut S, message: ChannelRequest) -> Result<ChannelResponse>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    message.write(stream).await?;

    let req: ChannelResponse = ChannelResponse::read(stream).await?;

    Ok(req)
}
