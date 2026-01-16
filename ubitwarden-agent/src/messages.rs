use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ubitwarden::{credentials::BwCredentials, error::Result, session::BwSessionData};

use crate::channel::AgentChannelTrait;

#[derive(Serialize, Deserialize)]
pub enum ChannelRequest {
    Noop,
    Error { message: String },
    Hello { public_key: Vec<u8> },
    Quit,

    // session
    SessionDelete,
    SessionFetch,
    SessionStore(BwSessionData),

    // credentials
    CredentialsDelete,
    CredentialsFetch,
    CredentialsStore(BwCredentials),
}

#[derive(Serialize, Deserialize)]
pub enum ChannelResponse {
    Status(bool),
    Hello { public_key: Vec<u8> },
    SessionFetch(BwSessionData),
    CredentialsFetch(BwCredentials),
}

#[derive(Serialize, Deserialize)]
pub struct UBWChannelMessage {
    pub message: ChannelRequest,
}

impl AgentChannelTrait for UBWChannelMessage {}

impl UBWChannelMessage {
    pub fn new(message: ChannelRequest) -> Self {
        Self { message }
    }
}

pub async fn send_message<S>(stream: &mut S, message: ChannelRequest) -> Result<ChannelResponse>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    UBWChannelMessage::new(message).write(stream).await?;

    let req: ChannelResponse = UBWChannelMessage::read(stream).await?;

    Ok(req)
}
