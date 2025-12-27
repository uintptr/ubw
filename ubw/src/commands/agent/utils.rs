use std::env;

use anyhow::Result;
use dialoguer::Password;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use ubitwarden::{api::BwApi, credentials::BwCredentials, session::BwSession};

use log::{error, info, warn};

////////////////////////////////////////////////////////////////////////////////
// PRIVATE
////////////////////////////////////////////////////////////////////////////////
async fn store_data<K, V>(key: K, value: V) -> Result<()>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let command = format!("write:{}:{}", key.as_ref(), value.as_ref());

    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;

    write_string(&mut stream, command).await
}

async fn fetch_data(key: &str) -> Result<String> {
    let command = format!("read:{key}");

    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;

    write_string(&mut stream, command).await?;
    read_string(&mut stream).await
}

////////////////////////////////////////////////////////////////////////////////
// PROTECTED
////////////////////////////////////////////////////////////////////////////////
pub(crate) fn create_socket_name() -> String {
    let username = whoami::username();
    format!("\0ubw_{username}")
}

pub(crate) async fn read_string(stream: &mut UnixStream) -> Result<String> {
    let len = stream.read_i32().await?;
    let len: usize = len.try_into()?;

    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf).await?;

    let s = String::from_utf8(buf)?;

    Ok(s)
}

pub(crate) async fn write_string<S>(stream: &mut UnixStream, input: S) -> Result<()>
where
    S: AsRef<str>,
{
    let len = input.as_ref().len();
    let len: i32 = len.try_into()?;

    stream.write_i32(len).await?;

    stream.write_all(input.as_ref().as_bytes()).await?;

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub async fn ping_agent() -> Result<()> {
    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;
    write_string(&mut stream, "ping").await
}

pub async fn stop_agent() -> Result<()> {
    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;
    write_string(&mut stream, "stop").await
}

pub async fn store_user_data<D, K>(key: K, data: D) -> Result<()>
where
    D: AsRef<str>,
    K: AsRef<str>,
{
    store_data(key, data).await
}

pub async fn fetch_user_data<K>(key: K) -> Result<String>
where
    K: AsRef<str>,
{
    fetch_data(key.as_ref()).await
}

async fn fetch_session() -> Result<BwSession> {
    let data = fetch_user_data("session").await?;
    let session: BwSession = serde_json::from_str(&data)?;
    Ok(session)
}

async fn store_session(session: &BwSession) -> Result<()> {
    let encoded_session = serde_json::to_string(session)?;
    store_user_data("session", encoded_session).await?;
    Ok(())
}

pub async fn fetch_credentials() -> Result<BwCredentials> {
    let data = fetch_user_data("credentials").await?;
    let creds: BwCredentials = serde_json::from_str(&data)?;
    info!("found credentials for {}", creds.email);
    Ok(creds)
}

pub async fn store_credentials<E, U>(email: E, server_url: U) -> Result<()>
where
    E: AsRef<str>,
    U: AsRef<str>,
{
    let api = BwApi::new(&email, &server_url)?;

    let password = loop {
        //
        // helps with testing but not recommended
        //
        let password = if let Ok(password) = env::var("UBW_PASSWORD") {
            info!("using UBW_PASSWORD=***********");
            password.clone()
        } else {
            let prompt = format!("Password for {}", email.as_ref());
            Password::new().with_prompt(prompt).interact()?
        };

        //
        // try them
        //
        if let Err(e) = api.auth(&password).await {
            error!("auth failure {e}");
            continue;
        }

        break password;
    };

    let creds = BwCredentials {
        email: email.as_ref().to_string(),
        password,
        server_url: server_url.as_ref().to_string(),
    };

    let encoded_creds = serde_json::to_string(&creds)?;

    store_user_data("credentials", encoded_creds).await?;

    Ok(())
}

pub async fn load_session() -> Result<BwSession> {
    if let Ok(session) = fetch_session().await {
        if session.expired()? {
            warn!("session expired");
            //
            // see if the session is still usable ( expired )
            //
        } else {
            return Ok(session);
        }
    }

    let creds = fetch_credentials().await?;

    //
    // Either it didn't exist or it was expired. let's rejoin
    //
    let api = BwApi::new(&creds.email, &creds.server_url)?;

    let auth = api.auth(&creds.password).await?;

    let session = BwSession::new(&creds, &auth)?;

    // best effort. not fatal since we got what we wanted
    if let Err(e) = store_session(&session).await {
        error!("Unable to store session: ({e})");
    }

    Ok(session)
}
