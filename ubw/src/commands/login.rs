use crate::commands::auth::login_from_cache;
use anyhow::{Result, bail};
use tokio::io::{AsyncWriteExt, stdout};
use ubitwarden::{api::BwApi, api_types::BwCipherData, error::Error};
use ubitwarden_agent::agent::UBWAgent;

pub async fn command_totp<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client().await?;

    let session = agent.session_load().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.login(&session.auth, id.as_ref()).await?;

    if let BwCipherData::Login(login) = cipher.data
        && let Some(encrypted_totp) = login.totp
    {
        let totp = session.parse_totp(encrypted_totp)?;
        println!("totp: {totp}");
    }

    Ok(())
}

pub async fn command_password<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client().await?;

    let session = agent.session_load().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.cipher(&session.auth, id.as_ref()).await?;

    if let BwCipherData::Login(login) = cipher.data {
        if let Some(encrypted_password) = login.password {
            let pass: String = session.decrypt(&encrypted_password)?.try_into()?;

            let mut stdout = stdout();
            // can't safely use the println! macro
            stdout.write_all(pass.as_bytes()).await?;
            stdout.flush().await?;
            Ok(())
        } else {
            Err(Error::PasswordNotFound.into())
        }
    } else {
        Err(Error::LoginNotFound.into())
    }
}
