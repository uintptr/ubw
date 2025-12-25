use anyhow::{Result, bail};
use ubitwarden::{api::BwApi, crypto::BwCrypt, error::Error};

use crate::{commands::login::login_from_cache, common::load_session};

pub async fn command_password<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.cipher(&session.auth, id.as_ref()).await?;

    if let Some(login) = cipher.login {
        if let Some(encrypted_password) = login.password {
            let pass: String = crypt.decrypt(&encrypted_password)?.try_into()?;
            println!("{pass}");
            Ok(())
        } else {
            Err(Error::PasswordNotFound.into())
        }
    } else {
        Err(Error::LoginNotFound.into())
    }
}
