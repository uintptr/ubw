use crate::{commands::auth::login_from_cache, common::decrypt_field};
use anyhow::{Context, Result, bail};
use std::io::{Write, stdout};
use ubitwarden::{api::BwApi, api_types::BwCipherData, error::Error};
use ubitwarden_agent::agent::UBWAgent;

pub fn command_totp<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache() {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client()?;

    let session = agent.session_load()?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.login(&session.auth, id.as_ref())?;

    if let BwCipherData::Login(login) = &cipher.data
        && let Some(encrypted_totp) = &login.totp
    {
        //
        // decrypt_field first: it names the entry and the likely cause, which
        // parse_totp can't do
        //
        decrypt_field(&session, &cipher, "totp", encrypted_totp)?;

        let totp = session
            .parse_totp(encrypted_totp)
            .with_context(|| format!("could not read the totp of cipher {}", cipher.id))?;
        println!("totp: {totp}");
    }

    Ok(())
}

pub fn command_password<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache() {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client()?;

    let session = agent.session_load()?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.cipher(&session.auth, id.as_ref())?;

    if let BwCipherData::Login(login) = &cipher.data {
        if let Some(encrypted_password) = &login.password {
            let pass = decrypt_field(&session, &cipher, "password", encrypted_password)?;

            let mut stdout = stdout();
            // can't safely use the println! macro
            stdout.write_all(pass.as_bytes())?;
            stdout.flush()?;
            Ok(())
        } else {
            Err(Error::PasswordNotFound.into())
        }
    } else {
        Err(Error::LoginNotFound.into())
    }
}
