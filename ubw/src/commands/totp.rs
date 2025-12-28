use anyhow::{Result, bail};
use ubitwarden::{api::BwApi, crypto::BwCrypt};

use crate::commands::{agent::utils::load_session, auth::login_from_cache};

pub async fn command_totp<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let encrypted_totp = api.totp(&session.auth, id.as_ref()).await?;

    let totp = crypt.parse_totp(encrypted_totp)?;

    println!("totp: {totp}");

    Ok(())
}
