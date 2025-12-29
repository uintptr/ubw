use anyhow::{Result, bail};
use ubitwarden::{
    api::BwApi,
    api_types::{BwCipher, BwCipherData},
    session::BwSession,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::commands::auth::login_from_cache;

fn display_ssh_keys(session: &BwSession, keys: &[BwCipher]) -> Result<()> {
    for c in keys {
        if let BwCipherData::Ssh(ssh) = &c.data {
            let public_key: String = session.decrypt(&ssh.public_key)?.try_into()?;

            println!("{public_key}");
        }
    }

    Ok(())
}

pub async fn command_ssh_keys() -> Result<()> {
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::new().await?;

    let session = agent.load_session().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let keys = api.ssh_keys(&session.auth).await?;

    display_ssh_keys(&session, &keys)
}
