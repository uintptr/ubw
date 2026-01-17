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

            let name = if let Some(encrypted_name) = &ssh.name {
                let plain_name: String = session.decrypt(encrypted_name)?.try_into()?;
                plain_name
            } else {
                String::new()
            };
            println!("{public_key} {name}");
        }
    }

    Ok(())
}

pub async fn command_ssh_keys() -> Result<()> {
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client().await?;

    let session = agent.session_load().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let keys = api.ssh_keys(&session.auth).await?;

    display_ssh_keys(&session, &keys)
}
