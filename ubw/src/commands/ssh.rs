use anyhow::{Result, bail};
use ubitwarden::{
    api::BwApi,
    api_types::{BwCipher, BwCipherData},
    crypto::BwCrypt,
};

use crate::commands::{agent::utils::load_session, login::login_from_cache};

fn display_ssh_keys(crypt: &BwCrypt, keys: &[BwCipher]) -> Result<()> {
    for c in keys {
        if let BwCipherData::Ssh(ssh) = &c.data {
            let public_key: String = crypt.decrypt(&ssh.public_key)?.try_into()?;

            println!("{public_key}");
        }
    }

    Ok(())
}

pub async fn command_ssh_keys() -> Result<()> {
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let keys = api.ssh_keys(&session.auth).await?;

    display_ssh_keys(&crypt, &keys)
}
