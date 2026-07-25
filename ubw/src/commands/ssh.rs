use anyhow::{Result, bail};
use log::error;
use ubitwarden::{
    api::BwApi,
    api_types::{BwCipher, BwCipherData},
    session::BwSession,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::{
    commands::auth::login_from_cache,
    common::{UNREADABLE, decrypt_field},
};

fn display_ssh_keys(session: &BwSession, keys: &[BwCipher]) {
    for c in keys {
        if let BwCipherData::Ssh(ssh) = &c.data {
            //
            // Nothing to print without the key itself, so skip this one and
            // keep going through the rest
            //
            let public_key = match decrypt_field(session, c, "public key", &ssh.public_key) {
                Ok(public_key) => public_key,
                Err(e) => {
                    error!("{e:#}");
                    continue;
                }
            };

            let name = if let Some(encrypted_name) = &ssh.name {
                match decrypt_field(session, c, "name", encrypted_name) {
                    Ok(name) => name,
                    Err(e) => {
                        error!("{e:#}");
                        UNREADABLE.to_string()
                    }
                }
            } else {
                String::new()
            };

            println!("{public_key} {name}");
        }
    }
}

pub fn command_ssh_keys() -> Result<()> {
    if let Err(e) = login_from_cache() {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client()?;

    let session = agent.session_load()?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let keys = api.ssh_keys(&session.auth)?;

    display_ssh_keys(&session, &keys);

    Ok(())
}
