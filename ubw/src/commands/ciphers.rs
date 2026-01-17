use anyhow::{Result, bail};
use tabled::{Table, Tabled, settings::Style};
use ubitwarden::{
    api::BwApi,
    api_types::{BwCipher, BwCipherData},
    error::Error,
    session::BwSession,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::commands::auth::login_from_cache;
use clap::Args;
use log::error;

#[derive(Args)]
pub struct CiphersArgs {
    /// filter
    pub filter: Option<String>,
}

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
    totp: String,
}

fn get_totp(sessions: &BwSession, cipher: &BwCipher) -> Result<String> {
    if let BwCipherData::Login(login) = &cipher.data
        && let Some(totp) = &login.totp
    {
        let totp_string = sessions.parse_totp(totp)?;
        Ok(totp_string)
    } else {
        Err(Error::TotpNotFound.into())
    }
}

fn display_ciphers(session: &BwSession, ciphers: &[BwCipher], filter: Option<&String>) -> Result<()> {
    let mut cipher_table = Vec::new();

    for c in ciphers {
        let totp = get_totp(session, c).unwrap_or_default();

        let name: String = session.decrypt(&c.name)?.try_into()?;

        if let Some(filter) = filter
            && !name.contains(filter)
        {
            continue;
        }

        let table_entry = CipherTable {
            id: &c.id,
            ctype: c.cipher_type.to_string(),
            name,
            totp,
        };

        cipher_table.push(table_entry);
    }

    let mut table = Table::new(cipher_table);
    table.with(Style::modern());

    println!("{table}");

    Ok(())
}

pub async fn command_ciphers(args: CiphersArgs) -> Result<()> {
    let mut agent = match login_from_cache().await {
        Ok(v) => v,
        Err(e) => {
            error!("not logged in");
            return Err(e);
        }
    };

    let session = agent.session_load().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let ciphers = api.ciphers(&session.auth).await?;

    display_ciphers(&session, &ciphers, args.filter.as_ref())
}

pub async fn command_cipher<I>(id: I) -> Result<()>
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

    display_ciphers(&session, &[cipher], None)
}
