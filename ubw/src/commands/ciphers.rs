use anyhow::{Context, Result, bail};
use tabled::{Table, Tabled, settings::Style};
use ubitwarden::{
    api::BwApi,
    api_types::{BwCipher, BwCipherData},
    error::Error,
    session::BwSession,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::{
    commands::auth::login_from_cache,
    common::{UNREADABLE, decrypt_field},
};
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

fn get_totp(session: &BwSession, cipher: &BwCipher) -> Result<String> {
    if let BwCipherData::Login(login) = &cipher.data
        && let Some(totp) = &login.totp
    {
        //
        // decrypt_field first, so a key mismatch is reported as such instead of
        // looking like a malformed otpauth url
        //
        decrypt_field(session, cipher, "totp", totp)?;

        let totp_string = session
            .parse_totp(totp)
            .with_context(|| format!("could not read the totp of cipher {}", cipher.id))?;
        Ok(totp_string)
    } else {
        Err(Error::TotpNotFound.into())
    }
}

fn display_ciphers(session: &BwSession, ciphers: &[BwCipher], filter: Option<&String>) {
    let mut cipher_table = Vec::new();

    for c in ciphers {
        let totp = match get_totp(session, c) {
            Ok(totp) => totp,
            Err(e) => {
                //
                // Most entries simply don't have one, which isn't worth saying
                //
                if !matches!(e.downcast_ref::<Error>(), Some(Error::TotpNotFound)) {
                    error!("{e:#}");
                }
                String::new()
            }
        };

        let name = match decrypt_field(session, c, "name", &c.name) {
            Ok(name) => name,
            Err(e) => {
                //
                // Still list the entry, so an unreadable one is visible
                //
                error!("{e:#}");
                UNREADABLE.to_string()
            }
        };

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
}

pub fn command_ciphers(args: &CiphersArgs) -> Result<()> {
    let mut agent = match login_from_cache() {
        Ok(v) => v,
        Err(e) => {
            error!("not logged in");
            return Err(e);
        }
    };

    let session = agent.session_load()?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let ciphers = api.ciphers(&session.auth)?;

    display_ciphers(&session, &ciphers, args.filter.as_ref());

    Ok(())
}

pub fn command_cipher<I>(id: I) -> Result<()>
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

    display_ciphers(&session, &[cipher], None);

    Ok(())
}
