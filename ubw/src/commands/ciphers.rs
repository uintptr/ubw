use anyhow::{Result, bail};
use tabled::{Table, Tabled, settings::Style};
use ubitwarden::{
    api::{BwApi, BwCipher},
    crypto::BwCrypt,
    error::Error,
};

use crate::commands::{cache::utils::load_session, login::login_from_cache};

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
    totp: String,
}

fn get_totp(crypt: &BwCrypt, cipher: &BwCipher) -> Result<String> {
    if let Some(login) = &cipher.login
        && let Some(totp) = &login.totp
    {
        let totp_string = crypt.parse_totp(totp)?;
        Ok(totp_string)
    } else {
        Err(Error::TotpNotFound.into())
    }
}

fn display_ciphers(crypt: &BwCrypt, ciphers: &[BwCipher]) -> Result<()> {
    let mut cipher_table = Vec::new();

    for c in ciphers {
        let totp = get_totp(crypt, c).unwrap_or_default();

        let name: String = crypt.decrypt(&c.name)?.try_into()?;

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

pub async fn command_ciphers() -> Result<()> {
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let ciphers = api.ciphers(&session.auth).await?;

    display_ciphers(&crypt, &ciphers)
}

pub async fn command_cipher<I>(id: I) -> Result<()>
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

    display_ciphers(&crypt, &[cipher])
}
