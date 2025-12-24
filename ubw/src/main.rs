use clap::{Args, Parser, Subcommand};
use tabled::{Table, Tabled, settings::Style};

use log::{error, warn};

use anyhow::Result;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;
use ubitwarden::{
    api::{BwApi, BwCipher},
    cache::common::{fetch_user_data, store_user_data},
    crypto::BwCrypt,
    error::Error,
    session::BwSession,
};
use ubw::{
    commands::{
        login::{LoginArgs, command_login},
        server::{ServerArgs, command_server},
    },
    common::fetch_credentials,
};

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
    totp: String,
}

#[derive(Args)]
pub struct CipherArgs {
    /// cipher id
    #[arg(short, long)]
    id: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new session
    Login(LoginArgs),
    /// List ciphers
    Ciphers,
    /// Pull cipher
    Cipher(CipherArgs),
    /// Pull the TOTP for the specified id
    Totp(CipherArgs),
    /// Credential Server
    Server(ServerArgs),
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct UserArgs {
    /// verbose
    #[arg(short, long)]
    pub verbose: bool,

    /// Comamnd
    #[command(subcommand)]
    pub command: Commands,
}

async fn fetch_session() -> Result<BwSession> {
    let data = fetch_user_data("session").await?;
    let session: BwSession = serde_json::from_str(&data)?;
    Ok(session)
}

async fn store_session(session: &BwSession) -> Result<()> {
    let encoded_session = serde_json::to_string(session)?;
    store_user_data("session", encoded_session).await?;
    Ok(())
}

async fn load_session() -> Result<BwSession> {
    if let Ok(session) = fetch_session().await {
        if session.expired()? {
            warn!("session expired");
            //
            // see if the session is still usable ( expired )
            //
        } else {
            return Ok(session);
        }
    }

    let creds = fetch_credentials().await?;

    //
    // Either it didn't exist or it was expired. let's rejoin
    //
    let api = BwApi::new(&creds.email, &creds.server_url)?;

    let auth = api.auth(&creds.password).await?;

    let session = BwSession::new(&creds, &auth)?;

    // best effort. not fatal since we got what we wanted
    if let Err(e) = store_session(&session).await {
        error!("Unable to store session: ({e})");
    }

    Ok(session)
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

async fn command_ciphers() -> Result<()> {
    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let ciphers = api.ciphers(&session.auth).await?;

    display_ciphers(&crypt, &ciphers)
}

async fn command_cipher<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.cipher(&session.auth, id.as_ref()).await?;

    display_ciphers(&crypt, &[cipher])
}

async fn command_totp<I>(id: I) -> Result<()>
where
    I: AsRef<str>,
{
    let session = load_session().await?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let encrypted_totp = api.totp(&session.auth, id.as_ref()).await?;

    let totp = crypt.parse_totp(encrypted_totp)?;

    println!("totp: {totp}");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = UserArgs::parse();

    let log_level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Error
    };

    StaplesLogger::new().with_colors().with_log_level(log_level).start();

    match args.command {
        Commands::Login(login) => command_login(login).await?,
        Commands::Server(a) => command_server(a).await?,
        Commands::Ciphers => command_ciphers().await?,
        Commands::Cipher(cipher) => command_cipher(cipher.id).await?,
        Commands::Totp(totp) => command_totp(totp.id).await?,
    }

    Ok(())
}
