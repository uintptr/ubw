use std::env;

use clap::{Args, Parser, Subcommand};
use dialoguer::Password;
use tabled::{Table, Tabled, settings::Style};

use log::{error, info, warn};

use anyhow::Result;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;
use ubitwarden::{
    api::{BwApi, BwCipher},
    cache::{
        common::{fetch_user_data, ping, store_user_data},
        server::cache_server,
    },
    credentials::BwCredentials,
    crypto::BwCrypt,
    error::Error,
    session::BwSession,
};

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
    totp: String,
}

#[derive(Args)]
pub struct LoginArgs {
    /// email address
    #[arg(short, long)]
    pub email: Option<String>,

    /// server url
    #[arg(short, long)]
    pub server_url: Option<String>,
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
    Server,
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

async fn fetch_credentials() -> Result<BwCredentials> {
    let data = fetch_user_data("credentials").await?;
    let creds: BwCredentials = serde_json::from_str(&data)?;
    info!("found credentials for {}", creds.email);
    Ok(creds)
}

async fn store_credentials(email: &str, args: &LoginArgs) -> Result<()> {
    //
    // helps with testing but not recommended
    //
    let password = if let Ok(password) = env::var("UBW_PASSWORD") {
        info!("using UBW_PASSWORD=***********");
        password.clone()
    } else {
        let prompt = format!("Password for {email}");
        Password::new().with_prompt(prompt).interact()?
    };

    let server_url = if let Some(server_url) = &args.server_url {
        server_url.clone()
    } else {
        let server_url = env::var("UBW_SERVER_URL")?;
        info!("using UBW_SERVER_URL={server_url}");
        server_url
    };

    let creds = BwCredentials {
        email: email.to_string(),
        password,
        server_url,
    };

    let encoded_creds = serde_json::to_string(&creds)?;

    store_user_data("credentials", encoded_creds).await
}

async fn fetch_session() -> Result<BwSession> {
    let data = fetch_user_data("session").await?;
    let session: BwSession = serde_json::from_str(&data)?;
    Ok(session)
}

async fn store_session(session: &BwSession) -> Result<()> {
    let encoded_session = serde_json::to_string(session)?;
    store_user_data("session", encoded_session).await
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

async fn command_login(args: LoginArgs) -> Result<()> {
    if let Err(e) = ping().await {
        println!("Unable to connect to credential server server");
        return Err(e);
    }

    let email = if let Some(email) = &args.email {
        email.clone()
    } else {
        let env_email = env::var("UBW_EMAIL")?;
        info!("using UBW_EMAIL={env_email}");
        env_email
    };

    store_credentials(&email, &args).await?;
    fetch_credentials().await?;

    Ok(())
}

fn get_totp(crypt: &BwCrypt, cipher: &BwCipher) -> Result<String> {
    if let Some(login) = &cipher.login
        && let Some(totp) = &login.totp
    {
        let totp_string: String = crypt.parse_totp(totp)?.try_into()?;
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
        Commands::Login(login) => command_login(login).await,
        Commands::Server => cache_server().await,
        Commands::Ciphers => command_ciphers().await,
        Commands::Cipher(cipher) => command_cipher(cipher.id).await,
        Commands::Totp(totp) => command_totp(totp.id).await,
    }
}
