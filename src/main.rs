use std::env;

use anyhow::Result;
use clap::Parser;
use log::{LevelFilter, error, info, warn};
use rstaples::logging::StaplesLogger;
use tabled::{Table, Tabled, settings::Style};
use totp_rs::TOTP;
use ubw::{
    api::{BwApi, BwCipher},
    args::{CiphersArgs, Commands, SessionArgs, UserArgs},
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

async fn command_session(args: SessionArgs) -> Result<()> {
    let email = if let Some(email) = args.email {
        email
    } else {
        let env_email = env::var("UBW_EMAIL")?;
        info!("using UBW_EMAIL={}", env_email);
        env_email
    };

    let server_url = if let Some(server_url) = args.server_url {
        server_url
    } else {
        let server_url = env::var("UBW_SERVER_URL")?;
        info!("using UBW_SERVER_URL={}", server_url);
        server_url
    };

    let mut api = BwApi::new(&email, &server_url)?;

    // helps with testing but not recommended
    let password = if let Ok(password) = env::var("UBW_PASSWORD") {
        info!("using UBW_PASSWORD=***********");
        password
    } else {
        let prompt = format!("Password for {}: ", email);
        rpassword::prompt_password(prompt)?
    };

    //
    // get a new bearer token
    //
    let auth = api.auth(&password).await?;

    //
    // create the symetric key
    //
    let crypt = BwCrypt::from_password(&email, password, auth)?;
    let key = crypt.export();

    //
    // Build the session key
    //
    let session = BwSession::new(&email, &server_url, key, auth)?;
    let session_env = session.export()?;

    //
    // print it for the user to source it
    //
    println!("{session_env}");

    Ok(())
}

fn get_totp(crypt: &BwCrypt, cipher: &BwCipher) -> Result<String> {
    if let Some(login) = &cipher.login
        && let Some(totp) = &login.totp
    {
        let totp_string: String = crypt.decrypt(&totp)?.try_into()?;

        if totp_string.starts_with("otpauth://") {
            let totp = match TOTP::from_url(&totp_string) {
                Ok(v) => v,
                Err(e) => {
                    error!("Unable to parse {totp_string} {e}");
                    return Err(e.into());
                }
            };
            let otp = totp.generate_current()?;

            Ok(otp)
        } else {
            warn!("format not implemented {totp_string}");
            Err(Error::TotpNotImplemented.into())
        }
    } else {
        Err(Error::TotpNotFound.into())
    }
}

async fn command_ciphers(_args: CiphersArgs) -> Result<()> {
    let session = BwSession::from_env()?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let mut api = BwApi::new(&session.email, &session.server_url)?;
    api.with_auth(&session.auth);

    let ciphers = api.ciphers().await?;

    let mut cipher_table = Vec::new();

    for c in &ciphers {
        let totp = get_totp(&crypt, &c).unwrap_or("".into());

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
        Commands::Session(sess) => command_session(sess).await,
        Commands::Ciphers(ciphers) => command_ciphers(ciphers).await,
    }
}
