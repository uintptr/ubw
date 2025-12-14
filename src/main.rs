use std::env;

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;
use tabled::{Table, Tabled, settings::Style};
use ubw::{
    api::BwApi,
    args::{CiphersArgs, Commands, SessionArgs, UserArgs},
    crypto::BwCrypt,
    session::BwSession,
};

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
}

async fn command_session(args: SessionArgs) -> Result<()> {
    let mut api = BwApi::new(&args.email, &args.server_url)?;

    let password = if let Ok(password) = env::var("UBW_PASSWORD") {
        password
    } else {
        let prompt = format!("Password for {}: ", args.email);
        rpassword::prompt_password(prompt)?
    };

    //
    // get a new bearer token
    //
    let auth = api.auth(&password).await?;

    //
    // create the symetric key
    //
    let crypt = BwCrypt::from_password(&args.email, password, auth)?;
    let key = crypt.export();

    let session = BwSession::new(&args.email, &args.server_url, key, auth)?;

    let session_env = session.export()?;

    println!("{session_env}");

    Ok(())
}

async fn command_ciphers(_args: CiphersArgs) -> Result<()> {
    let session = BwSession::from_env()?;

    let crypt = BwCrypt::from_encoded_key(session.key)?;

    let mut api = BwApi::new(&session.email, &session.server_url)?;
    api.with_auth(&session.auth);

    let ciphers = api.ciphers().await?;

    let mut cipher_table = Vec::new();

    for c in &ciphers {
        let name: String = crypt.decrypt(&c.name)?.try_into()?;

        let table_entry = CipherTable {
            id: &c.id,
            ctype: c.cipher_type.to_string(),
            name,
        };

        cipher_table.push(table_entry);
    }

    let mut table = Table::new(cipher_table);
    table.with(Style::modern());

    println!("\n{table}");

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

    /*
    let mut config = BwConfig::new(&args)?;
    augment_config(&args, &mut config).await?;

    let mut cache = BwCache::new()?;

    let mut api = BwApi::new(&config.credentials.email, &config.server.url)?;

    let crypt = init_crypt(&config, &mut cache, &mut api).await?;

    //
    // read the config file as-is, we'll augment it with the user args
    //
    let ciphers = api.ciphers().await?;

    let mut cipher_table = Vec::new();

    for c in &ciphers {
        let name: String = crypt.decrypt(&c.name)?.try_into()?;

        let table_entry = CipherTable {
            id: &c.id,
            ctype: c.cipher_type.to_string(),
            name,
        };

        cipher_table.push(table_entry);
    }

    let mut table = Table::new(cipher_table);
    table.with(Style::modern());

    println!("\n{}", table);
    */
}
