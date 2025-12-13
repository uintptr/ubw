use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;
use tabled::{Table, Tabled, settings::Style};
use ubw::{api::BwApi, config::BwConfig, crypto::BwCrypt};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct UserArgs {
    /// config file
    #[arg(short, long)]
    config_file: PathBuf,

    /// verbose
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Tabled)]
struct CipherTable<'a> {
    id: &'a str,
    ctype: String,
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = UserArgs::parse();

    let log_level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };

    StaplesLogger::new().with_colors().with_log_level(log_level).start();

    let config = BwConfig::from_file(&args.config_file)?;

    let mut api = BwApi::new(&config)?;

    let auth = api.auth().await?;

    let crypt = BwCrypt::new(&config, auth)?;

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
    //table.with(Style::rounded());

    println!("{}", table);

    Ok(())
}
