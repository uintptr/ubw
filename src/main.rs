use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;
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

    for c in &ciphers {
        let name: String = crypt.decrypt(&c.name)?.try_into()?;
        println!("{} name={name} type={}", c.id, c.cipher_type);
    }

    Ok(())
}
