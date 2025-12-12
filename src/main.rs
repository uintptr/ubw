use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use log::{LevelFilter, info};
use rstaples::logging::StaplesLogger;
use ubw::{api::BwApi, config::BwConfig};

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

    let log_level = match args.verbose {
        true => LevelFilter::Info,
        false => LevelFilter::Warn,
    };

    StaplesLogger::new().with_colors().with_log_level(log_level).start();

    let config = BwConfig::from_file(&args.config_file)?;

    info!("client_id={}", config.credentials.client_id);

    let mut api = BwApi::new(&config);

    api.auth().await?;

    let sync = api.sync().await?;

    dbg!(sync);

    Ok(())
}
