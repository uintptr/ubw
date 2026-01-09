use std::{env, fs};

use anyhow::{Result, anyhow, bail};
use log::{LevelFilter, info};
use rstaples::logging::StaplesLogger;
use ubw_moz::{
    moz::{moz_install, moz_uninstall},
    proxy::moz_proxy,
};

const UBW_MOZ_DATA_DIR: &str = env!("CARGO_PKG_NAME");

fn init_logging() -> Result<()> {
    let data_dir = dirs::data_dir().ok_or_else(|| anyhow!("unable to find data dir"))?;
    let data_dir = data_dir.join(UBW_MOZ_DATA_DIR);

    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }

    let log_file = data_dir.join("proxy.log");

    StaplesLogger::new()
        .with_colors()
        .with_log_level(LevelFilter::Debug)
        .with_log_file(&log_file)
        .start();

    info!("logging to {}", log_file.display());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging()?;

    for (i, a) in env::args().enumerate() {
        info!("{i}: {a}");
    }

    let args: Vec<String> = env::args().collect();

    if 2 == args.len()
        && let Some(command) = args.get(1)
    {
        match command.as_str() {
            "install" => moz_install(),
            "uninstall" => moz_uninstall(),
            _ => bail!("Unknown command {command}"),
        }
    } else {
        moz_proxy().await
    }
}
