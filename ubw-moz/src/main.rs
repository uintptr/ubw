use std::env;

use anyhow::{Result, bail};
use log::{LevelFilter, info};
use rstaples::logging::StaplesLogger;
use ubw_moz::{
    data::init_data_dir,
    moz::{moz_install, moz_uninstall},
    proxy::moz_proxy,
};

async fn init_logging() -> Result<()> {
    let data_dir = init_data_dir().await?;

    let log_file = data_dir.join("proxy.log");

    StaplesLogger::new()
        .with_colors()
        .with_log_level(LevelFilter::Debug)
        .with_log_file(&log_file)
        .start();

    info!("logging to {}", log_file.display());

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_logging().await?;

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
