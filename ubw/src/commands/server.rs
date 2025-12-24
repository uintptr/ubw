use std::time::Duration;

use anyhow::{Result, bail};
use clap::Args;
use log::{info, warn};
use tokio::time::sleep;
use ubitwarden::cache::{
    common::{ping_server, stop_server},
    server::cache_server,
};
#[derive(Args)]

pub struct ServerArgs {
    /// server url
    #[arg(short, long)]
    pub stop: bool,
}

pub async fn command_server(args: ServerArgs) -> Result<()> {
    let running = if ping_server().await.is_ok() {
        info!("server is running");
        true
    } else {
        false
    };

    if args.stop && running {
        warn!("stopping the server");
        stop_server().await?;

        //
        // wait until ping fails
        //
        for _ in 0..5 {
            if ping_server().await.is_err() {
                info!("server stopped");
                return Ok(());
            }
            sleep(Duration::from_secs(1)).await;
        }

        bail!("Unable to stop server");
    } else if args.stop && !running {
        Ok(())
    } else {
        info!("starting the server");
        cache_server().await?;

        Ok(())
    }
}
