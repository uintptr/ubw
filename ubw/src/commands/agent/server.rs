use std::{env, time::Duration};

use anyhow::{Result, bail};
use clap::Args;
use log::{error, info, warn};
use tokio::{
    process::Command,
    select,
    signal::unix::{SignalKind, signal},
    sync::watch::{self},
    time::sleep,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::commands::agent::{credentials::CacheServer, ssh::SshAgentServer};

const SPAWN_WAIT_TIMEOUT: usize = 5;

#[derive(Args)]
pub struct AgentArgs {
    /// server url
    #[arg(short, long)]
    pub stop: bool,

    /// stay in the foreground
    #[arg(short, long)]
    pub foreground: bool,
}

async fn signal_handlers() -> Result<()> {
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        select! {
            _ = sighup.recv() => {
                info!("ignoring SIGHUP");
            }
            _ = sigint.recv() => {
                info!("received SIGINT. We're leaving");
                break Ok(())
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM. We're leaving");
                break Ok(())
            }
        }
    }
}

async fn cache_server() -> Result<()> {
    let mut creds_server = CacheServer::new()?;
    let ssh_server = SshAgentServer::new();

    let (quit_tx, quit_rx) = watch::channel(false);

    let mut creds_done = false;
    let mut ssh_done = false;

    loop {
        select! {
            _ = signal_handlers() => {
                quit_tx.send(true)?;
            }
            ret = creds_server.accept_loop(quit_rx.clone()), if !creds_done => {
                warn!("credentials thread returned, signaling shutdown");
                // signal the other thread to return
                quit_tx.send(true)?;
                creds_done = true;

                if let Err(e) = ret{
                    error!("credentials thread failed with error {e}");
                }

                if creds_done && ssh_done {
                    break;
                }
            }
            ret = ssh_server.accept_loop(quit_rx.clone()), if !ssh_done => {
                warn!("ssh-agent thread returned, signaling shutdown");
                // signal the other thread to return
                quit_tx.send(true)?;
                ssh_done = true;

                if let Err(e) = ret{
                    error!("ssh-agent thread failed with error {e}");
                }

                if creds_done && ssh_done {
                    break;
                }
            }
        }
    }

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub async fn spawn_server() -> Result<UBWAgent> {
    let self_exe = env::current_exe()?;

    info!("spawning {}", self_exe.display());

    Command::new(self_exe).arg("-v").arg("agent").spawn()?;

    //
    // wait until we can ping it
    //
    for i in 0..SPAWN_WAIT_TIMEOUT {
        if let Ok(a) = UBWAgent::new().await {
            return Ok(a);
        }
        info!("server is not ready...{i}/{SPAWN_WAIT_TIMEOUT}");
        sleep(Duration::from_secs(1)).await;
    }

    bail!("Unable to spawn credential server")
}

pub async fn command_agent(args: AgentArgs) -> Result<()> {
    match UBWAgent::new().await {
        Ok(mut v) => {
            //
            // server is running
            //
            if args.stop {
                warn!("stopping the server");
                v.stop().await?;

                // Wait until ping fails
                for _ in 0..5 {
                    if UBWAgent::new().await.is_err() {
                        info!("server stopped");
                        return Ok(());
                    }
                    sleep(Duration::from_secs(1)).await;
                }

                bail!("Unable to stop server");
            }
            Ok(())
        }
        Err(_) => {
            //
            // server is NOT running
            //
            if args.stop {
                // nothing to do
                info!("server is not running");
                Ok(())
            } else {
                // start the server
                info!("starting the server");
                //
                // this blocks!
                //
                cache_server().await?;
                Ok(())
            }
        }
    }
}
