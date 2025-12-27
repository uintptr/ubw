use std::{env, process::Stdio, time::Duration};

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

use crate::commands::agent::utils::{ping_agent, stop_agent};
use crate::commands::agent::{credentials::CacheServer, ssh::SshAgentServer};

const SPAWN_WAIT_TIMEOUT: usize = 5;

#[derive(Args)]
pub struct AgentArgs {
    /// server url
    #[arg(short, long)]
    pub stop: bool,
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
                info!("ignoring SIGINT");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM. we're leaving");
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

pub async fn spawn_server() -> Result<()> {
    let self_exe = env::current_exe()?;

    info!("spawning {}", self_exe.display());

    Command::new(self_exe)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    //
    // wait until we can ping it
    //
    for i in 0..SPAWN_WAIT_TIMEOUT {
        if ping_agent().await.is_ok() {
            return Ok(());
        }

        info!("server is not ready...{i}/{SPAWN_WAIT_TIMEOUT}");
        sleep(Duration::from_secs(1)).await;
    }

    bail!("Unable to spawn credential server")
}

pub async fn command_agent(args: AgentArgs) -> Result<()> {
    let running = ping_agent().await.is_ok();

    match (args.stop, running) {
        (true, true) => {
            warn!("stopping the server");
            stop_agent().await?;

            // Wait until ping fails
            for _ in 0..5 {
                if ping_agent().await.is_err() {
                    info!("server stopped");
                    return Ok(());
                }
                sleep(Duration::from_secs(1)).await;
            }

            bail!("Unable to stop server");
        }
        (true, false) => Ok(()),
        (false, false) => {
            info!("starting the server");
            //
            // this blocks!
            //
            cache_server().await?;
            Ok(())
        }
        (false, true) => {
            info!("already running");
            Ok(())
        }
    }
}
