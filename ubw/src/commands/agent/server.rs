use std::{
    env, fs,
    path::Path,
    process::Command,
    sync::mpsc::{self, Sender},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use log::{error, info, warn};
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGTERM},
    iterator::Signals,
};
use ubitwarden_agent::agent::UBWAgent;

use crate::{
    commands::agent::{ShutdownReason, credentials::CacheServer, signal_shutdown, ssh::SshAgentServer},
    common::UBW_APP_VERSION,
};

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

/// Watch for the signals we care about on a thread of its own.
///
/// SIGHUP is logged and ignored, the other two bring the daemon down.
fn signal_handlers(shutdown: &Sender<ShutdownReason>) -> Result<()> {
    let mut signals = Signals::new([SIGHUP, SIGINT, SIGTERM]).context("Failed to install signal handlers")?;

    for signal in &mut signals {
        match signal {
            SIGHUP => info!("ignoring SIGHUP"),
            SIGINT => {
                signal_shutdown(shutdown, ShutdownReason::Signal("SIGINT"));
                return Ok(());
            }
            SIGTERM => {
                signal_shutdown(shutdown, ShutdownReason::Signal("SIGTERM"));
                return Ok(());
            }
            other => warn!("ignoring unexpected signal {other}"),
        }
    }

    Ok(())
}

fn unlink_socket(socket_path: &Path) {
    if !socket_path.exists() {
        return;
    }

    info!("Deleting {}", socket_path.display());

    if let Err(e) = fs::remove_file(socket_path) {
        error!("Unable to delete {} ({e})", socket_path.display());
    }
}

/// Run both listeners until something asks us to stop.
///
/// The listeners and their clients each get a thread and a [`Sender`]. The main
/// thread parks on the receiver, which is the one place a shutdown can be
/// decided, and returning from here ends the process along with those threads.
fn cache_server() -> Result<()> {
    let creds_server = CacheServer::new().context("Failed to initialize credentials cache server")?;
    let ssh_server = SshAgentServer::new().context("Failed to initialize ssh-agent server")?;

    let creds_socket = creds_server.socket_path().map(Path::to_path_buf);
    let ssh_socket = ssh_server.socket_path().to_path_buf();

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let signals_tx = shutdown_tx.clone();
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            if let Err(e) = signal_handlers(&signals_tx) {
                error!("signal handler failed ({e})");
            }
        })
        .context("Failed to spawn the signal thread")?;

    let creds_tx = shutdown_tx.clone();
    thread::Builder::new()
        .name("creds-listener".into())
        .spawn(move || creds_server.accept_loop(&creds_tx))
        .context("Failed to spawn the credentials listener thread")?;

    thread::Builder::new()
        .name("ssh-listener".into())
        .spawn(move || ssh_server.accept_loop(&shutdown_tx))
        .context("Failed to spawn the ssh-agent listener thread")?;

    //
    // Nothing left to do but wait for a reason to leave
    //
    match shutdown_rx.recv() {
        Ok(reason) => info!("shutting down: {reason}"),
        Err(e) => error!("every shutdown sender is gone ({e})"),
    }

    //
    // Linux uses an abstract socket for the cache, which has no file to remove
    //
    if let Some(creds_socket) = &creds_socket {
        unlink_socket(creds_socket);
    }
    unlink_socket(&ssh_socket);

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub fn spawn_server() -> Result<UBWAgent> {
    let self_exe = env::current_exe().context("Failed to determine path to current executable")?;

    info!("spawning {}", self_exe.display());

    Command::new(&self_exe)
        .arg("-v")
        .arg("agent")
        .spawn()
        .with_context(|| format!("Failed to spawn server process at {}", self_exe.display()))?;

    //
    // wait until we can ping it
    //
    for i in 0..SPAWN_WAIT_TIMEOUT {
        if let Ok(a) = UBWAgent::client() {
            return Ok(a);
        }
        info!("server is not ready...{i}/{SPAWN_WAIT_TIMEOUT}");
        thread::sleep(Duration::from_secs(1));
    }

    bail!("Failed to connect to credential server after {SPAWN_WAIT_TIMEOUT} attempts")
}

pub fn command_agent(args: &AgentArgs) -> Result<()> {
    match UBWAgent::client() {
        Ok(mut v) => {
            //
            // server is running
            //
            if args.stop {
                warn!("stopping the server");
                v.quit()?;

                // Wait until ping fails
                for _ in 0..20 {
                    if UBWAgent::client().is_err() {
                        info!("server stopped");
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(100));
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
                info!("{}", "-".repeat(80));
                info!("starting the server version {UBW_APP_VERSION}");
                //
                // this blocks!
                //
                cache_server()?;
                Ok(())
            }
        }
    }
}
