use std::{collections::HashMap, os::unix::io::AsRawFd, time::Duration};

use anyhow::{Result, bail};
use clap::Args;
use log::{error, info, warn};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{UnixListener, UnixStream},
    select,
    signal::unix::{SignalKind, signal},
    sync::watch::{self, Receiver},
    time::sleep,
};
use ubitwarden::error::Error;

use crate::commands::cache::utils::{create_socket_name, ping_cache, read_string, stop_cache, write_string};

#[derive(Args)]
pub struct CacheArgs {
    /// server url
    #[arg(short, long)]
    pub stop: bool,
}

enum ServerResponse {
    Quit,
    Empty,
    String(String),
}

struct CacheServer {
    listener: UnixListener,
    self_uid: u32,
    storage: HashMap<String, String>,
}

fn get_peer_pid(client: &UnixStream) -> Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())?;

    let ret = unsafe {
        libc::getsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 {
        Ok(cred.uid)
    } else {
        Err(Error::ClientPidNotFound.into())
    }
}

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let socket_name = create_socket_name();
        let listener = UnixListener::bind(socket_name)?;

        let self_uid = nix::unistd::getuid().as_raw();

        let storage = HashMap::new();

        Ok(Self {
            listener,
            self_uid,
            storage,
        })
    }

    fn verify_client(&self, client: &UnixStream) -> Result<bool> {
        let client_uid = get_peer_pid(client)?;
        info!("client pid={client_uid}");
        Ok(self.self_uid == client_uid)
    }

    fn parse_command(&mut self, command: &str) -> Result<ServerResponse> {
        if let Some(kv) = command.strip_prefix("write:") {
            let comp: Vec<&str> = kv.splitn(2, ':').collect();

            if 2 == comp.len() {
                let key = comp.first().ok_or(Error::CommandEmptyKey)?.to_string();
                let val = comp.get(1).ok_or(Error::CommandEmptyValue)?.to_string();

                info!("writing {key}");

                self.storage.insert(key, val);
                Ok(ServerResponse::Empty)
            } else {
                error!("invalid command format {command}");
                Err(Error::InvalidCommandFormat.into())
            }
        } else if let Some(key) = command.strip_prefix("read:") {
            info!("reading {key}");

            match self.storage.get(key) {
                Some(v) => Ok(ServerResponse::String(v.clone())),
                None => Ok(ServerResponse::Empty),
            }
        } else if command.eq("ping") {
            Ok(ServerResponse::Empty)
        } else if command.eq("stop") {
            warn!("asked to stop");
            Ok(ServerResponse::Quit)
        } else {
            Err(Error::CommandNotFound {
                command: command.to_string(),
            }
            .into())
        }
    }

    async fn client_handler(&mut self, mut client: UnixStream) -> Result<()> {
        let verified = self.verify_client(&client)?;

        if !verified {
            error!("Verification failed");
            return Err(Error::ClientVerificationFailure.into());
        }

        let command = read_string(&mut client).await?;

        let response = self.parse_command(&command)?;

        match response {
            ServerResponse::Quit => Err(Error::EndOfFile.into()),
            ServerResponse::Empty => Ok(()),
            ServerResponse::String(s) => {
                write_string(&mut client, s).await?;
                client.flush().await?;
                Ok(())
            }
        }
    }

    pub async fn accept_loop(&mut self, mut quit_rx: Receiver<bool>) -> Result<()> {
        loop {
            info!("accepting clients");

            select! {
                // this'll get signaled after a SIGTERM and we'll break out
                _ = quit_rx.changed() => break Ok(()),
                accept_ret = self.listener.accept() => {
                    let ( client, _ ) = match accept_ret {
                        Ok(v) => v,
                        Err(e) => {
                            error!("accept failure ({e})");
                            break Err(e.into());
                        }
                    };

                    let client_ret = self.client_handler(client).await;

                    match client_ret {
                        Ok(()) => {},
                        Err(e) => {
                            if let Some(Error::EndOfFile) = e.downcast_ref::<Error>() {
                                break Ok(());
                            }
                            error!("{e}");
                        }
                    }
                },
            }
        }
    }
}

async fn cache_server() -> Result<()> {
    let mut server = CacheServer::new()?;

    let (quit_tx, quit_rx) = watch::channel(false);

    let mut t = tokio::spawn(async move {
        let ret = server.accept_loop(quit_rx).await;

        if let Err(e) = &ret {
            error!("server returned {e}");
        }

        ret
    });

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
                quit_tx.send(true)?;
            }
            ret = &mut t => {
                warn!("thread returned, we're done");
                match ret{
                    Ok(_) => break Ok(()),
                    Err(e) => break Err(e.into())
                }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////
pub async fn command_cache(args: CacheArgs) -> Result<()> {
    let running = ping_cache().await.is_ok();

    if running {
        info!("server is running");
    }

    match (args.stop, running) {
        (true, true) => {
            warn!("stopping the server");
            stop_cache().await?;

            // Wait until ping fails
            for _ in 0..5 {
                if ping_cache().await.is_err() {
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
