use std::{collections::HashMap, os::unix::io::AsRawFd};

use anyhow::Result;
use clap::Args;
use log::{error, info, warn};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{UnixListener, UnixStream},
    select,
    sync::watch::Receiver,
};
use ubitwarden::error::Error;

use crate::commands::agent::utils::{create_socket_name, read_string, write_string};

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

pub struct CacheServer {
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
