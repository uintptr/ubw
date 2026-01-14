use std::{fs, sync::Arc};

use anyhow::Result;
use clap::Args;
use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    select,
    sync::{RwLock, watch::Receiver},
    task::JoinSet,
};
use ubitwarden::error::Error;
use ubitwarden_agent::agent::UBWAgent;

use crate::commands::agent::storage::{CredStorage, CredStorageTrait};

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

struct ClientHandler {
    storage_lock: Arc<RwLock<CredStorage>>,
}

pub struct CacheServer {
    listener: UnixListener,
    storage_lock: Arc<RwLock<CredStorage>>,
}

#[cfg(target_os = "linux")]
fn get_peer_pid(client: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;

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

async fn read_string(stream: &mut UnixStream) -> Result<String> {
    let len = stream.read_i32().await?;
    let len: usize = len.try_into()?;

    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf).await?;

    let s = String::from_utf8(buf)?;

    Ok(s)
}

async fn write_string<S>(stream: &mut UnixStream, input: S) -> Result<()>
where
    S: AsRef<str>,
{
    let len = input.as_ref().len();
    let len: i32 = len.try_into()?;

    stream.write_i32(len).await?;
    stream.write_all(input.as_ref().as_bytes()).await?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_client(client: &UnixStream) -> Result<bool> {
    let self_uid = nix::unistd::getuid().as_raw();
    let client_uid = get_peer_pid(client)?;
    info!("client pid={client_uid}");
    Ok(self_uid == client_uid)
}

impl ClientHandler {
    pub fn new(storage_lock: Arc<RwLock<CredStorage>>) -> Self {
        Self { storage_lock }
    }

    async fn parse_command_write(&self, kv: &str) -> Result<ServerResponse> {
        let comp: Vec<&str> = kv.splitn(2, ':').collect();

        if 2 == comp.len() {
            let key = comp.first().ok_or(Error::CommandEmptyKey)?.to_string();
            let val = comp.get(1).ok_or(Error::CommandEmptyValue)?.to_string();

            info!("writing {key}");

            let mut storage = self.storage_lock.write().await;
            storage.add(key, val)?;

            Ok(ServerResponse::Empty)
        } else {
            error!("invalid command format write");
            Err(Error::InvalidCommandFormat.into())
        }
    }

    async fn parse_command_read(&self, key: &str) -> ServerResponse {
        info!("reading {key}");

        let storage = self.storage_lock.read().await;

        match storage.get(key) {
            Some(v) => ServerResponse::String(v.clone()),
            None => ServerResponse::String(String::new()),
        }
    }

    async fn parse_command_delete(&self, key: &str) -> ServerResponse {
        info!("deleting {key}");

        let mut storage = self.storage_lock.write().await;

        storage.remove(key);
        ServerResponse::Empty
    }

    async fn parse_command(&self, command: &str) -> Result<ServerResponse> {
        if let Some(kv) = command.strip_prefix("write:") {
            self.parse_command_write(kv).await
        } else if let Some(key) = command.strip_prefix("read:") {
            Ok(self.parse_command_read(key).await)
        } else if let Some(key) = command.strip_prefix("delete:") {
            Ok(self.parse_command_delete(key).await)
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

    async fn client_handler(&self, mut client: UnixStream) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let verified = verify_client(&client)?;
            if !verified {
                error!("Verification failed");
                return Err(Error::ClientVerificationFailure.into());
            }
        }

        loop {
            info!("waiting for client data");

            let command = read_string(&mut client).await?;

            let response = self.parse_command(&command).await?;

            match response {
                ServerResponse::Quit => break Err(Error::Shutdown.into()),
                ServerResponse::Empty => {}
                ServerResponse::String(s) => {
                    write_string(&mut client, s).await?;
                    client.flush().await?;
                }
            }
        }
    }
}

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let socket_path = UBWAgent::create_socket_name()?;

        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;

        let storage_lock = Arc::new(RwLock::new(CredStorage::new()?));

        Ok(Self { listener, storage_lock })
    }

    pub async fn accept_loop(&self, mut quit_rx: Receiver<bool>) -> Result<()> {
        let mut clients_set = JoinSet::new();

        loop {
            info!("accepting clients");

            select! {
                //
                // this'll get signaled after a SIGTERM or SIGINT
                // and we'll break out of the loop so we can return
                //
                _ = quit_rx.changed() => break Ok(()),
                accept_ret = self.listener.accept() => {
                    let ( client, _ ) = match accept_ret {
                        Ok(v) => v,
                        Err(e) => {
                            error!("accept failure ({e})");
                            break Err(e.into());
                        }
                    };

                    //
                    // spawn a task for this client
                    //

                    let handler = ClientHandler::new( Arc::clone(&self.storage_lock));

                    clients_set.spawn(async move {
                        handler.client_handler(client).await
                    });
                },
                Some(Ok(client_ret)) = clients_set.join_next() => {
                    warn!("client disconnected");

                    match client_ret {
                        Ok(()) => {},
                        Err(e) => {
                            if let Some(Error::Shutdown) = e.downcast_ref::<Error>() {
                                break Ok(());
                            }
                            error!("{e}");
                        }
                    }

                }
            }
        }
    }
}
