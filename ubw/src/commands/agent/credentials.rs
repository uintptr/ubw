use std::{collections::HashMap, fs};

use anyhow::Result;
use clap::Args;
use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    select,
    sync::watch::Receiver,
};
use ubitwarden::error::Error;
use ubitwarden_agent::agent::UBWAgent;

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

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let socket_path = UBWAgent::create_socket_name()?;

        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;

        let self_uid = nix::unistd::getuid().as_raw();

        let storage = HashMap::new();

        Ok(Self {
            listener,
            self_uid,
            storage,
        })
    }

    #[cfg(target_os = "linux")]
    fn verify_client(&self, client: &UnixStream) -> Result<bool> {
        let client_uid = get_peer_pid(client)?;
        info!("client pid={client_uid}");
        Ok(self.self_uid == client_uid)
    }

    #[cfg(target_os = "macos")]
    fn verify_client(&self, client: &UnixStream) -> Result<bool> {
        // on macos the socket file is only readable-writable by the
        // current user
        Ok(true)
    }

    fn parse_command_write(&mut self, kv: &str) -> Result<ServerResponse> {
        let comp: Vec<&str> = kv.splitn(2, ':').collect();

        if 2 == comp.len() {
            let key = comp.first().ok_or(Error::CommandEmptyKey)?.to_string();
            let val = comp.get(1).ok_or(Error::CommandEmptyValue)?.to_string();

            info!("writing {key}");

            self.storage.insert(key, val);
            Ok(ServerResponse::Empty)
        } else {
            error!("invalid command format write");
            Err(Error::InvalidCommandFormat.into())
        }
    }

    fn parse_command_read(&self, key: &str) -> ServerResponse {
        info!("reading {key}");

        match self.storage.get(key) {
            Some(v) => ServerResponse::String(v.clone()),
            None => ServerResponse::String(String::new()),
        }
    }

    fn parse_command_delete(&mut self, key: &str) -> ServerResponse {
        info!("deleting {key}");
        self.storage.remove(key);
        ServerResponse::Empty
    }

    fn parse_command(&mut self, command: &str) -> Result<ServerResponse> {
        if let Some(kv) = command.strip_prefix("write:") {
            self.parse_command_write(kv)
        } else if let Some(key) = command.strip_prefix("read:") {
            Ok(self.parse_command_read(key))
        } else if let Some(key) = command.strip_prefix("delete:") {
            Ok(self.parse_command_delete(key))
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

        loop {
            info!("waiting for client data");

            let command = read_string(&mut client).await?;

            let response = self.parse_command(&command)?;

            match response {
                ServerResponse::Quit => break Err(Error::EndOfFile.into()),
                ServerResponse::Empty => {}
                ServerResponse::String(s) => {
                    write_string(&mut client, s).await?;
                    client.flush().await?;
                }
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

                    warn!("client disconnected");

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
