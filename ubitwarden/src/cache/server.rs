use log::{error, info};
use std::{collections::HashMap, os::unix::io::AsRawFd};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
};

use crate::{
    cache::common::{BW_UNIX_SOCKET_NAME, read_string, write_string},
    error::{Error, Result},
};

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
        Err(Error::ClientPidNotFound)
    }
}

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let listener = UnixListener::bind(BW_UNIX_SOCKET_NAME)?;

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

    fn parse_command(&mut self, command: &str) -> Result<Option<&String>> {
        if let Some(kv) = command.strip_prefix("write:") {
            let comp: Vec<&str> = kv.splitn(2, ':').collect();

            if 2 == comp.len() {
                let key = comp.first().ok_or(Error::CommandEmptyKey)?.to_string();
                let val = comp.get(1).ok_or(Error::CommandEmptyValue)?.to_string();

                info!("writing {key}");

                self.storage.insert(key, val);

                Ok(None)
            } else {
                error!("invalid command format {command}");
                return Err(Error::InvalidCommandFormat);
            }
        } else if let Some(key) = command.strip_prefix("read:") {
            info!("reading {key}");
            let data = self.storage.get(key);

            info!("read:{key} -> some={}", data.is_some());

            Ok(data)
        } else if command.eq("ping") {
            Ok(None)
        } else {
            return Err(Error::CommandNotFound {
                command: command.to_string(),
            });
        }
    }

    pub async fn accept_loop(&mut self) -> Result<()> {
        loop {
            info!("accepting clients");

            let (mut client, _) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!("accept failure ({e})");
                    break Err(e.into());
                }
            };

            let verified = match self.verify_client(&client) {
                Ok(v) => v,
                Err(e) => {
                    error!("unable to verify client ({e})");
                    continue;
                }
            };

            if !verified {
                error!("Verification failed");
                continue;
            }

            let command = match read_string(&mut client).await {
                Ok(v) => v,
                Err(e) => {
                    error!("read failure ({e})");
                    continue;
                }
            };

            if let Ok(Some(data)) = self.parse_command(&command) {
                write_string(&mut client, data).await?;
                client.flush().await?;
            }
        }
    }
}

pub async fn cache_server() -> Result<()> {
    let mut server = CacheServer::new()?;
    server.accept_loop().await
}
