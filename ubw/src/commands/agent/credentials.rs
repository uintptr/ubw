use std::{fs, sync::Arc};

use anyhow::{Result, bail};
use clap::Args;
use log::{error, info, warn};
use secrecy::zeroize::Zeroize;
use tokio::{
    net::{UnixListener, UnixStream},
    select,
    sync::{RwLock, watch::Receiver},
    task::JoinSet,
};
use ubitwarden::{credentials::BwCredentials, error::Error, session::BwSessionData};
use ubitwarden_agent::{
    agent::{UBWAgent, create_socket_name},
    messages::{ChannelRequest, ChannelResponse},
};

use crate::commands::agent::storage::{CredStorage, CredStorageTrait};

#[derive(Args)]
pub struct CacheArgs {
    /// server url
    #[arg(short, long)]
    pub stop: bool,
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

    //
    // Session
    //
    async fn session_store(&self, data: BwSessionData) -> Result<ChannelResponse> {
        let mut session_string = serde_json::to_string(&data)?;

        let mut store = self.storage_lock.write().await;

        let success = store.add("session", &session_string).is_ok();

        session_string.zeroize();

        Ok(ChannelResponse::Status(success))
    }

    async fn session_fetch(&self) -> Result<ChannelResponse> {
        let store = self.storage_lock.read().await;

        let res = if let Some(mut session_string) = store.get("session") {
            let session: BwSessionData = serde_json::from_str(&session_string)?;
            session_string.zeroize();
            ChannelResponse::SessionFetch(session)
        } else {
            ChannelResponse::Error("Not Found".to_string())
        };

        Ok(res)
    }

    async fn session_delete(&self) -> Result<ChannelResponse> {
        let mut store = self.storage_lock.write().await;

        store.remove("session");

        Ok(ChannelResponse::Status(true))
    }

    //
    // Credentials
    //

    async fn credentials_fetch(&self) -> Result<ChannelResponse> {
        let store = self.storage_lock.read().await;

        let res = if let Some(mut creds_string) = store.get("credentials") {
            let creds: BwCredentials = serde_json::from_str(&creds_string)?;
            creds_string.zeroize();
            ChannelResponse::CredentialsFetch(creds)
        } else {
            ChannelResponse::Error("Not Found".to_string())
        };

        Ok(res)
    }

    async fn credentials_delete(&self) -> Result<ChannelResponse> {
        let mut store = self.storage_lock.write().await;

        store.remove("credentials");

        Ok(ChannelResponse::Status(true))
    }

    async fn credentials_store(&self, creds: BwCredentials) -> Result<ChannelResponse> {
        let mut creds_string = serde_json::to_string(&creds)?;
        let mut store = self.storage_lock.write().await;

        let success = store.add("credentials", &creds_string).is_ok();

        creds_string.zeroize();

        Ok(ChannelResponse::Status(success))
    }

    async fn client_handler(&self, client: UnixStream) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let verified = verify_client(&client)?;
            if !verified {
                error!("Verification failed");
                return Err(Error::ClientVerificationFailure.into());
            }
        }

        let mut client = UBWAgent::server(client).await?;

        loop {
            info!("wating for a request");

            let req = client.get_request().await?;

            info!("Request: {req}");

            let res = match req {
                ChannelRequest::Hello { public_key: _ } => bail!("Out of order"),
                ChannelRequest::Stop => break Err(Error::Shutdown.into()),
                //
                // Session
                //
                ChannelRequest::SessionStore(data) => self.session_store(data).await?,
                ChannelRequest::SessionFetch => self.session_fetch().await?,
                ChannelRequest::SessionDelete => self.session_delete().await?,
                //
                // Credentials
                //
                ChannelRequest::CredentialsDelete => self.credentials_delete().await?,
                ChannelRequest::CredentialsFetch => self.credentials_fetch().await?,
                ChannelRequest::CredentialsStore(creds) => self.credentials_store(creds).await?,
            };

            info!("Response: {res}");

            client.send_response(res).await?;
        }
    }
}

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let socket_path = create_socket_name()?;

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
