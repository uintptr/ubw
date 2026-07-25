use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, mpsc::Sender},
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use log::{error, info, warn};
use secrecy::zeroize::Zeroize;
use ubitwarden::{credentials::BwCredentials, error::Error, session::BwSessionData};
use ubitwarden_agent::{
    agent::{UBWAgent, bind_cache_socket, cache_socket_cleanup_path, is_disconnect},
    messages::{ChannelRequest, ChannelResponse},
};

use crate::commands::agent::{
    ShutdownReason, signal_shutdown,
    storage::{CredStorage, CredStorageTrait},
};

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
    socket_path: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn get_peer_pid(client: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .context("Failed to compute socket credential structure size")?;

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
        Err(Error::ClientPidNotFound).context("getsockopt(SO_PEERCRED) failed - unable to get client credentials")
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

    fn read_store(&self) -> Result<RwLockReadGuard<'_, CredStorage>> {
        self.storage_lock
            .read()
            .map_err(|_| anyhow!("credential storage lock was poisoned"))
    }

    fn write_store(&self) -> Result<RwLockWriteGuard<'_, CredStorage>> {
        self.storage_lock
            .write()
            .map_err(|_| anyhow!("credential storage lock was poisoned"))
    }

    //
    // Session
    //
    fn session_store(&self, data: &BwSessionData) -> Result<ChannelResponse> {
        let mut session_string = serde_json::to_string(data)?;

        let mut store = self.write_store()?;

        let success = store.add("session", &session_string).is_ok();

        session_string.zeroize();

        Ok(ChannelResponse::Status(success))
    }

    fn session_fetch(&self) -> Result<ChannelResponse> {
        let store = self.read_store()?;

        let res = if let Some(mut session_string) = store.get("session") {
            let session: BwSessionData = serde_json::from_str(&session_string)?;
            session_string.zeroize();
            ChannelResponse::SessionFetch(session)
        } else {
            ChannelResponse::Error("Not Found".to_string())
        };

        Ok(res)
    }

    fn session_delete(&self) -> Result<ChannelResponse> {
        let mut store = self.write_store()?;

        store.remove("session");

        Ok(ChannelResponse::Status(true))
    }

    //
    // Credentials
    //

    fn credentials_fetch(&self) -> Result<ChannelResponse> {
        let store = self.read_store()?;

        let res = if let Some(mut creds_string) = store.get("credentials") {
            let creds: BwCredentials = serde_json::from_str(&creds_string)?;
            creds_string.zeroize();
            ChannelResponse::CredentialsFetch(creds)
        } else {
            ChannelResponse::Error("Not Found".to_string())
        };

        Ok(res)
    }

    fn credentials_delete(&self) -> Result<ChannelResponse> {
        let mut store = self.write_store()?;

        store.remove("credentials");

        Ok(ChannelResponse::Status(true))
    }

    fn credentials_store(&self, creds: &BwCredentials) -> Result<ChannelResponse> {
        let mut creds_string = serde_json::to_string(creds)?;
        let mut store = self.write_store()?;

        let success = store.add("credentials", &creds_string).is_ok();

        creds_string.zeroize();

        Ok(ChannelResponse::Status(success))
    }

    fn client_handler(&self, client: UnixStream) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let verified = verify_client(&client).context("Client verification failed for incoming connection")?;
            if !verified {
                error!("Verification failed");
                return Err(Error::ClientVerificationFailure.into());
            }
        }

        let mut client = UBWAgent::server(client).context("Failed to initialize server protocol handler for client")?;

        loop {
            info!("waiting for a request");

            let req = match client.get_request() {
                Ok(req) => req,
                //
                // A client that is done with us just closes the socket
                //
                Err(Error::Io(e)) if is_disconnect(&e) => break Ok(()),
                Err(e) => return Err(e).context("Failed to receive request from client"),
            };

            info!("Request: {req}");

            let res = match req {
                ChannelRequest::Hello { public_key: _ } => bail!("Out of order"),
                ChannelRequest::Stop => break Err(Error::Shutdown.into()),
                //
                // Session
                //
                ChannelRequest::SessionStore(data) => self.session_store(&data)?,
                ChannelRequest::SessionFetch => self.session_fetch()?,
                ChannelRequest::SessionDelete => self.session_delete()?,
                //
                // Credentials
                //
                ChannelRequest::CredentialsDelete => self.credentials_delete()?,
                ChannelRequest::CredentialsFetch => self.credentials_fetch()?,
                ChannelRequest::CredentialsStore(creds) => self.credentials_store(&creds)?,
            };

            info!("Response: {res}");

            client.send_response(&res)?;
        }
    }
}

impl CacheServer {
    pub fn new() -> Result<Self> {
        info!("binding unix socket");

        let listener = bind_cache_socket().context("Failed to bind the credentials cache socket")?;

        let socket_path = cache_socket_cleanup_path().context("Failed to determine socket path")?;

        let storage_lock = Arc::new(RwLock::new(
            CredStorage::new().context("Failed to initialize credential storage")?,
        ));

        Ok(Self {
            listener,
            storage_lock,
            socket_path,
        })
    }

    /// The socket to unlink at shutdown, or `None` when the platform doesn't
    /// keep one on disk.
    pub fn socket_path(&self) -> Option<&Path> {
        self.socket_path.as_deref()
    }

    /// Serve clients until the listener breaks.
    ///
    /// Every client gets its own thread: a client can hold its connection open
    /// across an interactive password prompt, and the ssh-agent side of the
    /// daemon is itself a client, so serving them one at a time would deadlock.
    pub fn accept_loop(&self, shutdown: &Sender<ShutdownReason>) {
        loop {
            info!("accepting clients");

            let client = match self.listener.accept() {
                Ok((client, _)) => client,
                Err(e) => {
                    error!("accept failure ({e})");
                    signal_shutdown(shutdown, ShutdownReason::ListenerFailed("credentials"));
                    return;
                }
            };

            let handler = ClientHandler::new(Arc::clone(&self.storage_lock));
            let shutdown = shutdown.clone();

            let spawned = thread::Builder::new()
                .name("creds-client".into())
                .spawn(move || handle_client(&handler, client, &shutdown));

            if let Err(e) = spawned {
                error!("unable to spawn a client thread ({e})");
            }
        }
    }
}

fn handle_client(handler: &ClientHandler, client: UnixStream, shutdown: &Sender<ShutdownReason>) {
    let ret = handler.client_handler(client);

    warn!("client disconnected");

    if let Err(e) = ret {
        if let Some(Error::Shutdown) = e.downcast_ref::<Error>() {
            signal_shutdown(shutdown, ShutdownReason::StopRequested);
        } else {
            error!("{e}");
        }
    }
}
