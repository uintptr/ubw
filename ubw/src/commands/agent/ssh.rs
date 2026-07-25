use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use signature::Signer;
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::{
    proto::{Extension, Identity, Request, Response, SignRequest},
    ssh_key::{Algorithm, PrivateKey, PublicKey, Signature, private::KeypairData},
};
use ubitwarden::api::BwApi;
use ubitwarden::api_types::{BwCipherData, BwSshKey};
use ubitwarden::session::BwSession;

use log::{error, info, warn};
use ubitwarden_agent::agent::UBWAgent;

use crate::commands::agent::{ShutdownReason, signal_shutdown};
use crate::common::UBW_DATA_DIR;

const SOCK_PREFIX: &str = env!("CARGO_PKG_NAME");

/// The largest agent message we're willing to allocate for. OpenSSH caps
/// messages at 256KiB, so anything past that is a bogus length prefix.
const MAX_MESSAGE_LEN: usize = 256 * 1024;

struct BwSshAgent {
    session_bind: Option<Vec<u8>>,
    cache: Arc<RwLock<HashMap<String, PrivateKey>>>,
}

impl BwSshAgent {
    pub fn new(cache: Arc<RwLock<HashMap<String, PrivateKey>>>) -> Self {
        Self {
            session_bind: None,
            cache,
        }
    }

    fn find_key_cache(&self, public_key: &str) -> Result<PrivateKey> {
        let keys = self.cache.read().map_err(|_| anyhow!("SSH key cache lock was poisoned"))?;
        if let Some(key) = keys.get(public_key) {
            return Ok(key.clone());
        }

        bail!("{public_key} was not cached")
    }

    fn find_key_remote(public_key: &str) -> Result<PrivateKey> {
        //
        // Get keys from the server and find it
        //
        let (crypt, ssh_keys) = get_remote_keys().context("Failed to fetch SSH keys from remote server")?;

        for ssh_key in ssh_keys {
            let cur_pub_b64 = match crypt.decrypt(&ssh_key.public_key) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert public key to string: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt public key: {e}");
                    continue;
                }
            };

            if cur_pub_b64 != public_key {
                continue;
            }

            //
            // Ok we have the key
            //

            let cur_pri_b64 = match crypt.decrypt(&ssh_key.private_key) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert public key to string: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt public key: {e}");
                    continue;
                }
            };

            let cur_pri = match PrivateKey::from_openssh(cur_pri_b64) {
                Ok(v) => v,
                Err(e) => {
                    error!("{e}");
                    continue;
                }
            };

            return Ok(cur_pri);
        }

        bail!("private key not found");
    }

    fn add_key(&self, public_key: &str, private_key: &PrivateKey) -> Result<()> {
        info!("adding {public_key} to cache");
        let mut keys = self
            .cache
            .write()
            .map_err(|_| anyhow!("SSH key cache lock was poisoned during write"))?;
        keys.insert(public_key.to_string(), private_key.clone());
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // PUBLIC
    ////////////////////////////////////////////////////////////////////////////
    pub fn find_key(&self, public_key: &PublicKey) -> Result<PrivateKey> {
        let pub_key_openssh = public_key
            .to_openssh()
            .context("Failed to convert public key to OpenSSH format")?;

        //
        // is it cached ?
        //
        if let Ok(key) = self.find_key_cache(&pub_key_openssh) {
            info!("{pub_key_openssh} was cached");
            return Ok(key);
        }

        info!("{pub_key_openssh} was not cached");

        if let Ok(key) = Self::find_key_remote(&pub_key_openssh) {
            //
            // add it to the cache for the next time around
            //
            self.add_key(&pub_key_openssh, &key)
                .context("Failed to cache SSH key after remote retrieval")?;
            return Ok(key);
        }

        bail!("SSH key '{pub_key_openssh}' not found in cache or remote server");
    }
}

fn get_remote_keys() -> Result<(BwSession, Vec<BwSshKey>)> {
    let mut agent = UBWAgent::client().context("Failed to connect to local credential cache")?;

    // Load session and fetch ciphers from Bitwarden
    let session = agent.session_load().context("Failed to load Bitwarden session from cache")?;

    // Create API client and fetch all ciphers
    let api = BwApi::new(&session.email, &session.server_url)
        .with_context(|| format!("Failed to initialize API client for {}", session.email))?;

    let mut ssh_keys = vec![];
    for cipher in api
        .ssh_keys(&session.auth)
        .context("Failed to fetch SSH keys from Bitwarden server")?
    {
        if let BwCipherData::Ssh(ssh) = cipher.data {
            ssh_keys.push(ssh);
        }
    }

    Ok((session, ssh_keys))
}

////////////////////////////////////////////////////////////////////////////////
// PROTOCOL
////////////////////////////////////////////////////////////////////////////////

impl BwSshAgent {
    fn request_identities() -> Vec<Identity> {
        let (crypt, ssh_keys) = match get_remote_keys() {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to get keys from remote server ({e})");
                return vec![];
            }
        };

        let mut identities = Vec::new();

        for ssh_key in ssh_keys {
            // Decrypt the fingerprint to use as comment

            let name = if let Some(v) = &ssh_key.name {
                v
            } else {
                &ssh_key.key_fingerprint
            };

            let comment = match crypt.decrypt(name) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert cipher name to string: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt cipher name: {e}");
                    continue;
                }
            };

            let public_key_b64 = match crypt.decrypt(&ssh_key.public_key) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert cipher name to string: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt cipher name: {e}");
                    continue;
                }
            };

            // Parse the public key
            let public_key = match PublicKey::from_openssh(&public_key_b64) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!("Failed to parse public key for '{comment}': {e}");
                    continue;
                }
            };

            identities.push(Identity {
                pubkey: public_key.into(),
                comment,
            });
        }

        info!("Returning {} SSH identities", identities.len());
        identities
    }

    fn sign(&self, request: SignRequest) -> Result<Signature> {
        // If session binding is set, we should validate it here
        // The session binding data would typically be used to ensure the signature
        // is only valid for the specific SSH session that was bound
        if let Some(ref session_data) = self.session_bind {
            info!("Session binding is active ({} bytes)", session_data.len());
            // Note: Full session binding validation would require parsing the
            // session data and verifying it matches the current connection context.
            // This is typically done by the SSH server, but the agent can log it.
        }

        // Convert request pubkey to PublicKey for comparison
        let request_pubkey: PublicKey = <KeyData as Into<PublicKey>>::into(request.pubkey);

        // this'll lookup the cache first and fallback on asking the server
        let private_key = self.find_key(&request_pubkey).context("No matching private key found")?;

        // Sign the data using the private key
        // For SSH agent protocol, we need to create a raw cryptographic signature
        // not an SSH signature format (which includes namespace)
        if let KeypairData::Ed25519(ed25519_keypair) = private_key.key_data() {
            // Convert to ed25519_dalek SigningKey
            let signing_key: ed25519_dalek::SigningKey = ed25519_keypair
                .try_into()
                .map_err(|e| anyhow!("Failed to convert Ed25519 key: {e}"))?;

            // Sign the data directly
            let sig: ed25519_dalek::Signature = signing_key.sign(&request.data);

            // Create the SSH agent signature
            let algorithm = Algorithm::new("ssh-ed25519").context("Invalid algorithm")?;

            let signature = Signature::new(algorithm, sig.to_bytes().to_vec()).context("Failed to create signature")?;

            info!("Successfully signed data with Ed25519 key");
            return Ok(signature);
        }

        bail!("Only Ed25519 keys are currently supported")
    }

    fn extension(&mut self, extension: &Extension) -> Result<Option<Extension>> {
        match extension.name.as_str() {
            // Handle the query extension - returns which extensions are supported
            "query" => {
                // Return a list of supported extensions
                let supported_extensions = b"query\0session-bind@openssh.com".to_vec();
                Ok(Some(Extension {
                    name: "query".to_string(),
                    details: supported_extensions.into(),
                }))
            }

            // Session binding extension - prevents session hijacking
            "session-bind@openssh.com" => {
                // The details contain the session identifier (hostkey, session_id, signature, etc.)
                // Store the session binding information for validation during sign operations
                let details_bytes: &[u8] = extension.details.as_ref();
                if details_bytes.is_empty() {
                    bail!("session-bind: empty details provided");
                }

                self.session_bind = Some(details_bytes.to_vec());
                info!("session-bind: stored session binding ({} bytes)", details_bytes.len());

                // Return success with no response data
                Ok(None)
            }

            // Unknown or unsupported extension
            name => bail!("unsupported extension: {name}"),
        }
    }

    /// Turn a request into the response we owe the client.
    ///
    /// A failed request is a `Failure` response, not a dead connection, so this
    /// deliberately swallows errors after logging them.
    fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::RequestIdentities => Response::IdentitiesAnswer(Self::request_identities()),
            Request::SignRequest(request) => match self.sign(request) {
                Ok(signature) => Response::SignResponse(signature),
                Err(e) => {
                    error!("unable to sign ({e})");
                    Response::Failure
                }
            },
            Request::Extension(extension) => match self.extension(&extension) {
                Ok(Some(response)) => Response::ExtensionResponse(response),
                Ok(None) => Response::Success,
                Err(e) => {
                    warn!("{e}");
                    Response::ExtensionFailure
                }
            },
            other => {
                warn!("unsupported request: {}", other.message_id());
                Response::Failure
            }
        }
    }
}

/// Read one length prefixed request, or `None` once the client hangs up.
fn read_request<R>(stream: &mut R) -> Result<Option<Request>>
where
    R: Read,
{
    let mut len_buf = [0u8; 4];

    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("Failed to read the agent message length"),
    }

    let len = usize::try_from(u32::from_be_bytes(len_buf))?;

    if len > MAX_MESSAGE_LEN {
        bail!("agent message of {len} bytes is over the {MAX_MESSAGE_LEN} byte limit");
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .with_context(|| format!("Failed to read a {len} byte agent message"))?;

    let mut reader = buf.as_slice();
    let request = Request::decode(&mut reader).context("Failed to decode the agent message")?;

    Ok(Some(request))
}

/// Write a response, length prefixed the way the client expects it.
fn write_response<W>(stream: &mut W, response: &Response) -> Result<()>
where
    W: Write,
{
    let len = u32::try_from(response.encoded_len().context("Failed to size the agent response")?)?;

    let mut out = Vec::new();
    len.encode(&mut out).context("Failed to encode the response length")?;
    response.encode(&mut out).context("Failed to encode the response")?;

    stream.write_all(&out).context("Failed to write the agent response")?;
    stream.flush().context("Failed to flush the agent response")?;

    Ok(())
}

/// Serve one client until it hangs up.
fn session_loop(mut agent: BwSshAgent, mut stream: UnixStream) -> Result<()> {
    loop {
        let Some(request) = read_request(&mut stream)? else {
            info!("ssh client disconnected");
            return Ok(());
        };

        info!("Request: {}", request.message_id());

        let response = agent.handle(request);

        write_response(&mut stream, &response)?;
    }
}

////////////////////////////////////////////////////////////////////////////////
// SERVER
////////////////////////////////////////////////////////////////////////////////

pub struct SshAgentServer {
    listener: UnixListener,
    socket_path: PathBuf,
    cache: Arc<RwLock<HashMap<String, PrivateKey>>>,
}

impl SshAgentServer {
    pub fn new() -> Result<Self> {
        let data_dir = dirs::data_dir().context("Failed to determine data directory for SSH agent socket")?;
        let data_dir = data_dir.join(UBW_DATA_DIR);

        // create data dir if it doesn't exist
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)
                .with_context(|| format!("Failed to create data directory at {}", data_dir.display()))?;
        }

        let socket_name = format!("{SOCK_PREFIX}.sock");
        let socket_path = data_dir.join(socket_name);

        if socket_path.exists() {
            warn!("deleting {}", socket_path.display());
            fs::remove_file(&socket_path).with_context(|| {
                format!(
                    "Failed to remove existing SSH agent socket at {}",
                    socket_path.display()
                )
            })?;
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("Failed to bind SSH agent socket at {}", socket_path.display()))?;

        let perms = Permissions::from_mode(0o600);
        fs::set_permissions(&socket_path, perms).with_context(|| {
            format!(
                "Failed to set permissions on SSH agent socket at {}",
                socket_path.display()
            )
        })?;

        Ok(Self {
            listener,
            socket_path,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Serve ssh clients until the listener breaks.
    ///
    /// One thread per connection: `ssh` keeps its connection open for the whole
    /// session, so a serial loop would block the second `ssh` indefinitely.
    pub fn accept_loop(&self, shutdown: &Sender<ShutdownReason>) {
        loop {
            info!("accepting ssh clients");

            let client = match self.listener.accept() {
                Ok((client, _)) => client,
                Err(e) => {
                    error!("ssh accept failure ({e})");
                    signal_shutdown(shutdown, ShutdownReason::ListenerFailed("ssh-agent"));
                    return;
                }
            };

            let agent = BwSshAgent::new(Arc::clone(&self.cache));

            let spawned = thread::Builder::new().name("ssh-client".into()).spawn(move || {
                if let Err(e) = session_loop(agent, client) {
                    error!("ssh session failed ({e})");
                }
            });

            if let Err(e) = spawned {
                error!("unable to spawn an ssh client thread ({e})");
            }
        }
    }
}
