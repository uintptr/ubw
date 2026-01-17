use std::collections::HashMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, RwLock};

use anyhow::{Result, anyhow, bail};
use signature::Signer;
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::{
    agent::{Session, listen},
    error::AgentError,
    proto::{Extension, Identity, SignRequest},
    ssh_key::{Algorithm, PrivateKey, PublicKey, Signature, private::KeypairData},
};
use tokio::{fs, net::UnixListener, select, sync::watch::Receiver};
use ubitwarden::api::BwApi;
use ubitwarden::api_types::{BwCipherData, BwSshKey};
use ubitwarden::session::BwSession;

use log::{error, info, warn};
use ubitwarden_agent::agent::UBWAgent;

use crate::common::UBW_DATA_DIR;

const SOCK_PREFIX: &str = env!("CARGO_PKG_NAME");

#[derive(Clone)]
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
        let keys = self.cache.read().map_err(|e| anyhow!("Cache lock poisoned: {e}"))?;
        if let Some(key) = keys.get(public_key) {
            return Ok(key.clone());
        }

        bail!("{public_key} was not cached")
    }

    async fn find_key_remote(&self, public_key: &str) -> Result<PrivateKey> {
        //
        // Get keys from the server and find it
        //
        let (crypt, ssh_keys) = get_remote_keys().await?;

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
        let mut keys = self.cache.write().map_err(|e| anyhow!("Cache lock poisoned: {e}"))?;
        keys.insert(public_key.to_string(), private_key.clone());
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // PUBLIC
    ////////////////////////////////////////////////////////////////////////////
    pub async fn find_key(&self, public_key: &PublicKey) -> Result<PrivateKey> {
        let pub_key_openssh = public_key.to_openssh()?;

        //
        // is it cached ?
        //
        if let Ok(key) = self.find_key_cache(&pub_key_openssh) {
            info!("{pub_key_openssh} was cached");
            return Ok(key);
        }

        info!("{pub_key_openssh} was not cached");

        if let Ok(key) = self.find_key_remote(&pub_key_openssh).await {
            //
            // add it to the cache for the next time around
            //
            self.add_key(&pub_key_openssh, &key)?;
            return Ok(key);
        }

        bail!("Key Not found");
    }
}

async fn get_remote_keys() -> Result<(BwSession, Vec<BwSshKey>)> {
    let mut agent = UBWAgent::client().await?;

    // Load session and fetch ciphers from Bitwarden
    let session = agent.session_load().await?;

    // Create API client and fetch all ciphers
    let api = BwApi::new(&session.email, &session.server_url)?;

    let mut ssh_keys = vec![];
    for cipher in api.ssh_keys(&session.auth).await? {
        if let BwCipherData::Ssh(ssh) = cipher.data {
            ssh_keys.push(ssh);
        }
    }

    Ok((session, ssh_keys))
}

#[ssh_agent_lib::async_trait]
impl Session for BwSshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let (crypt, ssh_keys) = match get_remote_keys().await {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to get keys from remote server ({e})");
                return Ok(vec![]);
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
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
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
        let private_key = match self.find_key(&request_pubkey).await {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to get keys from remote server ({e})");
                return Err(AgentError::Other("No matching private key found".into()));
            }
        };

        // Sign the data using the private key
        // For SSH agent protocol, we need to create a raw cryptographic signature
        // not an SSH signature format (which includes namespace)
        if let KeypairData::Ed25519(ed25519_keypair) = private_key.key_data() {
            // Convert to ed25519_dalek SigningKey
            let signing_key: ed25519_dalek::SigningKey = ed25519_keypair
                .try_into()
                .map_err(|e| AgentError::Other(format!("Failed to convert Ed25519 key: {e}").into()))?;

            // Sign the data directly
            let sig: ed25519_dalek::Signature = signing_key.sign(&request.data);

            // Create the SSH agent signature
            let algorithm = Algorithm::new("ssh-ed25519")
                .map_err(|e| AgentError::Other(format!("Invalid algorithm: {e}").into()))?;

            let signature = Signature::new(algorithm, sig.to_bytes().to_vec())
                .map_err(|e| AgentError::Other(format!("Failed to create signature: {e}").into()))?;

            info!("Successfully signed data with Ed25519 key");
            return Ok(signature);
        }

        Err(AgentError::Other("Only Ed25519 keys are currently supported".into()))
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
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
                    warn!("session-bind: empty details provided");
                    return Err(AgentError::ExtensionFailure);
                }

                self.session_bind = Some(details_bytes.to_vec());
                info!("session-bind: stored session binding ({} bytes)", details_bytes.len());

                // Return success with no response data
                Ok(None)
            }

            // Unknown or unsupported extension
            _ => {
                warn!("unsupported extension: {}", extension.name);
                Err(AgentError::ExtensionFailure)
            }
        }
    }
}

pub struct SshAgentServer {
    cache: Arc<RwLock<HashMap<String, PrivateKey>>>,
}

impl SshAgentServer {
    pub fn new() -> Self {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        Self { cache }
    }

    pub async fn accept_loop(&self, mut quit_rx: Receiver<bool>) -> Result<()> {
        let data_dir = dirs::data_dir().ok_or_else(|| anyhow!("unable to find data-dir"))?;
        let data_dir = data_dir.join(UBW_DATA_DIR);

        // create data dir if it doesn't exist
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir).await?;
        }

        let socket_name = format!("{SOCK_PREFIX}.sock");
        let socket_path = data_dir.join(socket_name);

        if socket_path.exists() {
            warn!("deleting {}", socket_path.display());
            fs::remove_file(&socket_path).await?;
        }

        let fd = UnixListener::bind(&socket_path)?;

        let perms = Permissions::from_mode(0o600);
        fs::set_permissions(&socket_path, perms).await?;

        let agent = BwSshAgent::new(Arc::clone(&self.cache));

        let ret = select! {
            _ = quit_rx.changed() => Ok(()),
            ret = listen(fd, agent) => {
                match ret{
                    Ok(()) => Ok(()),
                    Err(e) => {
                        error!("listen() returned {e}");
                        Err(e.into())
                    }
                }
            }
        };

        if socket_path.exists() {
            info!("Deleting {}", socket_path.display());

            if let Err(e) = fs::remove_file(&socket_path).await {
                error!("Unable to delete {} ({e})", socket_path.display());
            }
        }

        ret
    }
}
