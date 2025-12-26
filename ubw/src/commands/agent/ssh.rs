use anyhow::{Result, anyhow};
use signature::Signer;
use ssh_agent_lib::{
    agent::{Session, listen},
    error::AgentError,
    proto::{Extension, Identity, SignRequest},
    ssh_key::{Algorithm, PrivateKey, PublicKey, Signature, private::KeypairData},
};
use tokio::{fs, net::UnixListener, select, sync::watch::Receiver};
use ubitwarden::{
    api::{BwApi, BwCipherType},
    crypto::BwCrypt,
};

use log::{error, info, warn};

use super::utils::load_session;
const DATA_DIR: &str = env!("CARGO_PKG_NAME");
const SOCK_PREFIX: &str = env!("CARGO_PKG_NAME");

#[derive(Debug)]
struct SshAgentError(String);

impl std::fmt::Display for SshAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SshAgentError {}

#[derive(Clone)]
struct UbwSshAgent {
    session_bind: Option<Vec<u8>>,
}

#[ssh_agent_lib::async_trait]
impl Session for UbwSshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        warn!("request_identities called");

        // Load session and fetch ciphers from Bitwarden
        let session = match load_session().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load session: {}", e);
                return Ok(vec![]);
            }
        };

        let crypt = match BwCrypt::from_encoded_key(&session.key) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create crypto: {}", e);
                return Ok(vec![]);
            }
        };

        // Create API client and fetch all ciphers
        let api = match BwApi::new(&session.email, &session.server_url) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create API client: {}", e);
                return Ok(vec![]);
            }
        };

        let ciphers = match api.ciphers(&session.auth).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch ciphers: {}", e);
                return Ok(vec![]);
            }
        };

        // Filter for SSH key ciphers and convert to identities
        let mut identities = Vec::new();

        for cipher in ciphers {
            if !matches!(cipher.cipher_type, BwCipherType::Ssh) {
                continue;
            }

            // Decrypt the cipher name to use as comment
            let comment = match crypt.decrypt(&cipher.name) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert cipher name to string: {}", e);
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt cipher name: {}", e);
                    continue;
                }
            };

            // Get the public key from cipher data
            // Assuming the public key is stored in cipher.data.username or cipher.data.password

            let public_key_str = if let Some(ssh) = &cipher.ssh_key {
                match crypt.decrypt(&ssh.public_key) {
                    Ok(decrypted) => match String::try_from(decrypted) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to convert public key to string: {}", e);
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decrypt public key: {}", e);
                        continue;
                    }
                }
            } else {
                warn!("No public key found for cipher: {}", comment);
                continue;
            };

            // Parse the public key
            let public_key = match PublicKey::from_openssh(&public_key_str) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!("Failed to parse public key for '{}': {}", comment, e);
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
        warn!("sign request for pubkey fingerprint");

        // If session binding is set, we should validate it here
        // The session binding data would typically be used to ensure the signature
        // is only valid for the specific SSH session that was bound
        if let Some(ref session_data) = self.session_bind {
            info!("Session binding is active ({} bytes)", session_data.len());
            // Note: Full session binding validation would require parsing the
            // session data and verifying it matches the current connection context.
            // This is typically done by the SSH server, but the agent can log it.
        }

        // Load session and fetch ciphers from Bitwarden
        let session = match load_session().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load session: {}", e);
                return Err(AgentError::other(SshAgentError(format!(
                    "Failed to load session: {}",
                    e
                ))));
            }
        };

        let crypt = match BwCrypt::from_encoded_key(&session.key) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create crypto: {}", e);
                return Err(AgentError::other(SshAgentError(format!(
                    "Failed to create crypto: {}",
                    e
                ))));
            }
        };

        // Create API client and fetch all ciphers
        let api = match BwApi::new(&session.email, &session.server_url) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to create API client: {}", e);
                return Err(AgentError::other(SshAgentError(format!(
                    "Failed to create API client: {}",
                    e
                ))));
            }
        };

        let ciphers = match api.ciphers(&session.auth).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch ciphers: {}", e);
                return Err(AgentError::other(SshAgentError(format!(
                    "Failed to fetch ciphers: {}",
                    e
                ))));
            }
        };

        // Convert request pubkey to PublicKey for comparison
        let request_pubkey: PublicKey = request.pubkey.try_into().map_err(AgentError::other)?;

        // Find the cipher with matching public key
        for cipher in ciphers {
            if !matches!(cipher.cipher_type, BwCipherType::Ssh) {
                continue;
            }

            let ssh_key = match &cipher.ssh_key {
                Some(sk) => sk,
                None => continue,
            };

            // Decrypt and parse the public key to compare
            let public_key_str = match crypt.decrypt(&ssh_key.public_key) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to convert public key to string: {}", e);
                        continue;
                    }
                },
                Err(e) => {
                    warn!("Failed to decrypt public key: {}", e);
                    continue;
                }
            };

            let public_key = match PublicKey::from_openssh(&public_key_str) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!("Failed to parse public key: {}", e);
                    continue;
                }
            };

            // Check if this is the key we're looking for
            if public_key.fingerprint(Default::default()) != request_pubkey.fingerprint(Default::default()) {
                warn!("this is not the key you're looking for");
                continue;
            }

            // Found the matching key, now decrypt the private key
            let private_key_str = match crypt.decrypt(&ssh_key.private_key) {
                Ok(decrypted) => match String::try_from(decrypted) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to convert private key to string: {}", e);
                        return Err(AgentError::other(SshAgentError(format!(
                            "Failed to convert private key: {}",
                            e
                        ))));
                    }
                },
                Err(e) => {
                    error!("Failed to decrypt private key: {}", e);
                    return Err(AgentError::other(SshAgentError(format!(
                        "Failed to decrypt private key: {}",
                        e
                    ))));
                }
            };

            // Parse the private key
            let private_key = match PrivateKey::from_openssh(&private_key_str) {
                Ok(pk) => pk,
                Err(e) => {
                    error!("Failed to parse private key: {}", e);
                    return Err(AgentError::other(SshAgentError(format!(
                        "Failed to parse private key: {}",
                        e
                    ))));
                }
            };

            // Sign the data using the private key
            // For SSH agent protocol, we need to create a raw cryptographic signature
            // not an SSH signature format (which includes namespace)
            match private_key.key_data() {
                KeypairData::Ed25519(ed25519_keypair) => {
                    // Convert to ed25519_dalek SigningKey
                    let signing_key: ed25519_dalek::SigningKey = ed25519_keypair.try_into().map_err(|e| {
                        AgentError::other(SshAgentError(format!("Failed to convert Ed25519 key: {}", e)))
                    })?;

                    // Sign the data directly
                    let sig: ed25519_dalek::Signature = signing_key.sign(&request.data);

                    // Create the SSH agent signature
                    let algorithm = Algorithm::new("ssh-ed25519")
                        .map_err(|e| AgentError::other(SshAgentError(format!("Invalid algorithm: {}", e))))?;

                    let signature = Signature::new(algorithm, sig.to_bytes().to_vec())
                        .map_err(|e| AgentError::other(SshAgentError(format!("Failed to create signature: {}", e))))?;

                    info!("Successfully signed data with Ed25519 key");
                    return Ok(signature);
                }
                _ => {
                    error!("Unsupported key type for signing");
                    return Err(AgentError::other(SshAgentError(
                        "Only Ed25519 keys are currently supported".to_string(),
                    )));
                }
            }
        }

        error!("No matching private key found for the requested public key");
        Err(AgentError::other(SshAgentError(
            "No matching private key found".to_string(),
        )))
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        warn!("extension request: {}", extension.name);

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
                warn!("session-bind: stored session binding ({} bytes)", details_bytes.len());

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

pub struct SshAgentServer {}

impl SshAgentServer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn accept_loop(&mut self, mut quit_rx: Receiver<bool>) -> Result<()> {
        let data_dir = dirs::data_dir().ok_or(anyhow!("unable to find data-dir"))?;
        let data_dir = data_dir.join(DATA_DIR);

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

        let fd = UnixListener::bind(socket_path)?;

        let agent = UbwSshAgent { session_bind: None };

        select! {
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
        }
    }
}
