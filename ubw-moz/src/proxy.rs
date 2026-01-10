#![allow(unused)]
use std::{
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::Aes256;
use anyhow::{Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit},
};
use hmac::{Hmac, Mac};
use log::{error, info};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize, Serializer};
use sha1::Sha1;
use sha2::Sha256;
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, Stdin, Stdout},
};
use ubitwarden_agent::agent::UBWAgent;

#[derive(Deserialize)]
struct CommandMessage {
    pub command: String,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "messageId")]
    pub message_id: u64,
    pub timestamp: u64,
}

#[derive(Deserialize)]
struct CommandRequest {
    #[serde(rename = "appId")]
    pub app_id: String,
    pub message: CommandMessage,
}

#[derive(Deserialize)]
struct EncryptedData {
    #[serde(rename = "encryptedString")]
    pub encrypted_string: String,
    #[serde(rename = "encryptionType")]
    pub encryption_type: u32,
    pub data: String,
    pub iv: String,
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedMessage {
    #[serde(rename = "encryptedString")]
    pub encrypted_string: String,
    #[serde(rename = "encryptionType")]
    pub encryption_type: u32,
    pub data: String,
    pub iv: String,
    pub mac: String,
}

#[derive(Deserialize)]
struct DecryptRequest {
    #[serde(rename = "appId")]
    pub app_id: String,
    pub message: EncryptedMessage,
}

#[derive(Serialize)]
struct NativeMessageResponse<'a> {
    #[serde(rename = "appId")]
    pub app_id: &'a str,
    pub command: &'a str,
    #[serde(rename = "messageId")]
    pub message_id: i64,
    #[serde(rename = "sharedSecret")]
    pub shared_secret: &'a str,
}

#[derive(Serialize)]
struct GetBiometricStatus<'a> {
    pub command: &'a str,
    #[serde(rename = "messageId")]
    pub message_id: u64,
    pub response: i64,
    pub timestamp: i64,
}

#[derive(Serialize)]
struct UnlockVaultStatus<'a> {
    pub command: &'a str,
    #[serde(rename = "messageId")]
    pub message_id: u64,
    pub response: bool,
    #[serde(rename = "userKeyB64")]
    pub user_key_b64: Option<String>,
}

#[derive(Serialize)]
struct EncryptedResponse<'a> {
    #[serde(rename = "appId")]
    pub app_id: &'a str,
    #[serde(rename = "messageId")]
    pub message_id: u64,
    pub message: EncryptedMessage,
}

struct UBwMozSessionKey {
    pub key: Vec<u8>,
}

impl UBwMozSessionKey {
    fn new() -> Self {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 64]; // Generate a 64-byte (512-bit) session key
        rng.fill_bytes(&mut key);

        Self { key }
    }

    pub fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        // Decode base64 components
        let iv = BASE64_STANDARD.decode(&encrypted.iv)?;
        let data = BASE64_STANDARD.decode(&encrypted.data)?;
        let mac = BASE64_STANDARD.decode(&encrypted.mac)?;

        // Split session key: first 32 bytes = encryption key, last 32 bytes = MAC key
        let enc_key = &self.key[0..32];
        let mac_key = &self.key[32..64];

        // Verify HMAC-SHA256
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)?;
        hmac.update(&iv);
        hmac.update(&data);
        hmac.verify_slice(&mac)?;

        // Decrypt AES-256-CBC
        let cipher = Decryptor::<Aes256>::new_from_slices(enc_key, &iv)?;
        let decrypted = cipher
            .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&data)
            .map_err(|e| anyhow::anyhow!("Decryption padding error: {:?}", e))?;

        Ok(decrypted)
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<EncryptedMessage> {
        use cbc::{
            Encryptor,
            cipher::{BlockEncryptMut, KeyIvInit},
        };
        use rand::RngCore;

        // Generate random 16-byte IV
        let mut rng = rand::thread_rng();
        let mut iv = vec![0u8; 16];
        rng.fill_bytes(&mut iv);

        // Split session key: first 32 bytes = encryption key, last 32 bytes = MAC key
        let enc_key = &self.key[0..32];
        let mac_key = &self.key[32..64];

        // Encrypt AES-256-CBC with PKCS7 padding
        let cipher = Encryptor::<Aes256>::new_from_slices(enc_key, &iv)?;
        let encrypted_data = cipher.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(msg);

        // Compute HMAC-SHA256
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)?;
        hmac.update(&iv);
        hmac.update(&encrypted_data);
        let mac = hmac.finalize().into_bytes();

        // Encode to base64
        let iv_b64 = BASE64_STANDARD.encode(&iv);
        let data_b64 = BASE64_STANDARD.encode(&encrypted_data);
        let mac_b64 = BASE64_STANDARD.encode(&mac);

        // Create encrypted string format: "2.iv|data|mac"
        let encrypted_string = format!("2.{}|{}|{}", iv_b64, data_b64, mac_b64);

        Ok(EncryptedMessage {
            encrypted_string,
            encryption_type: 2,
            data: data_b64,
            iv: iv_b64,
            mac: mac_b64,
        })
    }
}

struct UBwProxy {
    session_key: Option<UBwMozSessionKey>,
    app_id: Option<String>,
}

impl UBwProxy {
    pub fn new() -> Self {
        Self {
            session_key: None,
            app_id: None,
        }
    }

    async fn write_encrypted_message<S>(&mut self, w: &mut BufWriter<Stdout>, res: S, msg_id: u64) -> Result<()>
    where
        S: Serialize,
    {
        let app_id = match &self.app_id {
            Some(v) => v,
            None => bail!("Missing app id"),
        };

        let encoded_respose = serde_json::to_string(&res)?;

        if let Some(session_key) = &self.session_key {
            let encrypted_msg = session_key.encrypt(encoded_respose.as_bytes())?;

            // Wrap in the outer message structure expected by the browser
            let response = EncryptedResponse {
                app_id: app_id,
                message_id: msg_id,
                message: encrypted_msg,
            };

            let msg = serde_json::to_string(&response)?;

            // Write message length prefix (required by native messaging protocol)
            let msg_len: u32 = msg.len().try_into()?;
            w.write_u32_le(msg_len).await?;
            w.write_all(msg.as_bytes()).await?;
            w.flush().await?;
            Ok(())
        } else {
            bail!("Session key missing");
        }
    }

    async fn read_message(&mut self, rdr: &mut BufReader<Stdin>) -> Result<CommandMessage> {
        let data = read_buffer(rdr).await?;

        let msg = if let Ok(req) = serde_json::from_slice::<CommandRequest>(&data) {
            info!("using app_id={}", req.app_id);
            self.app_id = Some(req.app_id);
            req.message
        } else if let Ok(req) = serde_json::from_slice::<DecryptRequest>(&data) {
            if let Some(key) = &self.session_key {
                let enc_req: DecryptRequest = serde_json::from_slice(&data)?;

                let plain_data = key.decrypt_message(&enc_req.message)?;

                let msg: CommandMessage = serde_json::from_slice(&plain_data)?;

                msg
            } else {
                bail!("session key not found")
            }
        } else {
            bail!("Unable to deserialize");
        };

        Ok(msg)
    }

    async fn setup_encryption(&mut self, w: &mut BufWriter<Stdout>, msg: &CommandMessage) -> Result<()> {
        let app_id = match &self.app_id {
            Some(v) => v,
            None => bail!("Missing app id"),
        };

        let key = UBwMozSessionKey::new();

        let encrypted_key = encrypt_message(msg, &key.key)?;

        let resp = NativeMessageResponse {
            app_id: app_id,
            command: &msg.command,
            message_id: -1,
            shared_secret: &encrypted_key,
        };

        let message = serde_json::to_string(&resp)?;

        //
        // write len
        //
        let msg_len: u32 = message.len().try_into()?;
        w.write_u32_le(msg_len).await?;
        w.write_all(message.as_bytes()).await?;
        w.flush().await?;

        self.session_key = Some(key);

        Ok(())
    }

    async fn get_vault_key(&self) -> Result<String> {
        let mut agent = UBWAgent::new().await?;
        let session = agent.fetch_session().await?;

        Ok(session.export_key())
    }

    async fn cmd_unlock_vault(&mut self, w: &mut BufWriter<Stdout>, message_id: u64) -> Result<()> {
        let (response, user_key_b64) = match self.get_vault_key().await {
            Ok(v) => (true, Some(v)),
            Err(e) => {
                error!("Unable to get vault key ({e}");
                (false, None)
            }
        };

        let res = UnlockVaultStatus {
            command: "unlockWithBiometricsForUser",
            response,
            message_id,
            user_key_b64,
        };

        self.write_encrypted_message(w, &res, message_id).await
    }

    async fn cmd_biometric_for_user(&mut self, w: &mut BufWriter<Stdout>, msg_id: u64) -> Result<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        let res = GetBiometricStatus {
            command: "getBiometricsStatusForUser",
            message_id: msg_id,
            response: 0,
            timestamp: ts,
        };

        self.write_encrypted_message(w, &res, msg_id).await
    }

    async fn cmd_biometric_status(&mut self, w: &mut BufWriter<Stdout>, msg_id: u64) -> Result<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        let res = GetBiometricStatus {
            command: "getBiometricsStatus",
            message_id: msg_id,
            response: 0,
            timestamp: ts,
        };

        self.write_encrypted_message(w, &res, msg_id).await
    }
}

fn encrypt_message(msg: &CommandMessage, plain: &[u8]) -> Result<String> {
    let mut rng = rand::thread_rng(); // rand@0.8

    let der_key = if let Some(public_key) = &msg.public_key {
        BASE64_STANDARD.decode(public_key.as_bytes())?
    } else {
        bail!("public key missing");
    };

    let key = RsaPublicKey::from_public_key_der(&der_key)?;

    let padding = Oaep::new::<Sha1>();
    let encrypted_data = key.encrypt(&mut rng, padding, plain)?;

    Ok(BASE64_STANDARD.encode(encrypted_data))
}

async fn read_buffer(rdr: &mut BufReader<Stdin>) -> Result<Vec<u8>> {
    let len: usize = rdr.read_u32_le().await?.try_into()?;

    if 0 == len {
        error!("EOF");
        return Err(anyhow!("EOF"));
    }

    let mut data = vec![0u8; len];

    if let Err(e) = rdr.read_exact(&mut data).await {
        error!("Unable to read {len} bytes ({e})");
        return Err(e.into());
    }

    Ok(data)
}

async fn io_loop(mut proxy: UBwProxy) -> Result<()> {
    let stdin = io::stdin();
    let mut rdr = BufReader::new(stdin);

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout);

    let mut session_key: Option<UBwMozSessionKey> = None;

    loop {
        let msg = proxy.read_message(&mut rdr).await?;

        info!("msg_id={} command={}", msg.message_id, msg.command);

        match msg.command.as_str() {
            "setupEncryption" => proxy.setup_encryption(&mut writer, &msg).await?,
            "getBiometricsStatus" => proxy.cmd_biometric_status(&mut writer, msg.message_id).await?,
            "getBiometricsStatusForUser" => proxy.cmd_biometric_for_user(&mut writer, msg.message_id).await?,
            "unlockWithBiometricsForUser" => proxy.cmd_unlock_vault(&mut writer, msg.message_id).await?,
            _ => {
                error!("unhandled command {}", msg.command);
                bail!("unhandled command {}", msg.command)
            }
        }
    }

    Ok(())
}

pub async fn moz_proxy() -> Result<()> {
    let proxy = UBwProxy::new();

    if let Err(e) = io_loop(proxy).await {
        error!("io_loop() returnd {e}");
        return Err(e.into());
    }

    Ok(())
}
