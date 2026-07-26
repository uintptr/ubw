use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit},
};
use hmac::{Hmac, Mac};
use log::{error, info, warn};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::io::{self, BufReader, BufWriter, Read, Stdin, Stdout, Write};
use ubitwarden_agent::agent::UBWAgent;

use crate::biometric::biometric_login;

//
// The extension waits for this before it considers the native port usable. The real
// desktop_proxy emits it as soon as it connects to the desktop app's IPC socket, and
// since 2026-07 the extension gates every biometric command behind having seen it.
//
const CONNECTED_MESSAGE: &str = r#"{"command":"connected"}"#;

#[derive(Deserialize)]
struct CommandMessage {
    pub command: String,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "messageId")]
    pub message_id: u64,
}

#[derive(Deserialize)]
struct CommandRequest {
    #[serde(rename = "appId")]
    pub app_id: String,
    pub message: CommandMessage,
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
    pub timestamp: i64,
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
        let mut key = vec![0u8; 64]; // Generate a 64-byte (512-bit) session key
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);

        Self { key }
    }

    pub fn decrypt_message(&self, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        // Decode base64 components
        let iv = BASE64_STANDARD.decode(&encrypted.iv)?;
        let data = BASE64_STANDARD.decode(&encrypted.data)?;
        let mac = BASE64_STANDARD.decode(&encrypted.mac)?;

        // Split session key: first 32 bytes = encryption key, last 32 bytes = MAC key
        let enc_key = self.key.get(0..32).ok_or_else(|| anyhow!("Invalid key size"))?;
        let mac_key = self.key.get(32..64).ok_or_else(|| anyhow!("Invalid key size"))?;

        // Verify HMAC-SHA256
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key)?;
        hmac.update(&iv);
        hmac.update(&data);
        hmac.verify_slice(&mac)?;

        // Decrypt AES-256-CBC
        let cipher = Decryptor::<Aes256>::new_from_slices(enc_key, &iv)?;
        let decrypted = cipher
            .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&data)
            .map_err(|e| anyhow::anyhow!("Decryption padding error: {e}"))?;

        Ok(decrypted)
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<EncryptedMessage> {
        use cbc::{
            Encryptor,
            cipher::{BlockEncryptMut, KeyIvInit},
        };
        // Generate random 16-byte IV
        let mut iv = vec![0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut iv);

        // Split session key: first 32 bytes = encryption key, last 32 bytes = MAC key
        let enc_key = self.key.get(0..32).ok_or_else(|| anyhow!("Invalid key size"))?;
        let mac_key = self.key.get(32..64).ok_or_else(|| anyhow!("Invalid key size"))?;

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
        let mac_b64 = BASE64_STANDARD.encode(mac);

        // Create encrypted string format: "2.iv|data|mac"
        let encrypted_string = format!("2.{iv_b64}|{data_b64}|{mac_b64}");

        Ok(EncryptedMessage {
            encrypted_string,
            encryption_type: 2,
            data: data_b64,
            iv: iv_b64,
            mac: mac_b64,
        })
    }
}

enum Incoming {
    Command(CommandMessage),
    Ignored,
    Eof,
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

    fn write_encrypted_message<S>(&self, w: &mut BufWriter<Stdout>, res: S, msg_id: u64) -> Result<()>
    where
        S: Serialize,
    {
        let Some(app_id) = &self.app_id else {
            bail!("Missing app id");
        };

        let encoded_respose = serde_json::to_string(&res)?;

        if let Some(session_key) = &self.session_key {
            let encrypted_msg = session_key.encrypt(encoded_respose.as_bytes())?;

            // Wrap in the outer message structure expected by the browser
            let response = EncryptedResponse {
                app_id,
                message_id: msg_id,
                message: encrypted_msg,
            };

            let msg = serde_json::to_string(&response)?;

            write_message(w, &msg).context("failed to write encrypted response to stdout")
        } else {
            bail!("Session key missing");
        }
    }

    //
    // Incoming::Ignored means the message wasn't meant for us (the extension also opens a
    // second port for its SDK IPC transport, which speaks a protocol we don't implement).
    // Those are skipped instead of taking the whole port down with us.
    //
    fn read_message(&mut self, rdr: &mut BufReader<Stdin>) -> Result<Incoming> {
        let Some(data) = read_buffer(rdr)? else {
            return Ok(Incoming::Eof);
        };

        let msg = if let Ok(req) = serde_json::from_slice::<CommandRequest>(&data) {
            info!("using app_id={}", req.app_id);
            self.app_id = Some(req.app_id);
            req.message
        } else if let Some(key) = &self.session_key
            && let Ok(enc_req) = serde_json::from_slice::<DecryptRequest>(&data)
        {
            let plain_data = key.decrypt_message(&enc_req.message)?;

            serde_json::from_slice::<CommandMessage>(&plain_data)?
        } else {
            warn!("ignoring unrecognized message ({} bytes)", data.len());
            return Ok(Incoming::Ignored);
        };

        Ok(Incoming::Command(msg))
    }

    fn setup_encryption(&mut self, w: &mut BufWriter<Stdout>, msg: &CommandMessage) -> Result<()> {
        let Some(app_id) = &self.app_id else {
            bail!("Missing app id")
        };

        let key = UBwMozSessionKey::new();

        let encrypted_key = encrypt_message(msg, &key.key)?;

        let resp = NativeMessageResponse {
            app_id,
            command: &msg.command,
            message_id: -1,
            shared_secret: &encrypted_key,
        };

        let message = serde_json::to_string(&resp)?;

        write_message(w, &message).context("failed to write encryption setup response to stdout")?;

        self.session_key = Some(key);

        Ok(())
    }

    fn get_vault_key() -> Result<String> {
        let mut agent = UBWAgent::client()?;
        let session = agent.session_load()?;
        Ok(session.export_key())
    }

    fn cmd_unlock_vault(&self, w: &mut BufWriter<Stdout>, message_id: u64) -> Result<()> {
        let (response, user_key_b64) = match Self::get_vault_key() {
            Ok(v) => {
                if let Err(e) = biometric_login() {
                    error!("biometric failure ({e})");
                    (false, None)
                } else {
                    (true, Some(v))
                }
            }
            Err(e) => {
                error!("Unable to get vault key ({e})");
                (false, None)
            }
        };

        //
        // stamped after the (possibly slow) biometric prompt: the extension drops
        // responses whose timestamp is more than 10 seconds off from its own clock
        //
        let res = UnlockVaultStatus {
            command: "unlockWithBiometricsForUser",
            response,
            message_id,
            user_key_b64,
            timestamp: now_ms()?,
        };

        self.write_encrypted_message(w, &res, message_id)
    }

    fn cmd_biometric_for_user(&self, w: &mut BufWriter<Stdout>, msg_id: u64) -> Result<()> {
        let res = GetBiometricStatus {
            command: "getBiometricsStatusForUser",
            message_id: msg_id,
            response: 0,
            timestamp: now_ms()?,
        };

        self.write_encrypted_message(w, &res, msg_id)
    }

    fn cmd_biometric_status(&self, w: &mut BufWriter<Stdout>, msg_id: u64) -> Result<()> {
        let res = GetBiometricStatus {
            command: "getBiometricsStatus",
            message_id: msg_id,
            response: 0,
            timestamp: now_ms()?,
        };

        self.write_encrypted_message(w, &res, msg_id)
    }
}

fn encrypt_message(msg: &CommandMessage, plain: &[u8]) -> Result<String> {
    let mut rng = rand_core::OsRng;

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

fn now_ms() -> Result<i64> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?;
    Ok(ts)
}

fn write_message(w: &mut BufWriter<Stdout>, msg: &str) -> Result<()> {
    //
    // message length prefix (required by the native messaging protocol)
    //
    let msg_len: u32 = msg.len().try_into()?;
    w.write_all(&msg_len.to_le_bytes())?;
    w.write_all(msg.as_bytes())?;
    w.flush()?;

    Ok(())
}

//
// Ok(None) when the browser closed the port
//
fn read_buffer(rdr: &mut BufReader<Stdin>) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];

    if let Err(e) = rdr.read_exact(&mut len_buf) {
        if io::ErrorKind::UnexpectedEof == e.kind() {
            return Ok(None);
        }
        return Err(e).context("failed to read the message length from native messaging input");
    }

    let len: usize = u32::from_le_bytes(len_buf).try_into()?;

    if 0 == len {
        return Err(anyhow!("received zero-length message from native messaging interface"));
    }

    let mut data = vec![0u8; len];

    rdr.read_exact(&mut data)
        .with_context(|| format!("failed to read {len} bytes from native messaging input"))?;

    Ok(Some(data))
}

fn io_loop(mut proxy: UBwProxy) -> Result<()> {
    let stdin = io::stdin();
    let mut rdr = BufReader::new(stdin);

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout);

    //
    // unprompted, and before anything else. the extension won't send us a single
    // command until it has seen it
    //
    write_message(&mut writer, CONNECTED_MESSAGE).context("failed to announce the connection")?;

    loop {
        let msg = match proxy.read_message(&mut rdr)? {
            Incoming::Command(msg) => msg,
            Incoming::Ignored => continue,
            Incoming::Eof => {
                info!("port closed by the browser");
                return Ok(());
            }
        };

        info!("msg_id={} command={}", msg.message_id, msg.command);

        match msg.command.as_str() {
            "setupEncryption" => proxy.setup_encryption(&mut writer, &msg)?,
            "getBiometricsStatus" => proxy.cmd_biometric_status(&mut writer, msg.message_id)?,
            "getBiometricsStatusForUser" => proxy.cmd_biometric_for_user(&mut writer, msg.message_id)?,
            "unlockWithBiometricsForUser" => proxy.cmd_unlock_vault(&mut writer, msg.message_id)?,
            _ => error!("unhandled command {}", msg.command),
        }
    }
}

//
// No single-instance lock here: the extension opens two native ports (biometrics and
// its SDK IPC transport), so we get two live processes and neither may kill the other.
//
pub fn moz_proxy() -> Result<()> {
    let proxy = UBwProxy::new();

    if let Err(e) = io_loop(proxy) {
        error!("io_loop() returned {e}");
        return Err(e);
    }

    Ok(())
}
