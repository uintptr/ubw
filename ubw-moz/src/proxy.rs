#![allow(unused)]
use anyhow::{Result, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use log::{error, info};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, Stdout},
};
use ubitwarden_agent::agent::UBWAgent;

#[derive(Deserialize)]
struct NativeMessage {
    pub command: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "messageId")]
    pub message_id: u64,
    pub timestamp: u64,
}

#[derive(Deserialize)]
struct NativeMessageRequest {
    #[serde(rename = "appId")]
    pub app_id: String,
    pub message: NativeMessage,
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
}

fn encrypt_message(req: &NativeMessageRequest, msg: &[u8]) -> Result<String> {
    let mut rng = rand::thread_rng(); // rand@0.8

    let der_key = BASE64_STANDARD.decode(req.message.public_key.as_bytes())?;

    let key = RsaPublicKey::from_public_key_der(&der_key)?;

    let padding = Oaep::new::<Sha1>();
    let encrypted_data = key.encrypt(&mut rng, padding, msg)?;

    Ok(BASE64_STANDARD.encode(encrypted_data))
}

async fn setup_encryption(w: &mut BufWriter<Stdout>, req: &NativeMessageRequest) -> Result<UBwMozSessionKey> {
    let key = UBwMozSessionKey::new();

    let encrypted_key = encrypt_message(req, &key.key)?;

    let resp = NativeMessageResponse {
        app_id: &req.app_id,
        command: &req.message.command,
        message_id: -1,
        shared_secret: &encrypted_key,
    };

    let message = serde_json::to_string(&resp)?;

    info!("sending {} bytes", message.len());

    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .write(true)
        .create(true)
        .open("/tmp/test.json")
        .await?;

    f.write_all(message.as_bytes()).await?;

    //
    // write len
    //
    let msg_len: u32 = message.len().try_into()?;
    w.write_u32_le(msg_len).await?;
    w.write_all(message.as_bytes()).await?;

    Ok(key)
}

pub async fn io_loop() -> Result<()> {
    //let mut agent = UBWAgent::new().await?;
    //let session = agent.fetch_session().await?;

    let stdin = io::stdin();
    let mut rdr = BufReader::new(stdin);

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout);

    let mut session_key: Option<UBwMozSessionKey> = None;

    loop {
        info!("reading");
        let len: usize = rdr.read_u32_le().await?.try_into()?;

        info!("len: {len:?}");

        if 0 == len {
            error!("EOF");
            break;
        }

        let mut data = vec![0u8; len];

        if let Err(e) = rdr.read_exact(&mut data).await {
            error!("Unable to read {len} bytes ({e})");
            return Err(e.into());
        }

        let req: NativeMessageRequest = match serde_json::from_slice(&data) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to deserialize request ({e})");
                return Err(e.into());
            }
        };

        info!("id={} command={}", req.message.message_id, req.message.command);

        match req.message.command.as_str() {
            "setupEncryption" => {
                let key = setup_encryption(&mut writer, &req).await?;

                session_key = Some(key);
            }
            _ => {
                error!("unhandled command {}", req.message.command);
                bail!("unhandled command {}", req.message.command)
            }
        }
    }

    Ok(())
}

pub async fn moz_proxy() -> Result<()> {
    if let Err(e) = io_loop().await {
        error!("io_loop() returnd {e}");
        return Err(e.into());
    }

    Ok(())
}
