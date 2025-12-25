use std::{
    env, fs,
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use clap::Args;

use anyhow::{Result, anyhow, bail};
use log::{error, info};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use ubitwarden::cache::common::ping_server;

use crate::common::{fetch_credentials, store_credentials};

const LOGIN_FILE_NAME: &str = "login.json";
const CONFIG_DIR: &str = env!("CARGO_PKG_NAME");

#[derive(Serialize, Deserialize)]
struct LoginConfigData {
    email: String,
    server_url: String,
}

#[derive(Args)]
pub struct LoginArgs {
    /// email address
    #[arg(short, long)]
    pub email: Option<String>,

    /// server url
    #[arg(short, long)]
    pub server_url: Option<String>,
}

async fn spawn_server() -> Result<()> {
    let self_exe = env::current_exe()?;

    Command::new(self_exe)
        .arg("cache")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    //
    // wait until we can ping it
    //
    for _ in 0..4 {
        if ping_server().await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }

    bail!("Unable to spawn credential server")
}

impl LoginConfigData {
    pub fn new<E, U>(email: E, server_url: U) -> Self
    where
        E: AsRef<str>,
        U: AsRef<str>,
    {
        Self {
            email: email.as_ref().to_string(),
            server_url: server_url.as_ref().to_string(),
        }
    }

    pub fn from_file() -> Result<Self> {
        let config_dir = dirs::config_dir().ok_or(anyhow!("config dir not found"))?;

        let config_file = config_dir.join(CONFIG_DIR).join(LOGIN_FILE_NAME);

        if !config_file.exists() {
            bail!("{} doesn't exist", config_file.display())
        }

        let config_data = fs::read_to_string(config_file)?;

        let config: Self = serde_json::from_str(&config_data)?;

        Ok(config)
    }

    pub fn sync(&self) -> Result<()> {
        let config_dir = dirs::config_dir().ok_or(anyhow!("config dir not found"))?;

        let config_dir = config_dir.join(CONFIG_DIR);

        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        let config_file = config_dir.join(LOGIN_FILE_NAME);

        let data = serde_json::to_string_pretty(self)?;

        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(config_file)?;

        f.write_all(data.as_bytes())?;

        Ok(())
    }
}

pub async fn command_login(args: LoginArgs) -> Result<()> {
    if let Err(e) = ping_server().await {
        error!("{e}");
        info!("unable to talk to the server. spawning a new one");
        spawn_server().await?;
    }

    let cache = LoginConfigData::from_file();

    let email = if let Some(email) = &args.email {
        email
    } else if let Ok(file) = &cache {
        &file.email
    } else {
        bail!("missing email");
    };

    let server_url = if let Some(server_url) = &args.server_url {
        server_url
    } else if let Ok(file) = &cache {
        &file.server_url
    } else {
        bail!("missing server url");
    };

    store_credentials(&email, &server_url).await?;
    fetch_credentials().await?;

    LoginConfigData::new(&email, &server_url).sync()
}

pub async fn login_from_cache() -> Result<()> {
    if let Err(e) = ping_server().await {
        error!("{e}");
        info!("unable to talk to the server. spawning a new one");
        spawn_server().await?;
    }

    let cache = LoginConfigData::from_file()?;

    if fetch_credentials().await.is_err() {
        store_credentials(&cache.email, &cache.server_url).await?;
        LoginConfigData::new(&cache.email, &cache.server_url).sync()?;
    }

    Ok(())
}
