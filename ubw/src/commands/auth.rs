use std::{env, fs, io::Write, os::unix::fs::OpenOptionsExt};

use clap::Args;

use anyhow::{Result, anyhow, bail};
use dialoguer::Password;
use log::{error, info};
use serde::{Deserialize, Serialize};
use ubitwarden::{api::BwApi, api_types::BwCipherData};
use ubitwarden_agent::agent::UBWAgent;

use crate::{
    banner::display_banner,
    commands::agent::server::spawn_server,
    common::{UBW_APP_NAME, UBW_APP_VERSION, UBW_CONFIG_DIR},
};

const LOGIN_FILE_NAME: &str = "login.json";
const UBW_LOGIN_ATTEMPTS: i8 = 3;
const UBW_DEF_FIGLET_FONT: &str = "pagga";

#[derive(Serialize, Deserialize)]
struct LoginConfigData {
    email: String,
    server_url: String,
}

#[derive(Args)]
pub struct AuthArgs {
    /// email address
    #[arg(short, long, env = "UBW_EMAIL")]
    pub email: Option<String>,

    /// server url
    #[arg(short, long, env = "UBW_SERVER_URL")]
    pub server_url: Option<String>,

    /// force
    #[arg(short, long)]
    pub force: bool,
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
        let config_dir = dirs::config_dir().ok_or_else(|| anyhow!("config dir not found"))?;

        let config_file = config_dir.join(UBW_CONFIG_DIR).join(LOGIN_FILE_NAME);

        if !config_file.exists() {
            bail!("{} doesn't exist", config_file.display())
        }

        info!("reading: {}", config_file.display());

        let config_data = fs::read_to_string(config_file)?;

        let config: Self = serde_json::from_str(&config_data)?;

        Ok(config)
    }

    pub fn sync(&self) -> Result<()> {
        let config_dir = dirs::config_dir().ok_or_else(|| anyhow!("config dir not found"))?;

        let config_dir = config_dir.join(UBW_CONFIG_DIR);

        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        let config_file = config_dir.join(LOGIN_FILE_NAME);

        let data = serde_json::to_string_pretty(self)?;

        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(config_file)?;

        f.write_all(data.as_bytes())?;

        Ok(())
    }
}

async fn ask_password_loop<E, U>(email: E, server_url: U) -> Result<String>
where
    E: AsRef<str>,
    U: AsRef<str>,
{
    let api = BwApi::new(&email, &server_url)?;

    let banner_text = format!("{UBW_APP_NAME} {UBW_APP_VERSION}");
    display_banner(banner_text, UBW_DEF_FIGLET_FONT)?;

    for attempt in 1..=UBW_LOGIN_ATTEMPTS {
        //
        // helps with testing but not recommended
        //
        let password = if let Ok(password) = env::var("UBW_PASSWORD") {
            info!("using UBW_PASSWORD={:*<width$}", "", width = password.len());
            password
        } else {
            let prompt = format!("\x1b[1;35m{}\x1b[0m", email.as_ref());
            //let prompt = format!("Password for {}", email.as_ref());
            Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(prompt)
                .interact()?
        };

        //
        // try it before blindly accepting it
        //
        match api.auth(&password).await {
            Ok(_) => return Ok(password),
            Err(e) => {
                if attempt == UBW_LOGIN_ATTEMPTS {
                    return Err(e.into());
                }
            }
        }
    }

    unreachable!()
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub async fn ask_password<E, U>(email: E, server_url: U) -> Result<String>
where
    E: AsRef<str>,
    U: AsRef<str>,
{
    ask_password_loop(email, server_url).await
}

pub async fn login_from_cache() -> Result<UBWAgent> {
    let mut agent = if let Ok(v) = UBWAgent::client().await {
        v
    } else {
        info!("unable to talk to the server. spawning a new one");
        spawn_server().await?;
        UBWAgent::client().await?
    };

    let cache = LoginConfigData::from_file()?;

    if agent.credentials_fetch().await.is_err() {
        let password = ask_password(&cache.email, &cache.server_url).await?;
        agent.credentials_store(&cache.email, &cache.server_url, password).await?;
        LoginConfigData::new(&cache.email, &cache.server_url).sync()?;
    }

    Ok(agent)
}

pub async fn command_logins() -> Result<()> {
    if let Err(e) = login_from_cache().await {
        bail!("Not logged in ({e})");
    }

    let mut agent = UBWAgent::client().await?;

    let session = agent.session_load().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let ciphers = api.logins(&session.auth).await?;

    for c in ciphers {
        if let BwCipherData::Login(login) = c.data
            && let Some(encrypted_username) = login.username
        {
            let name: String = session.decrypt(&encrypted_username)?.try_into()?;
            println!("* {} {name}", c.id);
        }
    }

    Ok(())
}

pub async fn command_auth(args: AuthArgs) -> Result<()> {
    let mut agent = if let Ok(v) = UBWAgent::client().await {
        v
    } else {
        info!("unable to talk to the server. spawning a new one");
        spawn_server().await?;
        UBWAgent::client().await?
    };

    if !args.force {
        //
        // unless force is specifed, we'll check that the server have creds
        // and bail if it does.
        //
        // This way "ubw login" can be used multiple times without prompting
        //
        if agent.credentials_fetch().await.is_ok() {
            info!("already authenticated");
            return Ok(());
        }
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

    info!("using {email} {server_url}");

    let password = ask_password(&email, &server_url).await?;

    info!("storing password");
    agent.credentials_store(email, server_url, password).await?;
    agent.credentials_fetch().await?;

    LoginConfigData::new(email, server_url).sync()
}

pub async fn command_logout() -> Result<()> {
    let Ok(mut agent) = UBWAgent::client().await else {
        //
        // not running nothing to do
        //
        info!("not running, nothing to do");
        return Ok(());
    };

    if agent.credentials_fetch().await.is_ok() {
        info!("deleting credentials");
        if let Err(e) = agent.credentials_delete().await {
            error!("unable to delete credentials ({e})");
            return Err(e.into());
        }
    }

    if agent.session_fetch().await.is_ok() {
        info!("deleting session");

        if let Err(e) = agent.delete_session().await {
            error!("unable to delete session ({e})");
            return Err(e.into());
        }
    }

    Ok(())
}
