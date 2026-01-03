use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled, settings::Style};
use ubitwarden::api::BwApi;

use crate::{commands::auth::login_from_cache, common::IdArgs};
use log::{error, info};

const BW_FIREFOX_API_FIELD_NAME: &str = "api_key";
const FIREFOX_RELAY_API_ENDPOINT_URI: &str = "https://relay.firefox.com/api";

#[derive(Args)]
pub struct CreateArgs {
    /// cipher uuid
    #[arg(short, long)]
    pub id: String,

    /// Email Description Context
    #[arg(short, long)]
    pub description: String,
}

#[derive(Subcommand)]
pub enum FirefoxCommands {
    /// Create a new relay email
    CreateEmail(CreateArgs),
    /// List relay emails
    #[command(visible_alias = "ls")]
    ListEmail(IdArgs),
}

#[derive(Serialize)]
struct FirefoxEmailRelayRequest {
    description: String,
    enabled: bool,
}

#[derive(Deserialize, Tabled)]
struct FirefoxEmailRelayResponse {
    id: u64,
    full_address: String,
    description: String,
    #[serde(rename = "num_blocked")]
    blocked: u64,
    #[serde(rename = "num_forwarded")]
    forwarded: u64,
}

async fn find_api_key<S>(id: S) -> Result<String>
where
    S: AsRef<str>,
{
    let mut agent = match login_from_cache().await {
        Ok(v) => v,
        Err(e) => {
            error!("not logged in");
            return Err(e);
        }
    };

    let session = agent.load_session().await?;

    let api = BwApi::new(&session.email, &session.server_url)?;

    let cipher = api.cipher(&session.auth, id).await?;

    info!("found cipher");

    let encrypted_field = cipher
        .field_by_name(&session, BW_FIREFOX_API_FIELD_NAME)
        .ok_or_else(|| anyhow!("{BW_FIREFOX_API_FIELD_NAME} not found in"))?;

    let api_key: String = session.decrypt(&encrypted_field.value)?.try_into()?;

    Ok(api_key)
}

async fn list_email_relays<S>(id: S) -> Result<()>
where
    S: AsRef<str>,
{
    let api_key = find_api_key(id).await?;

    let client = Client::new();

    let url = format!("{FIREFOX_RELAY_API_ENDPOINT_URI}/v1/relayaddresses/");
    let token = format!("Token {}", api_key);

    let emails_array = client
        .get(url)
        .header("content-type", "application/json")
        .header("authorization", token)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    dbg!(&emails_array);

    let emails: Vec<FirefoxEmailRelayResponse> = serde_json::from_value(emails_array)?;

    let mut table = Table::new(emails);
    table.with(Style::modern());

    println!("{table}");

    Ok(())
}

async fn create_email_relay<D, S>(id: S, description: D) -> Result<()>
where
    D: Into<String>,
    S: AsRef<str>,
{
    let api_key = find_api_key(id).await?;

    let client = Client::new();

    let url = format!("{FIREFOX_RELAY_API_ENDPOINT_URI}/v1/relayaddresses/");
    let token = format!("Token {}", api_key);

    let req = FirefoxEmailRelayRequest {
        description: description.into(),
        enabled: true,
    };

    let response_dict = client
        .post(url)
        .header("content-type", "application/json")
        .header("authorization", token)
        .json(&req)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    //dbg!(&response_dict);

    let res: FirefoxEmailRelayResponse = serde_json::from_value(response_dict)?;

    println!("Email: {}", res.full_address);

    Ok(())
}

pub async fn commands_firefox(command: FirefoxCommands) -> Result<()> {
    match command {
        FirefoxCommands::CreateEmail(c) => create_email_relay(c.id, c.description).await,
        FirefoxCommands::ListEmail(l) => list_email_relays(l.id).await,
    }
}
