use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use base64::prelude::*;
use log::info;
use serde::{Deserialize, Serialize};

const SESSION_ENV_VAR: &str = "UBW_SESSION";

use crate::api::BwAuth;

#[derive(Debug, Deserialize, Serialize)]
pub struct BwSession {
    ts: u64,
    pub email: String,
    pub server_url: String,
    pub auth: BwAuth,
    pub key: String,
}

impl BwSession {
    pub fn new<E, S, U>(email: E, server_url: U, key: S, auth: &BwAuth) -> Result<Self>
    where
        S: AsRef<str>,
        E: AsRef<str>,
        U: AsRef<str>,
    {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(Self {
            ts,
            email: email.as_ref().into(),
            server_url: server_url.as_ref().into(),
            auth: auth.clone(),
            key: key.as_ref().into(),
        })
    }

    pub fn from_env() -> Result<Self> {
        let base64_data = std::env::var(SESSION_ENV_VAR)?;

        info!("{SESSION_ENV_VAR} is set, len={} bytes", base64_data.len());

        let json_string: String = BASE64_STANDARD.decode(base64_data)?.try_into()?;

        let data: BwSession = serde_json::from_str(&json_string)?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expiry = data.ts.saturating_add(data.auth.expires_in);
        let rem_sec = expiry.saturating_sub(now);

        info!("{SESSION_ENV_VAR} expires in {rem_sec} seconds");

        Ok(data)
    }

    pub fn export(&self) -> Result<String> {
        let json_string = serde_json::to_string(self)?;

        let bas64_string = BASE64_STANDARD.encode(json_string.as_bytes());

        let env_string = format!("{SESSION_ENV_VAR}={bas64_string}");

        Ok(env_string)
    }
}
