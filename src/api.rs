use std::collections::HashMap;

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

use crate::{config::BwConfig, error::Error};

#[derive(Debug, Deserialize)]
pub struct BwCipherData {
    pub name: String,
    pub password: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct BwCipher {
    pub data: BwCipherData,
}

#[derive(Debug, Deserialize)]
pub struct BwProfile {
    pub email: String,
    pub premium: bool,
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct BwSync {
    pub ciphers: Vec<BwCipher>,
    pub profile: BwProfile,
}

#[derive(Deserialize)]
pub struct BwToken {
    pub access_token: String,
}

pub struct BwApi<'a> {
    client: Client,
    config: &'a BwConfig,
    token: Option<BwToken>,
}

impl<'a> BwApi<'a> {
    pub fn new(config: &'a BwConfig) -> Self {
        Self {
            client: Client::new(),
            config,
            token: None,
        }
    }

    pub async fn auth(&mut self) -> Result<()> {
        let auth_url = format!("{}/identity/connect/token", self.config.server.url);

        let mut params = HashMap::new();

        params.insert("grant_type", "client_credentials");
        params.insert("scope", "api");
        params.insert("client_id", &self.config.credentials.client_id);
        params.insert("client_secret", &self.config.credentials.client_secret);
        params.insert("device_identifier", "ubw");
        params.insert("device_name", "ubw");
        params.insert("device_type", "1");

        let res = self
            .client
            .post(auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?
            .json::<BwToken>()
            .await?;

        self.token = Some(res);

        Ok(())
    }

    pub async fn sync(&mut self) -> Result<BwSync> {
        let url = format!("{}/api/sync", self.config.server.url);

        if let Some(token) = &self.token {
            let data = self
                .client
                .get(url)
                .bearer_auth(&token.access_token)
                .send()
                .await?
                .json::<BwSync>()
                .await?;

            Ok(data)
        } else {
            Err(Error::AuthNotFoundError.into())
        }
    }
}
