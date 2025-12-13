use std::collections::HashMap;

use anyhow::Result;
use derive_more::Display;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;

use crate::{auth_cache::BwCachedAuth, config::BwConfig};

#[derive(Debug, Deserialize)]
pub struct BwCipherData {
    pub name: String,
    pub password: Option<String>,
    pub username: Option<String>,
}

#[derive(Display, Debug, Deserialize_repr)]
#[repr(u8)]
pub enum BwCipherType {
    Login = 1,
    Note = 2,
    Card = 3,
    Identity = 4,
    Ssh = 5,
}

#[derive(Debug, Deserialize)]
pub struct BwCipher {
    pub id: String,
    pub data: BwCipherData,
    pub name: String,
    #[serde(rename = "type")]
    pub cipher_type: BwCipherType,
}

#[derive(Debug, Deserialize)]
pub struct BwSync {
    pub ciphers: Vec<BwCipher>,
    pub profile: BwProfile,
}

#[derive(Debug, Deserialize)]
pub struct BwCipherResponse {
    #[serde(rename = "continuationToken")]
    pub continuation_token: Option<String>,
    pub data: Vec<BwCipher>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BwAuth {
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "Key")]
    pub key: String,
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct BwProfile {
    pub email: String,
    pub premium: bool,
    pub key: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

pub struct BwApi<'a> {
    client: Client,
    config: &'a BwConfig,
    auth: BwAuth,
    auth_cache: BwCachedAuth,
}

impl<'a> BwApi<'a> {
    pub fn new(config: &'a BwConfig) -> Result<Self> {
        let auth_cache = BwCachedAuth::new()?;

        Ok(Self {
            client: Client::new(),
            config,
            auth: BwAuth::default(),
            auth_cache,
        })
    }

    async fn remote_auth(&mut self) -> Result<BwAuth> {
        info!("doing remote auth");

        let auth_url = format!("{}/identity/connect/token", self.config.server.url);

        let mut params = HashMap::new();

        params.insert("grant_type", "client_credentials");
        params.insert("scope", "api");
        params.insert("client_id", &self.config.credentials.client_id);
        params.insert("client_secret", &self.config.credentials.client_secret);
        params.insert("device_identifier", "ubw");
        params.insert("device_name", "ubw");
        params.insert("device_type", "1");

        let auth = self
            .client
            .post(auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?
            .json::<BwAuth>()
            .await?;

        Ok(auth)
    }

    fn cached_auth(&self) -> Result<BwAuth> {
        self.auth_cache.load()
    }

    pub async fn auth(&mut self) -> Result<&BwAuth> {
        let auth = if let Ok(v) = self.cached_auth() {
            info!("cached auth is still usable");
            v
        } else {
            let auth = self.remote_auth().await?;
            // save it for next time
            let _ = self.auth_cache.save(&auth);
            auth
        };

        self.auth = auth;
        Ok(&self.auth)
    }

    pub async fn sync(&mut self) -> Result<BwSync> {
        let url = format!("{}/api/sync?excludeDomains=true", self.config.server.url);

        let data = self
            .client
            .get(url)
            .bearer_auth(&self.auth.access_token)
            .send()
            .await?
            .json::<BwSync>()
            .await?;
        Ok(data)
    }

    pub async fn ciphers(&mut self) -> Result<Vec<BwCipher>> {
        let mut cont_token = None;

        let mut ciphers = Vec::new();

        loop {
            let url = if let Some(token) = cont_token {
                format!("{}/api/ciphers?continuationToken={token}", self.config.server.url)
            } else {
                format!("{}/api/ciphers", self.config.server.url)
            };

            let resp = self
                .client
                .get(url)
                .bearer_auth(&self.auth.access_token)
                .send()
                .await?
                .json::<BwCipherResponse>()
                .await?;

            ciphers.extend(resp.data);

            if let Some(token) = resp.continuation_token {
                cont_token = Some(token);
            } else {
                break;
            }
        }

        Ok(ciphers)
    }
}
