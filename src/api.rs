use std::collections::HashMap;

use anyhow::Result;
use derive_more::Display;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;

use crate::crypto::build_password_hash;

const UBW_DEVICE_ID: &str = "2c28ca63-da34-452d-9d54-3180c2d1165e";

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
pub struct BwLogin {
    pub totp: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwCipher {
    pub id: String,
    pub data: BwCipherData,
    pub name: String,
    #[serde(rename = "type")]
    pub cipher_type: BwCipherType,
    pub login: Option<BwLogin>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BwAuth {
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "Key")]
    pub key: String,
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct BwProfile {
    pub email: String,
    pub premium: bool,
    pub key: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

#[derive(Debug, Serialize)]
pub struct BwPreLoginRequest<'a> {
    pub email: &'a str,
}
#[derive(Debug, Deserialize)]
pub struct BwPreLogin {
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
}

pub struct BwApi {
    client: Client,
    email: String,
    server: String,
    auth: BwAuth,
}

impl BwApi {
    pub fn new<E, S>(email: E, server: S) -> Result<Self>
    where
        E: AsRef<str>,
        S: AsRef<str>,
    {
        Ok(Self {
            client: Client::new(),
            email: email.as_ref().into(),
            server: server.as_ref().into(),
            auth: BwAuth::default(),
        })
    }

    pub fn with_auth(&mut self, auth: &BwAuth) {
        self.auth = auth.clone();
    }

    pub async fn auth<S>(&mut self, password: S) -> Result<&BwAuth>
    where
        S: AsRef<str>,
    {
        info!("doing remote auth");

        let auth_url = format!("{}/identity/connect/token", self.server);

        let mut params = HashMap::new();

        let pre = self.prelogin().await?;

        let password_hash = build_password_hash(pre.kdf_iterations, &self.email, password.as_ref())?;

        params.insert("grant_type", "password");
        params.insert("username", &self.email);
        params.insert("password", &password_hash);
        params.insert("scope", "api offline_access");
        params.insert("client_id", "web");
        params.insert("deviceType", "10");
        params.insert("deviceIdentifier", UBW_DEVICE_ID);
        params.insert("deviceName", "ubw");

        let auth = self
            .client
            .post(auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?
            .json::<BwAuth>()
            .await?;

        self.auth = auth;

        Ok(&self.auth)
    }

    pub async fn sync(&mut self) -> Result<BwSync> {
        let sync_url = format!("{}/api/sync?excludeDomains=true", self.server);

        let data = self
            .client
            .get(sync_url)
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
            let ciphers_url = if let Some(token) = cont_token {
                format!("{}/api/ciphers?continuationToken={token}", self.server)
            } else {
                format!("{}/api/ciphers", self.server)
            };

            let resp = self
                .client
                .get(ciphers_url)
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

    pub async fn prelogin(&self) -> Result<BwPreLogin> {
        let prelogin_url = format!("{}/identity/accounts/prelogin", self.server);

        let req_data = BwPreLoginRequest { email: &self.email };

        let data = Client::new()
            .post(prelogin_url)
            .header("Content-Type", "application/json")
            .json(&req_data)
            .send()
            .await?
            .json::<BwPreLogin>()
            .await?;

        Ok(data)
    }
}
