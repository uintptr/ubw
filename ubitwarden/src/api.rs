use std::collections::HashMap;

use derive_more::Display;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;

use crate::{
    crypto::build_password_hash,
    error::{Error, Result},
};

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
    pub username: Option<String>,
    pub password: Option<String>,
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
        })
    }

    pub async fn auth<S>(&self, password: S) -> Result<BwAuth>
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

        let auth_dict = self
            .client
            .post(auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        //dbg!(&auth_dict);

        let auth: BwAuth = serde_json::from_value(auth_dict)?;

        Ok(auth)
    }

    pub async fn sync(&self, auth: &BwAuth) -> Result<BwSync> {
        let sync_url = format!("{}/api/sync?excludeDomains=true", self.server);

        let data = self
            .client
            .get(sync_url)
            .bearer_auth(&auth.access_token)
            .send()
            .await?
            .json::<BwSync>()
            .await?;
        Ok(data)
    }

    pub async fn ciphers(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
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
                .bearer_auth(&auth.access_token)
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

    pub async fn cipher<I>(&self, auth: &BwAuth, id: I) -> Result<BwCipher>
    where
        I: AsRef<str>,
    {
        let url = format!("{}/api/ciphers/{}", self.server, id.as_ref());

        let cipher_dict = self
            .client
            .get(url)
            .bearer_auth(&auth.access_token)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let cipher: BwCipher = serde_json::from_value(cipher_dict)?;

        Ok(cipher)
    }

    pub async fn totp<I>(&self, auth: &BwAuth, id: I) -> Result<String>
    where
        I: AsRef<str>,
    {
        let cipher = self.cipher(auth, id).await?;

        if let Some(login) = cipher.login
            && let Some(encrypted_totp) = login.totp
        {
            Ok(encrypted_totp)
        } else {
            Err(Error::TotpNotFound.into())
        }
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
