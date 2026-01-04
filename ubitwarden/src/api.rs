use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    api_types::{BwAuth, BwCipher, BwCipherData, BwCipherType, BwPreLogin, BwSync},
    crypto::build_password_hash,
    error::{Error, Result},
};

const UBW_DEVICE_ID: &str = "2c28ca63-da34-452d-9d54-3180c2d1165e";

#[derive(Debug, Serialize)]
struct BwPreLoginRequest<'a> {
    pub email: &'a str,
}

#[derive(Debug, Deserialize)]
struct BwCipherResponse {
    #[serde(rename = "continuationToken")]
    pub continuation_token: Option<String>,
    pub data: Vec<BwCipher>,
}

#[derive(Debug, Serialize)]
struct LoginRequest<'a> {
    grant_type: &'a str,
    username: &'a str,
    password: &'a str,
    scope: &'a str,
    client_id: &'a str,
    #[serde(rename = "deviceType")]
    device_type: &'a str,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: &'a str,
    #[serde(rename = "deviceName")]
    device_name: &'a str,
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

    async fn ciphers_with_type(&self, auth: &BwAuth, cipher_type: BwCipherType) -> Result<Vec<BwCipher>> {
        let mut cont_token = None;

        let mut ciphers = Vec::new();
        let cipher_type = cipher_type as u8;

        loop {
            let ciphers_url = if let Some(token) = cont_token {
                format!(
                    "{}/api/ciphers?continuationToken={token}&type={cipher_type}",
                    self.server
                )
            } else {
                format!("{}/api/ciphers?type={cipher_type}", self.server)
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

    ////////////////////////////////////////////////////////////////////////////
    // PUBLIC
    ////////////////////////////////////////////////////////////////////////////

    pub async fn auth<S>(&self, password: S) -> Result<BwAuth>
    where
        S: AsRef<str>,
    {
        info!("doing remote auth");

        let auth_url = format!("{}/identity/connect/token", self.server);

        let pre = self.prelogin().await?;

        let password_hash = build_password_hash(pre.kdf_iterations, &self.email, password.as_ref())?;

        let login_req = LoginRequest {
            grant_type: "password",
            username: &self.email,
            password: &password_hash,
            scope: "api offline_access",
            client_id: "web",
            device_type: "10",
            device_identifier: UBW_DEVICE_ID,
            device_name: "ubw",
        };

        let ret = self
            .client
            .post(auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&login_req)
            .send()
            .await?;

        if !ret.status().is_success() {
            return Err(Error::AuthFailure);
        }

        let text = ret.text().await?;
        let auth: BwAuth = serde_json::from_str(&text)?;

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

        //dbg!(&cipher_dict);

        let cipher: BwCipher = serde_json::from_value(cipher_dict)?;

        Ok(cipher)
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

            let ret = self.client.get(ciphers_url).bearer_auth(&auth.access_token).send().await?;

            let value = ret.json::<serde_json::Value>().await?;

            let resp: BwCipherResponse = serde_json::from_value(value)?;

            ciphers.extend(resp.data);

            if let Some(token) = resp.continuation_token {
                cont_token = Some(token);
            } else {
                break;
            }
        }

        Ok(ciphers)
    }

    pub async fn ssh_keys(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
        self.ciphers_with_type(auth, BwCipherType::Ssh).await
    }

    pub async fn logins(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
        self.ciphers_with_type(auth, BwCipherType::Login).await
    }

    pub async fn login<I>(&self, auth: &BwAuth, id: I) -> Result<BwCipher>
    where
        I: AsRef<str>,
    {
        self.cipher(auth, id).await
    }

    pub async fn totp<I>(&self, auth: &BwAuth, id: I) -> Result<String>
    where
        I: AsRef<str>,
    {
        let cipher = self.cipher(auth, id).await?;

        if let BwCipherData::Login(login) = cipher.data
            && let Some(encrypted_totp) = login.totp
        {
            Ok(encrypted_totp)
        } else {
            Err(Error::TotpNotFound)
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
