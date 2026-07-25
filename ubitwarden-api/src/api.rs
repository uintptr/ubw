use std::time::Duration;

use log::info;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ureq::{
    Agent,
    tls::{RootCerts, TlsConfig},
};

use crate::{
    api_types::{BwAuth, BwCipher, BwCipherData, BwCipherType, BwPreLogin, BwSync},
    crypto::build_password_hash,
    error::{Error, Result},
};

const UBW_DEVICE_ID: &str = "2c28ca63-da34-452d-9d54-3180c2d1165e";

/// Applies to the whole request, connect and body read included.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// ureq defaults to 10MB, which a large vault could realistically exceed.
const MAX_BODY_SIZE: u64 = 64 * 1024 * 1024;

/// Build the HTTP agent used for every request of a [`BwApi`].
///
/// Certificates are validated against the OS trust store so that self-hosted
/// servers using a privately issued certificate keep working.
fn build_agent() -> Agent {
    let tls_config = TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build();

    let config = Agent::config_builder()
        .tls_config(tls_config)
        .timeout_global(Some(HTTP_TIMEOUT))
        // We check statuses ourselves, so a 4xx is a response and not an error.
        .http_status_as_error(false)
        .build();

    Agent::new_with_config(config)
}

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

pub struct BwApi {
    agent: Agent,
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
            agent: build_agent(),
            email: email.as_ref().into(),
            server: server.as_ref().into(),
        })
    }

    /// Read a response body, failing on a non success status.
    fn read_body(mut resp: ureq::http::Response<ureq::Body>) -> Result<String> {
        let status = resp.status();

        if !status.is_success() {
            return Err(Error::HttpStatus(status.as_u16()));
        }

        let body = resp.body_mut().with_config().limit(MAX_BODY_SIZE).read_to_string()?;

        Ok(body)
    }

    /// Authenticated GET returning a deserialized body.
    fn get_json<T>(&self, url: &str, auth: &BwAuth) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let resp = self
            .agent
            .get(url)
            .header("Authorization", format!("Bearer {}", auth.access_token))
            .call()?;

        let body = Self::read_body(resp)?;

        Ok(serde_json::from_str(&body)?)
    }

    fn ciphers_with_type(&self, auth: &BwAuth, cipher_type: BwCipherType) -> Result<Vec<BwCipher>> {
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

            let resp: BwCipherResponse = self.get_json(&ciphers_url, auth)?;

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

    pub fn auth<S>(&self, password: S) -> Result<BwAuth>
    where
        S: AsRef<str>,
    {
        info!("doing remote auth");

        let auth_url = format!("{}/identity/connect/token", self.server);

        let pre = self.prelogin()?;

        let password_hash = build_password_hash(pre.kdf_iterations, &self.email, password.as_ref())?;

        let login_req = [
            ("grant_type", "password"),
            ("username", self.email.as_str()),
            ("password", password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", UBW_DEVICE_ID),
            ("deviceName", "ubw"),
        ];

        let resp = self.agent.post(&auth_url).send_form(login_req)?;

        if !resp.status().is_success() {
            return Err(Error::AuthFailure);
        }

        let text = Self::read_body(resp)?;
        let auth: BwAuth = serde_json::from_str(&text)?;

        Ok(auth)
    }

    pub fn sync(&self, auth: &BwAuth) -> Result<BwSync> {
        let sync_url = format!("{}/api/sync?excludeDomains=true", self.server);

        self.get_json(&sync_url, auth)
    }

    pub fn cipher<I>(&self, auth: &BwAuth, id: I) -> Result<BwCipher>
    where
        I: AsRef<str>,
    {
        let url = format!("{}/api/ciphers/{}", self.server, id.as_ref());

        self.get_json(&url, auth)
    }

    pub fn ciphers(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
        let mut cont_token = None;

        let mut ciphers = Vec::new();

        loop {
            let ciphers_url = if let Some(token) = cont_token {
                format!("{}/api/ciphers?continuationToken={token}", self.server)
            } else {
                format!("{}/api/ciphers", self.server)
            };

            let resp: BwCipherResponse = self.get_json(&ciphers_url, auth)?;

            ciphers.extend(resp.data);

            if let Some(token) = resp.continuation_token {
                cont_token = Some(token);
            } else {
                break;
            }
        }

        Ok(ciphers)
    }

    pub fn ssh_keys(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
        self.ciphers_with_type(auth, BwCipherType::Ssh)
    }

    pub fn logins(&self, auth: &BwAuth) -> Result<Vec<BwCipher>> {
        self.ciphers_with_type(auth, BwCipherType::Login)
    }

    pub fn login<I>(&self, auth: &BwAuth, id: I) -> Result<BwCipher>
    where
        I: AsRef<str>,
    {
        self.cipher(auth, id)
    }

    pub fn totp<I>(&self, auth: &BwAuth, id: I) -> Result<String>
    where
        I: AsRef<str>,
    {
        let cipher = self.cipher(auth, id)?;

        if let BwCipherData::Login(login) = cipher.data
            && let Some(encrypted_totp) = &login.totp
        {
            Ok(encrypted_totp.clone())
        } else {
            Err(Error::TotpNotFound)
        }
    }

    pub fn prelogin(&self) -> Result<BwPreLogin> {
        let prelogin_url = format!("{}/identity/accounts/prelogin", self.server);

        let req_data = BwPreLoginRequest { email: &self.email };

        let resp = self
            .agent
            .post(&prelogin_url)
            .header("Content-Type", "application/json")
            .send(serde_json::to_string(&req_data)?)?;

        let body = Self::read_body(resp)?;

        Ok(serde_json::from_str(&body)?)
    }
}
