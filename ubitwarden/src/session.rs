use std::{
    fmt,
    ops::Deref,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use log::info;
use serde::{Deserialize, Serialize};

use crate::{api_types::BwAuth, credentials::BwCredentials, crypto::BwCrypt, error::Result};

const BW_SESSION_EXPIRED_SEC: u64 = 30;

#[derive(Debug, Deserialize, Serialize)]
pub struct BwSessionData {
    ts: u64,
    pub email: String,
    pub server_url: String,
    pub auth: BwAuth,
}

impl BwSessionData {
    pub fn new(creds: &BwCredentials, auth: &BwAuth) -> Result<Self> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(Self {
            ts,
            email: creds.email.clone(),
            server_url: creds.server_url.clone(),
            auth: auth.clone(),
        })
    }
}

pub struct BwSession {
    inner: BwSessionData,
    crypt: BwCrypt,
}

impl fmt::Display for BwSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match serde_json::to_string(&self.inner) {
            Ok(v) => v,
            Err(e) => {
                log::error!("serde error {e}");
                return Err(fmt::Error);
            }
        };

        write!(f, "{s}")
    }
}

impl Deref for BwSession {
    type Target = BwSessionData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl FromStr for BwSession {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let inner: BwSessionData = serde_json::from_str(s)?;

        let crypt = BwCrypt::from_encoded_key(&inner.auth.key)?;

        Ok(Self { inner, crypt })
    }
}

impl BwSession {
    pub fn new(creds: &BwCredentials, auth: &BwAuth) -> Result<Self> {
        let inner = BwSessionData::new(creds, auth)?;

        let crypt = BwCrypt::from_password(&creds.email, &creds.password, auth)?;

        Ok(Self { inner, crypt })
    }

    pub fn decrypt<S>(&self, input: S) -> Result<Vec<u8>>
    where
        S: AsRef<str>,
    {
        self.crypt.decrypt(input)
    }

    pub fn parse_totp<T>(&self, encrypted_totp: T) -> Result<String>
    where
        T: AsRef<str>,
    {
        self.crypt.parse_totp(encrypted_totp)
    }

    pub fn expired(&self) -> Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expiry = self.inner.ts.saturating_add(self.inner.auth.expires_in);
        let rem_sec = expiry.saturating_sub(now);
        info!("session expires in {rem_sec}");
        Ok(rem_sec < BW_SESSION_EXPIRED_SEC)
    }
}
