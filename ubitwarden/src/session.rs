use std::{
    fmt,
    ops::Deref,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{api_types::BwAuth, credentials::BwCredentials, crypto::BwCrypt, error::Result};

const BW_SESSION_GRACE: u64 = 30;

#[derive(Debug, Deserialize, Serialize)]
pub struct BwSessionData {
    expiry_ts: u64,
    pub email: String,
    pub server_url: String,
    pub auth: BwAuth,
    pub key: String,
}

impl BwSessionData {
    pub fn new(crypt: &BwCrypt, creds: &BwCredentials, auth: &BwAuth) -> Result<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // added a grace period so we have to re-auth
        let expiry_ts = now + auth.expires_in - BW_SESSION_GRACE;

        let key = crypt.export();

        Ok(Self {
            expiry_ts,
            email: creds.email.clone(),
            server_url: creds.server_url.clone(),
            auth: auth.clone(),
            key,
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
        let inner: BwSessionData = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                info!("unable to deserialize session data ({e})");
                return Err(e.into());
            }
        };

        let crypt = match BwCrypt::from_encoded_key(&inner.key) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to load key from session data ({e})");
                return Err(e.into());
            }
        };

        Ok(Self { inner, crypt })
    }
}

impl BwSession {
    pub fn new(creds: &BwCredentials, auth: &BwAuth) -> Result<Self> {
        let crypt = BwCrypt::from_password(&creds.email, &creds.password, auth)?;

        let inner = BwSessionData::new(&crypt, creds, auth)?;

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

        if now > self.expiry_ts {
            warn!("session expired")
        }

        Ok(now > self.expiry_ts)
    }
}
