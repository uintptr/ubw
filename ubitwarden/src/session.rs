use std::time::{SystemTime, UNIX_EPOCH};

use log::info;
use serde::{Deserialize, Serialize};

use crate::{api_types::BwAuth, credentials::BwCredentials, crypto::BwCrypt, error::Result};

const BW_SESSION_EXPIRED_SEC: u64 = 30;

#[derive(Debug, Deserialize, Serialize)]
pub struct BwSession {
    ts: u64,
    pub email: String,
    pub server_url: String,
    pub auth: BwAuth,
    pub key: String,
}

impl BwSession {
    pub fn new(creds: &BwCredentials, auth: &BwAuth) -> Result<Self> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let crypt = BwCrypt::from_password(&creds.email, &creds.password, auth)?;
        let key = crypt.export();

        Ok(Self {
            ts,
            email: creds.email.clone(),
            server_url: creds.server_url.clone(),
            auth: auth.clone(),
            key,
        })
    }

    pub fn expired(&self) -> Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expiry = self.ts.saturating_add(self.auth.expires_in);
        let rem_sec = expiry.saturating_sub(now);
        info!("session expires in {rem_sec}");
        Ok(rem_sec < BW_SESSION_EXPIRED_SEC)
    }
}
