use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{api::BwAuth, error::Error};

#[derive(Deserialize, Serialize)]
struct BwCachedAuthData {
    ts: u64,
    auth: BwAuth,
}

pub struct BwCachedAuth {
    file_path: PathBuf,
}

impl BwCachedAuth {
    pub fn new() -> Result<Self> {
        let data_dir = dirs::data_dir().ok_or(anyhow!(Error::DataDirNotFound))?;

        let cache_dir = data_dir.join(env!("CARGO_PKG_NAME"));

        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }

        let file_path = cache_dir.join("auth.json");

        info!("auth cache file: {}", file_path.display());

        Ok(Self { file_path })
    }

    pub fn load(&self) -> Result<BwAuth> {
        if !self.file_path.exists() {
            return Err(Error::CacheFileNotFound.into());
        }

        info!("{} exists", self.file_path.display());

        let data = fs::read_to_string(&self.file_path)?;

        let cached_data: BwCachedAuthData = serde_json::from_str(&data)?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let expiry = cached_data.ts + cached_data.auth.expires_in;

        if expiry < now {
            warn!("{} expired", self.file_path.display());

            if let Err(e) = fs::remove_file(&self.file_path) {
                error!("unable to delete {} ({e})", self.file_path.display());
            }

            return Err(Error::CacheExpired.into());
        }

        Ok(cached_data.auth)
    }

    pub fn save(&self, auth: &BwAuth) -> Result<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let cache = BwCachedAuthData { ts, auth: auth.clone() };

        let cache_json = serde_json::to_string_pretty(&cache)?;

        fs::write(&self.file_path, cache_json.as_bytes())?;

        Ok(())
    }
}
