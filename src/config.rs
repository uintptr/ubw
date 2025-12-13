use std::{fs, path::Path};

use anyhow::Result;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BwCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct BwServer {
    pub url: String,
}

#[derive(Deserialize)]
pub struct BwConfig {
    pub credentials: BwCredentials,
    pub server: BwServer,
}

impl BwConfig {
    pub fn from_file<P>(file_path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let file_data = fs::read_to_string(file_path)?;

        let config = toml::from_str(&file_data)?;

        Ok(config)
    }
}
