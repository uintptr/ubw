use derive_more::Display;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_repr::Deserialize_repr;

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

#[derive(Debug, Deserialize)]
pub struct BwPreLogin {
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
}

#[derive(Debug, Deserialize)]
pub struct BwSync {
    pub ciphers: Vec<BwCipher>,
    pub profile: BwProfile,
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

//
// type = 1
//
#[derive(Debug, Deserialize)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    #[serde(rename = "passwordRevisionDate")]
    pub password_revision_date: Option<String>,
    #[serde(rename = "autofillOnPageLoad")]
    pub autofill_on_page_load: Option<bool>,
    pub uri: Option<String>,
    pub uris: Option<Vec<serde_json::Value>>,
}
//
// type = 2
//
#[derive(Debug, Deserialize)]
pub struct BwNote {
    #[serde(rename = "type")]
    pub note_type: Option<u8>,
}

//
// type = 3
//
#[derive(Debug, Deserialize)]
pub struct BwCard {
    #[serde(rename = "cardholderName")]
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    #[serde(rename = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(rename = "expYear")]
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

//
// type = 4
//
#[derive(Debug, Deserialize)]
pub struct BwIdentity {
    pub username: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(rename = "middleName")]
    pub middle_name: Option<String>,
}

//
// type = 5
//
#[derive(Debug, Deserialize)]
pub struct BwSshKey {
    pub name: Option<String>,
    #[serde(rename = "keyFingerprint")]
    pub key_fingerprint: String,
    #[serde(rename = "privateKey")]
    pub private_key: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug)]
pub enum BwCipherData {
    Login(BwLogin),
    Note(BwNote),
    Card(BwCard),
    Identity(BwIdentity),
    Ssh(BwSshKey),
}

fn deserialize_cipher_data<'de, D>(deserializer: D) -> Result<BwCipherData, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;

    let cipher_type = if value.get("totp").is_some() {
        BwCipherType::Login
    } else if value.get("keyFingerprint").is_some() {
        BwCipherType::Ssh
    } else if value.get("notes").is_some() {
        BwCipherType::Note
    } else if value.get("cardholderName").is_some() {
        BwCipherType::Card
    } else if value.get("passportNumber").is_some() {
        BwCipherType::Identity
    } else {
        return Err(serde::de::Error::custom("Unsupported data type"));
    };

    match cipher_type {
        BwCipherType::Login => serde_json::from_value(value.clone())
            .map(BwCipherData::Login)
            .map_err(serde::de::Error::custom),
        BwCipherType::Note => serde_json::from_value(value.clone())
            .map(BwCipherData::Note)
            .map_err(serde::de::Error::custom),
        BwCipherType::Card => serde_json::from_value(value.clone())
            .map(BwCipherData::Card)
            .map_err(serde::de::Error::custom),
        BwCipherType::Identity => serde_json::from_value(value.clone())
            .map(BwCipherData::Identity)
            .map_err(serde::de::Error::custom),
        BwCipherType::Ssh => serde_json::from_value(value.clone())
            .map(BwCipherData::Ssh)
            .map_err(serde::de::Error::custom),
    }
}

impl<'de> Deserialize<'de> for BwCipherData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_cipher_data(deserializer)
    }
}

#[derive(Debug, Deserialize)]
pub struct BwCipher {
    pub id: String,
    pub name: String,
    #[serde(rename = "deletedDate")]
    pub deleted_data: Option<String>,
    #[serde(deserialize_with = "deserialize_cipher_data")]
    pub data: BwCipherData,
    #[serde(rename = "type")]
    pub cipher_type: BwCipherType,
}

impl BwCipher {
    #[must_use]
    pub fn deleted(&self) -> bool {
        self.deleted_data.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use log::LevelFilter;
    use rstaples::logging::StaplesLogger;

    use crate::api_types::BwCipher;

    #[test]
    fn test_deserialize_sample() {
        StaplesLogger::new().with_colors().with_log_level(LevelFilter::Info).start();
        let manifest_dir = env!("CARGO_WORKSPACE_DIR");
        let sample_file = PathBuf::from(manifest_dir).join("samples").join("ciphers.json");
        let data = fs::read_to_string(sample_file).unwrap();
        serde_json::from_str::<Vec<BwCipher>>(&data).unwrap();
    }
}
