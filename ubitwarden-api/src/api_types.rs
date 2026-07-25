use derive_more::Display;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;
use zeroize::ZeroizeOnDrop;

use crate::session::BwSession;

#[derive(Debug, Clone, Default, Serialize, Deserialize, ZeroizeOnDrop)]
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

#[derive(Debug, Deserialize, ZeroizeOnDrop)]
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

#[derive(Display, Debug, Clone, Copy, Deserialize_repr)]
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
    //pub uris: Option<Vec<serde_json::Value>>,
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
#[derive(Debug, Deserialize, ZeroizeOnDrop)]
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
#[derive(Debug, Deserialize, ZeroizeOnDrop)]
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
#[derive(Debug, Deserialize, ZeroizeOnDrop)]
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

#[derive(Debug, Deserialize)]
pub struct BwCipherField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: u64,
    pub value: String,
}

/// Wire format of a cipher as returned by `/api/ciphers` and `/api/sync`.
///
/// The server sends the type-specific payload in a sibling key named after the
/// type (`login`, `secureNote`, ...) rather than in a single `data` object, so
/// the useful one is picked out by the `type` discriminant.
#[derive(Debug, Deserialize)]
struct BwCipherWire {
    id: String,
    name: String,
    #[serde(rename = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "type")]
    cipher_type: BwCipherType,
    fields: Option<Vec<BwCipherField>>,
    login: Option<BwLogin>,
    #[serde(rename = "secureNote")]
    secure_note: Option<BwNote>,
    card: Option<BwCard>,
    identity: Option<BwIdentity>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<BwSshKey>,
}

impl TryFrom<BwCipherWire> for BwCipher {
    type Error = String;

    fn try_from(wire: BwCipherWire) -> Result<Self, Self::Error> {
        let data = match wire.cipher_type {
            BwCipherType::Login => wire.login.map(BwCipherData::Login),
            BwCipherType::Note => wire.secure_note.map(BwCipherData::Note),
            BwCipherType::Card => wire.card.map(BwCipherData::Card),
            BwCipherType::Identity => wire.identity.map(BwCipherData::Identity),
            BwCipherType::Ssh => wire.ssh_key.map(BwCipherData::Ssh),
        };

        let data = data.ok_or_else(|| {
            format!("cipher {} has type {} but no matching payload", wire.id, wire.cipher_type)
        })?;

        Ok(Self {
            id: wire.id,
            name: wire.name,
            deleted_data: wire.deleted_date,
            data,
            cipher_type: wire.cipher_type,
            fields: wire.fields.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "BwCipherWire")]
pub struct BwCipher {
    pub id: String,
    pub name: String,
    pub deleted_data: Option<String>,
    pub data: BwCipherData,
    pub cipher_type: BwCipherType,
    pub fields: Vec<BwCipherField>,
}

impl BwCipher {
    #[must_use]
    pub fn deleted(&self) -> bool {
        self.deleted_data.is_some()
    }

    pub fn field_by_name<S>(&self, session: &BwSession, name: S) -> Option<&BwCipherField>
    where
        S: AsRef<str>,
    {
        for f in &self.fields {
            if let Ok(encoded_name) = session.decrypt(&f.name)
                && let Ok(field_name) = TryInto::<String>::try_into(encoded_name)
                && field_name == name.as_ref()
            {
                return Some(f);
            }
        }

        None
    }
}
