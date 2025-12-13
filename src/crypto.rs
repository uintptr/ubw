use std::{num::NonZero, str::FromStr};

use anyhow::Result;
use bitwarden_crypto::{EncString, Kdf, KeyDecryptable, MasterKey, SymmetricCryptoKey};
use log::info;

use crate::{api::BwAuth, config::BwConfig, error::Error};

pub struct BwCrypt {
    symmetric_key: SymmetricCryptoKey,
}

impl BwCrypt {
    pub fn new(config: &BwConfig, auth: &BwAuth) -> Result<Self> {
        let Some(nz_ndf) = NonZero::new(auth.kdf_iterations) else {
            return Err(Error::InvalidKDF.into());
        };

        let kdf = Kdf::PBKDF2 { iterations: nz_ndf };

        // this takes a long time in debug
        info!("deriving master key");
        let master = MasterKey::derive(&config.credentials.password, &config.credentials.email, &kdf)?;

        let enc_key = EncString::from_str(&auth.key)?;

        let symmetric_key: SymmetricCryptoKey = master.decrypt_user_key(enc_key)?;

        Ok(Self { symmetric_key })
    }

    pub fn decrypt<S>(&self, encoded: S) -> Result<Vec<u8>>
    where
        S: AsRef<str>,
    {
        let enc_string = EncString::from_str(encoded.as_ref())?;

        let decrypted = enc_string.decrypt_with_key(&self.symmetric_key)?;

        Ok(decrypted)
    }
}
