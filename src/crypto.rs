use std::{num::NonZero, str::FromStr};

use log::info;

use anyhow::Result;
use bitwarden_crypto::{EncString, HashPurpose, Kdf, KeyDecryptable, MasterKey, SymmetricCryptoKey};

use crate::{api::BwAuth, error::Error};

pub struct BwCrypt {
    symmetric_key: SymmetricCryptoKey,
}

fn hash_password<E, P>(email: E, password: P, kdf: &Kdf) -> Result<String>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    let master_key = MasterKey::derive(password.as_ref(), email.as_ref(), kdf)?;
    let password_hash =
        master_key.derive_master_key_hash(password.as_ref().as_bytes(), HashPurpose::ServerAuthorization)?;
    Ok(password_hash)
}

pub fn build_password_hash<E, P>(kdf_iterations: u32, email: E, password: P) -> Result<String>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    let Some(nz_ndf) = NonZero::new(kdf_iterations) else {
        return Err(Error::InvalidKDF.into());
    };

    let kdf = Kdf::PBKDF2 { iterations: nz_ndf };

    hash_password(email, password, &kdf)
}

impl BwCrypt {
    pub fn from_password<E, P>(email: E, password: P, auth: &BwAuth) -> Result<Self>
    where
        E: AsRef<str>,
        P: AsRef<str>,
    {
        let Some(nz_ndf) = NonZero::new(auth.kdf_iterations) else {
            return Err(Error::InvalidKDF.into());
        };

        let kdf = Kdf::PBKDF2 { iterations: nz_ndf };

        // this takes a long time in debug
        info!("deriving master key");
        let master = MasterKey::derive(password.as_ref(), email.as_ref(), &kdf)?;

        let enc_key = EncString::from_str(&auth.key)?;

        let symmetric_key: SymmetricCryptoKey = master.decrypt_user_key(enc_key)?;

        Ok(Self { symmetric_key })
    }

    pub fn from_encoded_key<S>(encoded_key: S) -> Result<Self>
    where
        S: AsRef<str>,
    {
        let symmetric_key = SymmetricCryptoKey::try_from(encoded_key.as_ref().to_string())?;

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

    #[must_use]
    pub fn export(&self) -> String {
        self.symmetric_key.to_base64()
    }
}
