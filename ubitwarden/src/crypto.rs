use std::{num::NonZero, str::FromStr};

use bitwarden_encoding::B64;
use log::{error, info};

use bitwarden_crypto::{EncString, HashPurpose, Kdf, KeyDecryptable, MasterKey, SymmetricCryptoKey};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    api::BwAuth,
    error::{Error, Result},
};

pub struct BwCrypt {
    symmetric_key: SymmetricCryptoKey,
}

fn hash_password<E, P>(email: E, password: P, kdf: &Kdf) -> Result<B64>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    let master_key = MasterKey::derive(password.as_ref(), email.as_ref(), kdf)?;
    let password_hash =
        master_key.derive_master_key_hash(password.as_ref().as_bytes(), HashPurpose::ServerAuthorization);

    Ok(password_hash)
}

pub fn build_password_hash<E, P>(kdf_iterations: u32, email: E, password: P) -> Result<String>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    let Some(nz_ndf) = NonZero::new(kdf_iterations) else {
        return Err(Error::InvalidKDF);
    };

    let kdf = Kdf::PBKDF2 { iterations: nz_ndf };

    let b64_data = hash_password(email, password, &kdf)?;

    Ok(String::from(b64_data))
}

impl BwCrypt {
    pub fn from_password<E, P>(email: E, password: P, auth: &BwAuth) -> Result<Self>
    where
        E: AsRef<str>,
        P: AsRef<str>,
    {
        let Some(nz_ndf) = NonZero::new(auth.kdf_iterations) else {
            return Err(Error::InvalidKDF);
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

    pub fn parse_totp<T>(&self, encrypted_totp: T) -> Result<String>
    where
        T: AsRef<str>,
    {
        let totp_string: String = self.decrypt(encrypted_totp)?.try_into()?;

        if totp_string.starts_with("otpauth://") {
            // Try parsing with validation first
            let totp = match TOTP::from_url(&totp_string) {
                Ok(v) => v,
                Err(e) => {
                    // If from_url fails, try the unchecked variant
                    info!("from_url failed ({e}), attempting from_url_unchecked");

                    match TOTP::from_url_unchecked(&totp_string) {
                        Ok(v) => v,
                        Err(e) => {
                            // If unchecked also fails (e.g., invalid base32 with lowercase),
                            // try normalizing the URL by uppercasing the secret parameter
                            info!("from_url_unchecked failed ({e}), attempting to normalize secret to uppercase");

                            // Parse URL and uppercase the secret parameter
                            let normalized = if let Some(secret_start) = totp_string.find("secret=") {
                                let secret_end_pos = secret_start.saturating_add(7);
                                let before_secret = &totp_string[..secret_end_pos]; // "secret="
                                let after_secret = &totp_string[secret_end_pos..];

                                // Find the end of the secret (next & or end of string)
                                let secret_end = after_secret.find('&').unwrap_or(after_secret.len());
                                let secret = &after_secret[..secret_end];
                                let rest = &after_secret[secret_end..];

                                format!("{}{}{}", before_secret, secret.to_uppercase(), rest)
                            } else {
                                totp_string.clone()
                            };

                            match TOTP::from_url_unchecked(&normalized) {
                                Ok(v) => v,
                                Err(e) => {
                                    error!("unable to parse {totp_string} ({e})");
                                    return Err(e.into());
                                }
                            }
                        }
                    }
                }
            };
            let otp = totp.generate_current()?;
            Ok(otp)
        } else {
            let secret = Secret::Encoded(totp_string.clone()).to_bytes()?;

            // Try with validation first
            let ret = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret.clone(),
                Some("example".to_string()),
                "test@example.com".to_string(),
            );

            match ret {
                Ok(v) => {
                    let otp = v.generate_current()?;
                    Ok(otp)
                }
                Err(e) => {
                    // If validation fails (likely due to short secret < 128 bits),
                    // use the unchecked variant
                    info!("TOTP::new failed ({e}), attempting new_unchecked for short secret");
                    let totp = TOTP::new_unchecked(
                        Algorithm::SHA1,
                        6,
                        1,
                        30,
                        secret,
                        Some("example".to_string()),
                        "test@example.com".to_string(),
                    );
                    let otp = totp.generate_current()?;
                    Ok(otp)
                }
            }
        }
    }

    #[must_use]
    pub fn export(&self) -> String {
        String::from(self.symmetric_key.to_base64())
    }
}
