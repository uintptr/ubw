use std::collections::HashMap;

use anyhow::{Result, bail};
use log::error;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

use crate::commands::agent::storage::CredStorageTrait;

pub struct EnclaveStorage {
    key: SecKey,
    memory: HashMap<String, Vec<u8>>,
}

impl CredStorageTrait for EnclaveStorage {
    fn new() -> Result<Self> {
        let memory = HashMap::new();

        let mut opt = GenerateKeyOptions::default();

        opt.set_token(security_framework::key::Token::SecureEnclave);
        opt.set_key_type(KeyType::ec());
        opt.set_size_in_bits(256);

        let key = match SecKey::new(&opt) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to create enclave key ({e})");
                bail!("Unable to create enclave key");
            }
        };

        Ok(Self { key, memory })
    }

    fn add<K, V>(&mut self, key: K, value: V) -> Result<()>
    where
        K: Into<String>,
        V: AsRef<str>,
    {
        if let Some(public_key) = self.key.public_key() {
            let data = value.as_ref().as_bytes();

            let ret = public_key.encrypt_data(
                security_framework::key::Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                data,
            );

            let ciphertext = match ret {
                Ok(v) => v,
                Err(e) => {
                    error!("Unable to encrypt value ({e})");
                    bail!("Unable to encrypt value");
                }
            };

            self.memory.insert(key.into(), ciphertext);
        } else {
            bail!("public key not found");
        }

        Ok(())
    }

    fn get<K>(&self, key: K) -> Option<String>
    where
        K: AsRef<str>,
    {
        let cipher_text = self.memory.get(key.as_ref())?;

        let ret = self.key.decrypt_data(
            security_framework::key::Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
            cipher_text,
        );

        let plain = match ret {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to decrypt key for {} ({e})", key.as_ref());
                return None;
            }
        };

        String::from_utf8(plain).ok()
    }

    fn remove<K>(&mut self, key: K)
    where
        K: AsRef<str>,
    {
        self.memory.remove(key.as_ref());
    }
}
