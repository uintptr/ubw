use std::collections::HashMap;

use anyhow::Result;
use secrecy::{ExposeSecret, SecretBox};

use crate::commands::agent::storage::CredStorageTrait;

pub struct MemoryStorage {
    memory: HashMap<String, SecretBox<String>>,
}

impl CredStorageTrait for MemoryStorage {
    fn new() -> Result<Self> {
        let memory = HashMap::new();

        Ok(Self { memory })
    }

    fn add<K, V>(&mut self, key: K, value: V) -> Result<()>
    where
        K: Into<String>,
        V: AsRef<str>,
    {
        let secret_value = SecretBox::new(Box::new(value.as_ref().to_string()));
        self.memory.insert(key.into(), secret_value);

        Ok(())
    }

    fn get<K>(&self, key: K) -> Option<String>
    where
        K: AsRef<str>,
    {
        let secret_value = self.memory.get(key.as_ref())?;
        Some(secret_value.expose_secret().to_string())
    }

    fn remove<K>(&mut self, key: K)
    where
        K: AsRef<str>,
    {
        self.memory.remove(key.as_ref());
    }
}
