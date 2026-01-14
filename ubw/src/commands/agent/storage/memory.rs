use std::collections::HashMap;

use anyhow::Result;

use crate::commands::agent::storage::CredStorageTrait;

pub struct MemoryStorage {
    memory: HashMap<String, String>,
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
        self.memory.insert(key.into(), value.as_ref().into());
        Ok(())
    }

    fn get<K>(&self, key: K) -> Option<String>
    where
        K: AsRef<str>,
    {
        self.memory.get(key.as_ref()).cloned()
    }

    fn remove<K>(&mut self, key: K)
    where
        K: AsRef<str>,
    {
        self.memory.remove(key.as_ref());
    }
}
