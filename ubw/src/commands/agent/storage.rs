use std::collections::HashMap;

pub struct CredStorage {
    memory: HashMap<String, String>,
}

impl CredStorage {
    pub fn new() -> Self {
        let memory = HashMap::new();

        Self { memory }
    }

    pub fn add<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.memory.insert(key.into(), value.into());
    }

    pub fn get<K>(&self, key: K) -> Option<&String>
    where
        K: AsRef<str>,
    {
        self.memory.get(key.as_ref())
    }

    pub fn remove<K>(&mut self, key: K)
    where
        K: AsRef<str>,
    {
        self.memory.remove(key.as_ref());
    }
}
