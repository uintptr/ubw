use anyhow::Result;

#[cfg(target_os = "linux")]
mod memory;

#[cfg(target_os = "linux")]
pub use memory::MemoryStorage as CredStorage;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::EnclaveStorage as CredStorage;

// In storage/mod.rs or a dedicated trait file
pub trait CredStorageTrait {
    fn new() -> Result<Self>
    where
        Self: Sized;

    fn add<K, V>(&mut self, key: K, value: V) -> Result<()>
    where
        K: Into<String>,
        V: AsRef<str>;
    fn get<K>(&self, key: K) -> Option<String>
    where
        K: AsRef<str>;
    fn remove<K>(&mut self, key: K)
    where
        K: AsRef<str>;
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use crate::commands::agent::storage::{CredStorage, CredStorageTrait};

    #[test]
    fn test_enclave() -> Result<()> {
        let mut storage = CredStorage::new()?;

        storage.add("hello", "world")?;

        if let Some(value) = storage.get("hello") {
            assert_eq!(value, "world");
        }

        Ok(())
    }
}
