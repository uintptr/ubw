use anyhow::Result;

#[cfg(target_os = "linux")]
mod memory;

#[cfg(target_os = "linux")]
pub use memory::MemoryStorage as CredStorage;

#[cfg(target_os = "macos")]
mod macos_enclave;

#[cfg(target_os = "macos")]
pub use macos_enclave::EnclaveStorage as CredStorage;

// In storage/mod.rs or a dedicated trait file
pub trait CredStorageTrait {
    fn new() -> Result<Self>
    where
        Self: Sized;
    fn add<K: Into<String>, V: AsRef<str>>(&mut self, key: K, value: V) -> Result<()>;
    fn get<K: AsRef<str>>(&self, key: K) -> Option<String>;
    fn remove<K: AsRef<str>>(&mut self, key: K);
}

#[cfg(test)]
mod tests {
    use crate::commands::agent::storage::{CredStorage, CredStorageTrait};

    #[test]
    fn test_enclave() {
        let mut storage = CredStorage::new().unwrap();

        storage.add("hello", "world").unwrap();

        let value = storage.get("hello").unwrap();

        assert_eq!(value, "world");
    }
}
