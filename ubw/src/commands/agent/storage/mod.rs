#[cfg(target_os = "linux")]
mod memory;

use anyhow::Result;
#[cfg(target_os = "linux")]
pub use memory::MemoryStorage as CredStorage;

// In storage/mod.rs or a dedicated trait file
pub trait CredStorageTrait {
    fn new() -> Result<Self>
    where
        Self: Sized;
    fn add<K: Into<String>, V: AsRef<str>>(&mut self, key: K, value: V) -> Result<()>;
    fn get<K: AsRef<str>>(&self, key: K) -> Option<String>;
    fn remove<K: AsRef<str>>(&mut self, key: K);
}
