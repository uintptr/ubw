#[cfg(target_os = "linux")]
mod memory;

#[cfg(target_os = "linux")]
pub use memory::CredStorage;

#[cfg(target_os = "macos")]
mod macos_enclave;

#[cfg(target_os = "macos")]
pub use macos_enclave::CredStorage;
