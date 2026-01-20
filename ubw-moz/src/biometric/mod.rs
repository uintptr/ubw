#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::biometric_login;

#[cfg(not(target_os = "macos"))]
mod totem;
#[cfg(not(target_os = "macos"))]
pub use totem::biometric_login;
