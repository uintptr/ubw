#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::biometric_login;

#[cfg(not(target_os = "macos"))]
mod passthru;
#[cfg(not(target_os = "macos"))]
pub use passthru::biometric_login;
