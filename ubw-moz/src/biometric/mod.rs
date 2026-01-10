#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::biometric_login;

#[cfg(not(target_os = "macos"))]
mod no_op;
#[cfg(not(target_os = "macos"))]
pub use no_op::biometric_login;
