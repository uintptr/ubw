use clap::Args;

#[cfg(target_os = "linux")]
pub mod x11;
#[cfg(target_os = "linux")]
pub use x11::command_xsecurelock;
#[cfg(not(target_os = "linux"))]
mod noop;
#[cfg(not(target_os = "linux"))]
pub use noop::command_xsecurelock;

#[derive(Args)]
pub struct XSecureLockArgs {
    /// email address
    #[arg(short, long)]
    pub email: String,

    /// server url
    #[arg(short, long)]
    pub server_url: String,
}
