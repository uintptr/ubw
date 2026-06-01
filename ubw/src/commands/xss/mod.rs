use clap::Args;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod x11;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use x11::command_xsecurelock;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod noop;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
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
