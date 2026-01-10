use anyhow::{Result, bail};

pub async fn biometric_login() -> Result<()> {
    bail!("Biometric authentication is not supported on this platform")
}
