use anyhow::{Result, bail};
use localauthentication_rs::{LAPolicy, LocalAuthentication};

pub async fn biometric_login() -> Result<()> {
    let local_authentication = LocalAuthentication::new();

    let authenticated = local_authentication.evaluate_policy(
        LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
        "Use Touch ID to Unlock",
    );

    if authenticated { Ok(()) } else { bail!("Auth failure") }
}
