use std::env;

use anyhow::Result;
use dialoguer::Password;
use log::info;
use ubitwarden::{
    cache::common::{fetch_user_data, store_user_data},
    credentials::BwCredentials,
};

pub async fn fetch_credentials() -> Result<BwCredentials> {
    let data = fetch_user_data("credentials").await?;
    let creds: BwCredentials = serde_json::from_str(&data)?;
    info!("found credentials for {}", creds.email);
    Ok(creds)
}

pub async fn store_credentials<E, U>(email: E, server_url: U) -> Result<()>
where
    E: AsRef<str>,
    U: AsRef<str>,
{
    //
    // helps with testing but not recommended
    //
    let password = if let Ok(password) = env::var("UBW_PASSWORD") {
        info!("using UBW_PASSWORD=***********");
        password.clone()
    } else {
        let prompt = format!("Password for {}", email.as_ref());
        Password::new().with_prompt(prompt).interact()?
    };

    let creds = BwCredentials {
        email: email.as_ref().to_string(),
        password,
        server_url: server_url.as_ref().to_string(),
    };

    let encoded_creds = serde_json::to_string(&creds)?;

    store_user_data("credentials", encoded_creds).await?;

    Ok(())
}
