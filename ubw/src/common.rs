use std::env;

use anyhow::Result;
use dialoguer::Password;
use log::{error, info, warn};
use ubitwarden::{api::BwApi, credentials::BwCredentials, session::BwSession};

use crate::commands::server::utils::{fetch_user_data, store_user_data};

async fn fetch_session() -> Result<BwSession> {
    let data = fetch_user_data("session").await?;
    let session: BwSession = serde_json::from_str(&data)?;
    Ok(session)
}

async fn store_session(session: &BwSession) -> Result<()> {
    let encoded_session = serde_json::to_string(session)?;
    store_user_data("session", encoded_session).await?;
    Ok(())
}

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
    let api = BwApi::new(&email, &server_url)?;

    let password = loop {
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

        //
        // try them
        //
        if let Err(e) = api.auth(&password).await {
            error!("auth failure {e}");
            continue;
        }

        break password;
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

pub async fn load_session() -> Result<BwSession> {
    if let Ok(session) = fetch_session().await {
        if session.expired()? {
            warn!("session expired");
            //
            // see if the session is still usable ( expired )
            //
        } else {
            return Ok(session);
        }
    }

    let creds = fetch_credentials().await?;

    //
    // Either it didn't exist or it was expired. let's rejoin
    //
    let api = BwApi::new(&creds.email, &creds.server_url)?;

    let auth = api.auth(&creds.password).await?;

    let session = BwSession::new(&creds, &auth)?;

    // best effort. not fatal since we got what we wanted
    if let Err(e) = store_session(&session).await {
        error!("Unable to store session: ({e})");
    }

    Ok(session)
}
