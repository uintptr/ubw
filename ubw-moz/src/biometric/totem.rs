use std::{path::PathBuf, process::Stdio};

use anyhow::{Result, anyhow, bail};
use log::{error, info};
use tokio::process::Command;
use which::which;

fn cargo_bin() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("home not found"))?;
    Ok(home.join(".cargo").join("bin"))
}

fn find_totem() -> Result<PathBuf> {
    let totem = match which("totem") {
        Ok(v) => v,
        Err(_) => {
            let cargo_bin = cargo_bin()?;

            let totem = cargo_bin.join("totem");

            totem
        }
    };

    Ok(totem)
}

pub async fn biometric_login() -> Result<()> {
    let totem = match find_totem() {
        Ok(v) => v,
        Err(e) => {
            error!("unable to find totem ({e}");
            return Err(e);
        }
    };

    info!("executing {}", totem.display());

    let out = match Command::new(totem).stdout(Stdio::piped()).output().await {
        Ok(v) => v,
        Err(e) => {
            error!("{} failed with {e}", totem.display());
            return Err(e);
        }
    };

    match String::from_utf8(out.stdout)?.as_str() {
        "1" => Ok(()),
        _ => bail!("Invalid totem"),
    }
}
