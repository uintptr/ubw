use std::{env, fs, io::Write, path::PathBuf};

use anyhow::{Result, anyhow, bail};
use log::info;
use serde::Serialize;

#[cfg(target_os = "macos")]
const MOZ_NATIVE_MSG_HOST_DIR: &str = "NativeMessagingHosts";
#[cfg(target_os = "linux")]
const MOZ_NATIVE_MSG_HOST_DIR: &str = "native-messaging-hosts";

const BITW_JSON_FILE_NAME: &str = "com.8bit.bitwarden.json";
const BW_CONFIG_NAME: &str = "com.8bit.bitwarden";
const BW_CONFIG_DESC: &str = "Bitwarden desktop <-> browser bridge";
const BW_CONFIG_TYPE: &str = "stdio";
const BW_CONFIG_ALLOWED_EXT_UUID: &str = "{446900e4-71c2-419f-a6a7-df9c091e268b}";

#[derive(Serialize)]
struct MozProxyFile {
    name: &'static str,
    description: &'static str,
    path: PathBuf,
    #[serde(rename = "type")]
    io_type: &'static str,
    allowed_extensions: Vec<&'static str>,
}

fn find_moz_root() -> Result<PathBuf> {
    let moz_root = if cfg!(target_os = "macos") {
        let config = dirs::config_dir().ok_or_else(|| anyhow!("config dir not found"))?;
        config.join("Mozilla")
    } else if cfg!(target_os = "linux") {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("home dir wasn't found"))?;
        home.join(".mozilla")
    } else {
        bail!("not implemented");
    };

    Ok(moz_root)
}

fn find_native_msg_host_dir() -> Result<PathBuf> {
    let moz_root = find_moz_root()?;
    info!("mozilla root: {}", moz_root.display());
    Ok(moz_root.join(MOZ_NATIVE_MSG_HOST_DIR))
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub fn moz_install() -> Result<()> {
    let dir = find_native_msg_host_dir()?;

    //
    // we're installing so we'll have to make sure it exists
    //
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    let self_exe = env::current_exe()?;

    let config_file = dir.join(BITW_JSON_FILE_NAME);

    let config = MozProxyFile {
        name: BW_CONFIG_NAME,
        description: BW_CONFIG_DESC,
        path: self_exe,
        io_type: BW_CONFIG_TYPE,
        allowed_extensions: vec![BW_CONFIG_ALLOWED_EXT_UUID],
    };

    let config_data = serde_json::to_string_pretty(&config)?;

    let mut f = fs::OpenOptions::new()
        .truncate(true)
        .write(true)
        .create(true)
        .open(config_file)?;

    f.write_all(config_data.as_bytes())?;

    Ok(())
}

pub fn moz_uninstall() -> Result<()> {
    let dir = find_native_msg_host_dir()?;

    //
    // Nothing to do if it doesn't exist
    //
    if !dir.exists() {
        return Ok(());
    }

    let config_file = dir.join(BITW_JSON_FILE_NAME);

    if !config_file.exists() {
        return Ok(());
    }

    fs::remove_file(config_file)?;

    Ok(())
}
