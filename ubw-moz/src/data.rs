use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use tokio::fs;

const UBW_MOZ_DATA_DIR: &str = env!("CARGO_PKG_NAME");

pub async fn init_data_dir() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| anyhow!("unable to find data dir"))?;
    let data_dir = data_dir.join(UBW_MOZ_DATA_DIR);

    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)
            .await
            .with_context(|| format!("failed to create data directory at {}", data_dir.display()))?;
    }

    Ok(data_dir)
}
