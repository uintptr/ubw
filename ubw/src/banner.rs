use anyhow::{Result, bail};
use figlet_rs::FIGlet;
use log::error;

pub fn render_banner<S>(text: S) -> Result<String>
where
    S: AsRef<str>,
{
    let fig = match FIGlet::slant() {
        Ok(v) => v,
        Err(e) => {
            error!("{e}");
            bail!("Unable to load fonts");
        }
    };

    let content = fig.convert(text.as_ref());

    Ok(content.map(|b| b.to_string()).unwrap_or_default())
}
