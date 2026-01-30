use std::path::PathBuf;

use anyhow::{Context, Result};
use figlet_rs::FIGfont;
use rust_embed::{Embed, EmbeddedFile};

#[derive(Embed)]
#[folder = "fonts"]
struct FigFonts;

pub fn display_banner<S, F>(text: S, font: F) -> Result<()>
where
    S: AsRef<str>,
    F: AsRef<str>,
{
    let mut font_data: Option<EmbeddedFile> = None;

    for efont in FigFonts::iter() {
        let file_ext = PathBuf::from(efont.to_string());

        if let Some(font_name) = file_ext.file_stem()
            && font.as_ref() == font_name
        {
            font_data = FigFonts::get(&efont);
        }
    }

    let fig = match font_data {
        Some(v) => {
            let font_str = String::from_utf8_lossy(&v.data);
            FIGfont::from_content(&font_str)
                .map_err(|e| anyhow::anyhow!(e))
                .with_context(|| format!("failed to load embedded FIGfont '{}'", font.as_ref()))?
        }
        None => FIGfont::standard()
            .map_err(|e| anyhow::anyhow!(e))
            .context("failed to load standard FIGfont")?,
    };

    let content = fig.convert(text.as_ref());

    if let Some(banner) = content {
        println!("{banner}");
    }

    Ok(())
}
