use anyhow::{Context, Result};
use clap::Args;
use ubitwarden::{api_types::BwCipher, session::BwSession};

#[derive(Args)]
pub struct IdArgs {
    /// cipher id
    #[arg(short, long)]
    pub id: String,
}

/// Shown in place of a name we couldn't read, so the entry is still listed.
pub const UNREADABLE: &str = "<unable to decrypt>";

/// Name a cipher as well as we can.
///
/// The name is encrypted with the same key as everything else, so it isn't
/// always readable, and then the id is all we have to go on.
fn describe(session: &BwSession, cipher: &BwCipher) -> String {
    let name = session
        .decrypt(&cipher.name)
        .ok()
        .and_then(|plain| String::try_from(plain).ok());

    match name {
        Some(name) => format!("'{name}' ({})", cipher.id),
        None => format!("cipher {}", cipher.id),
    }
}

/// Decrypt one field of a cipher, saying which cipher and which field failed.
///
/// A MAC mismatch here usually means the item belongs to an organization: those
/// are encrypted with the organization's key, which we don't hold.
pub fn decrypt_field<S>(session: &BwSession, cipher: &BwCipher, field: &str, value: S) -> Result<String>
where
    S: AsRef<str>,
{
    let plain = session.decrypt(value.as_ref()).with_context(|| {
        format!(
            "could not decrypt the {field} of {} (it may belong to an organization, which isn't supported yet)",
            describe(session, cipher)
        )
    })?;

    String::try_from(plain).with_context(|| {
        format!(
            "the {field} of {} did not decrypt to valid text",
            describe(session, cipher)
        )
    })
}

pub const UBW_DATA_DIR: &str = env!("CARGO_PKG_NAME");
pub const UBW_CONFIG_DIR: &str = env!("CARGO_PKG_NAME");
pub const UBW_APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const UBW_APP_VERSION: &str = env!("CARGO_PKG_VERSION");
