use thiserror::Error;
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Debug, Error)]
pub enum Error {
    //
    // 1st party
    //
    AuthNotFoundError,
    InvalidKDF,
    DataDirNotFound,
    CacheFileNotFound,
    CacheExpired,
    MissingParamError(String),
    TotpNotFound,
    TotpNotImplemented,
    ClientPidNotFound,
    InvalidCommandFormat,
    CommandNotFound { command: String },
    CommandEmptyKey,
    CommandEmptyValue,
    //
    // 2d party
    //
    Io(#[from] std::io::Error),
    Utf8(#[from] std::string::FromUtf8Error),
    Casting(#[from] std::num::TryFromIntError),
    TimeError(#[from] std::time::SystemTimeError),

    //
    // 3rd party
    //
    HttpError(#[from] reqwest::Error),
    Serialization(#[from] serde_json::Error),
    BwCryptoError(#[from] bitwarden_crypto::CryptoError),
    TotpSecretError(#[from] totp_rs::SecretParseError),
    TotpUrlError(#[from] totp_rs::TotpUrlError),
}
impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}
