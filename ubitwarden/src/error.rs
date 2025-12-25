use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;
#[derive(Debug, Error)]
pub enum Error {
    //
    // 1st party
    //
    #[error("Authentication not found")]
    AuthNotFoundError,
    #[error("Invalid KDF")]
    InvalidKDF,
    #[error("Data directory not found")]
    DataDirNotFound,
    #[error("Cache file not found")]
    CacheFileNotFound,
    #[error("Cache expired")]
    CacheExpired,
    #[error("Missing parameter: {0}")]
    MissingParamError(String),
    #[error("TOTP not found")]
    TotpNotFound,
    #[error("TOTP not implemented")]
    TotpNotImplemented,
    #[error("Client PID not found")]
    ClientPidNotFound,
    #[error("Invalid command format")]
    InvalidCommandFormat,
    #[error("Command not found: {command}")]
    CommandNotFound { command: String },
    #[error("Command empty key")]
    CommandEmptyKey,
    #[error("Command empty value")]
    CommandEmptyValue,
    #[error("Login Not Found")]
    LoginNotFound,
    #[error("Password Not Found")]
    PasswordNotFound,

    //
    // 2d party
    //
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Casting(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TimeError(#[from] std::time::SystemTimeError),

    //
    // 3rd party
    //
    #[error(transparent)]
    HttpError(#[from] reqwest::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    BwCryptoError(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    TotpSecretError(#[from] totp_rs::SecretParseError),
    #[error(transparent)]
    TotpUrlError(#[from] totp_rs::TotpUrlError),
}
