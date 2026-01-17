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
    #[error("Command Not Implemented")]
    CommandNotImplemented,
    #[error("Command empty key")]
    CommandEmptyKey,
    #[error("Command empty value")]
    CommandEmptyValue,
    #[error("Login Not Found")]
    LoginNotFound,
    #[error("Password Not Found")]
    PasswordNotFound,
    #[error("Client Verification Failure")]
    ClientVerificationFailure,
    #[error("Shutdown Requested")]
    Shutdown,
    #[error("Authentication Failure")]
    AuthFailure,
    #[error("Unknown type={0}")]
    UnknownTypeInt(u64),
    #[error("Basename failure")]
    BasenameError,
    #[error("Invalid Command")]
    CommandInvalid,
    #[error("Command Data Missing")]
    CommandDataMissing,
    #[error("Key Generation Failure")]
    KeyGenFailure,
    #[error("Key Agreement Failure")]
    KeyAgreementFailure,
    #[error("Hello Failure")]
    HelloFailure,
    #[error("Invaliud Command Response")]
    InvalidCommandResponse,

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
    #[error(transparent)]
    JoinFailure(#[from] tokio::task::JoinError),
    #[error(transparent)]
    SendBoolError(#[from] tokio::sync::watch::error::SendError<bool>),
    #[error(transparent)]
    WhoAmIError(#[from] whoami::Error),
    #[error(transparent)]
    CrytoError(#[from] orion::errors::UnknownCryptoError),
}
