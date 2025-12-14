use thiserror::Error;

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
    //
    // 2d party
    //
}
impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}
