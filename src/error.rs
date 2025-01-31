use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DefaultError>;

#[derive(Error, Debug)]
pub enum DefaultError {
    #[error("Error: `{0}`")]
    ErrorMessage(String),

    #[error("Hex Error: `{0}`")]
    FromHexError(#[from] hex::FromHexError),

    #[error("String UTF8 error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("io error: `{0}`")]
    IoError(#[from] io::Error),

    #[error("unknown error")]
    Unknown,
}
