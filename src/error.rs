use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DefaultError>;

#[derive(Error, Debug)]
pub enum DefaultError {
    #[error("Error: `{0}`")]
    ErrorMessage(String),
    #[error("io error: `{0}`")]
    IoError(#[from] io::Error),
    #[error("unknown error")]
    Unknown,
}
