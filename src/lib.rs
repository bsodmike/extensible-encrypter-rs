use crate::aes::AesEncrypter;
use crate::error::DefaultError;
use crate::hasher::Hashable;
use aes_gcm_siv::AesGcmSiv;
use prelude::AesEncrypt;
use tracing::trace;

pub mod aes;
pub mod encrypter;
pub mod error;
pub mod hasher;
pub mod prelude {
    pub use crate::aes::AesEncrypt;
}
