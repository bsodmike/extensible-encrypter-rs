use crate::error::DefaultError;

// NOTE: this needs to be migrated, that's a lot of unnecessary code due to a speedrun
pub(crate) mod aes;

pub mod decrypter;
pub mod encrypter;
pub mod error;
pub mod hasher;

pub mod prelude {
    use crate::decrypter::*;
}
