use crate::error::DefaultError;

pub(crate) mod aes;

// NOTE: These are now used as references of a crude speed run, and I'm extracting these into the
// public interface, with simplifcation as the goal.
pub(crate) mod encrypter_internal;
pub(crate) mod hasher_internal;

pub mod decrypter;
pub mod encrypter;
pub mod error;
pub mod hasher;

pub mod prelude {
    use crate::decrypter::*;
}
