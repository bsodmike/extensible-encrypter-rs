//! # Usage
//!
//! This is the current E2E test that performs encryption and decryption using the `extensible_encrypter` crate.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use extensible_encrypter::prelude::*;
//!
//! let plaintext = "secret nuke codes go inside the football";
//!
//! let provider = encrypter::Aes256GcmSivEncryptProvide;
//! let mut cipher_config = encrypter::Aes256GcmSivConfig::default();
//! cipher_config.set_hash_rounds(20); // low number of rounds for testing
//!
//! let result = encrypter::Encrypter::encrypt(
//!     plaintext,
//!     "password",
//!     provider,
//!     encrypter::Cipher::Aes256GcmSiv(cipher_config),
//! );
//! let result = result.expect("Encryption failed");
//! tracing::info!("Result: {:?}", result);
//!
//! let input = &mut DecrypterBuilder::new()
//!     .salt(result.salt)
//!     .nonce(result.nonce)
//!     .ciphertext(result.ciphertext)
//!     .build();
//!
//! let provider = decrypter::PBKDF2DecryptProvide;
//! let mut cipher_config = decrypter::Aes256GcmSivConfig::default();
//! cipher_config.set_hash_rounds(20); // low number of rounds for testing
//!
//! let result = decrypter::Decrypter::decrypt(
//!     input,
//!     provider,
//!     decrypter::DecrypterCipher::Aes256GcmSiv(cipher_config),
//! );
//!
//! assert_eq!(
//!     result?.plaintext(),
//!     "secret nuke codes go inside the football"
//! );
//!
//! # Ok(())
//! # }
//! ```

pub mod decrypter;
pub mod encrypter;
pub mod error;
pub mod hasher;

#[allow(unused_imports)]
pub mod prelude {
    pub use crate::decrypter::{
        self, builder,
        builder::{Decrypter as DecryptData, DecrypterBuilder, DecrypterPayload},
    };
    pub use crate::encrypter;
}
