//! # Usage
//!
//! This is the current E2E test that performs encryption and decryption using the `extensible_encrypter` crate.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use aes_gcm_siv::{
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//!     Aes256GcmSiv, Nonce
//! };
//! use extensible_encrypter::decrypter;
//! use extensible_encrypter::encrypter;
//!
//! let provider = encrypter::Aes256GcmSivEncryptProvide {};
//!
//! let plaintext = "secret nuke codes go inside the football";
//! let cipher_config = encrypter::Aes256GcmSivConfig::default();
//! let result = encrypter::Encrypter::encrypt(
//!     plaintext,
//!     "password",
//!     provider,
//!     encrypter::Cipher::Aes256GcmSiv(cipher_config),
//! );
//! tracing::info!("Result: {:?}", result);
//!
//! let input = &mut extensible_encrypter::prelude::decrypter::builder::DecrypterBuilder::new()
//!     .salt(result.salt)
//!     .nonce(result.nonce)
//!     .ciphertext(result.ciphertext)
//!     .build();
//!
//! let provider = decrypter::PBKDF2DecryptProvide {};
//! let cipher_config = decrypter::Aes256GcmSivConfig::default();
//! let result = decrypter::Decrypter::decrypt(
//!     input,
//!     provider,
//!     decrypter::DecrypterCipher::Aes256GcmSiv(cipher_config),
//! );
//!
//! assert_eq!(
//!     result.plaintext(),
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
    pub use crate::decrypter;
}
