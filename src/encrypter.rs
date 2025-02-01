use crate::aes::AesVecBuffer;
use crate::error::DefaultError;
use ::aes::cipher;
use ::aes::cipher::generic_array::GenericArray;
use aes256_gcm_siv::{Decryptable, Decrypter as AesDecrypter};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::AesGcmSiv;
use aes_gcm_siv::{
    aead::{AeadInPlace, Buffer, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use std::fmt::Debug;
use std::io::Read;
use std::marker::PhantomData;

pub mod aes256_gcm_siv;

pub enum DecrypterKind {
    Aes256GcmSiv,
}

pub trait DecryptProvider {
    type Kind;

    fn decrypt(
        &self,
        input: &mut AesDecrypter,
        kind: Self::Kind,
    ) -> Result<DecryptionResult, DefaultError>;
}

pub struct PBKDF2DecryptProvide {}

impl DecryptProvider for PBKDF2DecryptProvide {
    type Kind = DecrypterKind;

    fn decrypt(
        &self,
        input: &mut AesDecrypter,
        kind: Self::Kind,
    ) -> Result<DecryptionResult, DefaultError> {
        match kind {
            DecrypterKind::Aes256GcmSiv => {
                tracing::info!("Aes256GcmSiv");

                let plaintext = input.decrypt()?;

                Ok(DecryptionResult::new(plaintext))
            }
        }
    }
}

pub struct DecryptionResult {
    plaintext: String,
}

impl DecryptionResult {
    pub fn new(plaintext: String) -> Self {
        Self { plaintext }
    }

    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }
}

pub struct Decrypter {}

impl Decrypter {
    pub fn decrypt<DK>(
        // FIXME: input should use impl Trait instead of concrete type
        input: &mut AesDecrypter,
        provider: impl DecryptProvider<Kind = DK>,
        kind: DK,
    ) -> DecryptionResult {
        let result = provider.decrypt(input, kind).unwrap();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes256_gcm_siv::DecrypterBuilder;
    use tracing_test::traced_test;

    use prettytable::row;
    use prettytable::Table;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_with_impl_trait() {
        // Convert hex strings to bytes
        let key = "7be4595c40e86cfa210dcb689fccb39aa9674596f367610074f8ad27c00532f3";
        let nonce = "623432663335626432396163";
        let ciphertext = "3a065c2810ef1ae018223be7ace9337da1657c9fb4490660903074861536c8b7ca2085a65b2abcb3f8ec94f2985e2dfeb06b0f3f66d6751a";

        let input = &mut aes256_gcm_siv::DecrypterBuilder::new()
            .key(key)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build();

        let decrypter = PBKDF2DecryptProvide {};
        let result = Decrypter::decrypt(input, decrypter, DecrypterKind::Aes256GcmSiv);

        assert_eq!(result.plaintext, "secret nuke codes go inside the football");
    }
}
