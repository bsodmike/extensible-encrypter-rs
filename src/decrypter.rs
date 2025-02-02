use super::hasher::{HashProvider, HasherKind};
use crate::aes::AesVecBuffer;
use crate::error::DefaultError;
use ::aes::cipher;
use ::aes::cipher::generic_array::GenericArray;
use aes256_gcm_siv::{Decryptable, Decrypter as DecryptData, DecrypterPayload};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::AesGcmSiv;
use aes_gcm_siv::{
    aead::{AeadInPlace, Buffer, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
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
        input: &mut DecryptData,
        kind: Self::Kind,
    ) -> Result<DecryptionResult, DefaultError>;
}

pub struct PBKDF2DecryptProvide {}

impl DecryptProvider for PBKDF2DecryptProvide {
    type Kind = DecrypterKind;

    fn decrypt(
        &self,
        input: &mut DecryptData,
        kind: Self::Kind,
    ) -> Result<DecryptionResult, DefaultError> {
        match kind {
            DecrypterKind::Aes256GcmSiv => {
                tracing::info!("Aes256GcmSiv");

                // FIXME: old approach
                // let plaintext = input.decrypt()?;

                const HASH_ROUNDS: u32 = 20;

                // Convert hex strings to bytes
                let salt_hex = input.salt();
                let salt_decoded = hex::decode(salt_hex).unwrap();
                let salt = SaltString::new(&String::from_utf8(salt_decoded).unwrap()).unwrap();
                println!("Salt: {:?}", salt);

                let decoded_nonce = hex::decode(input.nonce()).unwrap();
                let nonce = Nonce::from_slice(decoded_nonce.as_ref());
                let ciphertext = hex::decode(input.ciphertext()).unwrap();

                let hash_provider = super::hasher::PBKDF2HashProvide {};
                // let hasher = crate::hasher::Hasher::hash(
                //     "password",
                //     &HASH_ROUNDS,
                //     hash_provider,
                //     HasherKind::PBKDF2,
                // );
                // assert_ne!(hasher.hash, "".to_string());

                // Derive a 32-byte key using PBKDF2 with SHA-512 and 20 rounds
                let hasher = super::hasher::pbkdf2::Hasher::hash(
                    "password",
                    &HASH_ROUNDS,
                    super::hasher::pbkdf2::Algorithm::Pbkdf2Sha256,
                    Some(salt),
                )
                .unwrap();

                // Convert the key to a fixed-size array
                let key = hex::decode(hasher.hash().as_str()).unwrap();
                let decryption_key_array: [u8; 32] = key.try_into().unwrap();

                // Initialize the AES-GCM-SIV cipher for decryption
                let decryption_cipher =
                    Aes256GcmSiv::new_from_slice(&decryption_key_array).unwrap();

                // Decrypt the ciphertext
                let decrypted_message = match decryption_cipher.decrypt(nonce, ciphertext.as_ref())
                {
                    Ok(message) => message,
                    Err(err) => {
                        return Err(DefaultError::ErrorMessage(format!(
                            "Failed to decrypt due to {}.",
                            err.to_string()
                        )))
                    }
                };

                // Convert the decrypted message to a string
                let decrypted_message = String::from_utf8(decrypted_message).unwrap();

                // Output the decryption result
                println!("Decrypted message: {}", decrypted_message);

                Ok(DecryptionResult::new(decrypted_message))
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
    ///  Uses impl trait to accept any type that implements DecrypterPayload and converts it to DecryptData, passing this to the provider to perform the decryption
    pub fn decrypt<DK>(
        mut input: impl DecrypterPayload,
        provider: impl DecryptProvider<Kind = DK>,
        kind: DK,
    ) -> DecryptionResult {
        let input = &mut DecryptData::from_payload(&mut input);
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
    // FIXME: the provided key, nonce, and ciphertext are incorrect
    fn aes256_gcm_siv_with_impl_trait() {
        // Convert hex strings to bytes
        // let key = "7be4595c40e86cfa210dcb689fccb39aa9674596f367610074f8ad27c00532f3";
        // let nonce = "623432663335626432396163";
        // let ciphertext = "3a065c2810ef1ae018223be7ace9337da1657c9fb4490660903074861536c8b7ca2085a65b2abcb3f8ec94f2985e2dfeb06b0f3f66d6751a";

        let ciphertext = "e7550de30e76d4546082d17e762032b6dfcc650e2d4072cc6e52bf";
        let nonce = "66444888d4f0e1a69f387dfe";
        let salt = "30656e4d7a36716534452b414837384d4a4946635967";

        let input = &mut aes256_gcm_siv::DecrypterBuilder::new()
            .salt(salt)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build();

        let provider = PBKDF2DecryptProvide {};
        let result = Decrypter::decrypt(input, provider, DecrypterKind::Aes256GcmSiv);

        assert_eq!(result.plaintext, "secret nuke codes go inside the football");
    }
}
