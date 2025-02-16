use crate::error::DefaultError;
use crate::prelude::*;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{aead::KeyInit, Aes256GcmSiv, Nonce};
use pbkdf2::password_hash::SaltString;

pub mod builder;

pub struct Aes256GcmSivConfig {
    hash_rounds: u32,
    hash_algorithm: super::hasher::pbkdf2::Algorithm,
}

#[allow(dead_code)]
impl Aes256GcmSivConfig {
    pub fn set_hash_algorithm(&mut self, hash_algorithm: super::hasher::pbkdf2::Algorithm) {
        self.hash_algorithm = hash_algorithm;
    }

    pub fn set_hash_rounds(&mut self, hash_rounds: u32) {
        self.hash_rounds = hash_rounds;
    }
}

/// Default configuration for Aes256GcmSiv with 20 rounds of PBKDF2 SHA-512
impl Default for Aes256GcmSivConfig {
    fn default() -> Self {
        Self {
            hash_rounds: 600_000,
            hash_algorithm: super::hasher::pbkdf2::Algorithm::Pbkdf2Sha512,
        }
    }
}

pub enum DecrypterCipher {
    Aes256GcmSiv(Aes256GcmSivConfig),
}

pub trait DecryptProvider {
    type Cipher;

    fn decrypt(
        &self,
        input: &mut DecryptData,
        cipher: Self::Cipher,
    ) -> Result<DecryptionResult, DefaultError>;
}

pub struct PBKDF2DecryptProvide;

impl DecryptProvider for PBKDF2DecryptProvide {
    type Cipher = DecrypterCipher;

    fn decrypt(
        &self,
        input: &mut DecryptData,
        cipher: Self::Cipher,
    ) -> Result<DecryptionResult, DefaultError> {
        match cipher {
            DecrypterCipher::Aes256GcmSiv(config) => {
                tracing::info!("Decrypting: Aes256GcmSiv");

                // Convert hex strings to bytes
                let salt = String::from_utf8(input.salt().clone())?;
                let salt = SaltString::from_b64(salt.as_str()).expect("salt is base64 encoded");

                let nonce = Nonce::from_slice(input.nonce());
                let ciphertext = input.ciphertext();

                // Derive a 32-byte key using PBKDF2 with SHA-512 and 20 rounds
                let hasher = super::hasher::pbkdf2::Hasher::hash(
                    "password",
                    &config.hash_rounds,
                    config.hash_algorithm,
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

pub struct Decrypter;

impl Decrypter {
    ///  Uses impl trait to accept any type that implements DecrypterPayload and converts it to DecryptData, passing this to the provider to perform the decryption
    pub fn decrypt<CipherType>(
        mut input: impl DecrypterPayload,
        provider: impl DecryptProvider<Cipher = CipherType>,
        cipher: CipherType,
    ) -> DecryptionResult {
        let input = &mut DecryptData::from_payload(&mut input);
        let result = provider.decrypt(input, cipher).unwrap();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_pbkdf2_sha256() {
        let ciphertext = "e7550de30e76d4546082d17e762032b6dfcc650e2d4072cc6e52bf";
        let nonce = "66444888d4f0e1a69f387dfe";
        let salt = "30656e4d7a36716534452b414837384d4a4946635967";

        let ciphertext = hex::decode(ciphertext).unwrap();
        let nonce = hex::decode(nonce).unwrap();
        let salt = hex::decode(salt).unwrap();

        let input = &mut builder::DecrypterBuilder::new()
            .salt(salt)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build();

        let provider = PBKDF2DecryptProvide {};

        let mut cipher_config = Aes256GcmSivConfig::default();
        cipher_config.set_hash_algorithm(crate::hasher::pbkdf2::Algorithm::Pbkdf2Sha256);
        cipher_config.set_hash_rounds(20); // low number of rounds for testing

        let result = Decrypter::decrypt(
            input,
            provider,
            DecrypterCipher::Aes256GcmSiv(cipher_config),
        );

        assert_eq!(result.plaintext, "hello there");
    }
}
