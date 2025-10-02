use crate::error::{self, DefaultError};
use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::password_hash::SaltString;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::io::Write;

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
/// Default configuration for Aes256GcmSiv
impl Default for Aes256GcmSivConfig {
    fn default() -> Self {
        Self {
            hash_rounds: 600_000,
            hash_algorithm: super::hasher::pbkdf2::Algorithm::Pbkdf2Sha512,
        }
    }
}

pub enum Cipher {
    Aes256GcmSiv(Aes256GcmSivConfig),
}

pub trait EncryptProvider {
    type Cipher;

    fn encrypt(
        &self,
        plaintext: &str,
        password: &str,
        ek: Self::Cipher,
    ) -> Result<EncryptionResult, DefaultError>;
}

pub struct Aes256GcmSivEncryptProvide;

impl EncryptProvider for Aes256GcmSivEncryptProvide {
    type Cipher = Cipher;

    fn encrypt(
        &self,
        plaintext: &str,
        password: &str,
        encryption_kind: Self::Cipher,
    ) -> Result<EncryptionResult, DefaultError> {
        match encryption_kind {
            Cipher::Aes256GcmSiv(config) => {
                tracing::info!("Encrypting: Aes256GcmSiv");

                // A salt for PBKDF2 (should be unique per encryption)
                let mut salt_result = Vec::new();
                let mut rng = ChaCha12Rng::from_os_rng();
                let salt = SaltString::from_rng(&mut rng);
                let salt_str = salt.as_str().as_bytes();
                salt_result
                    .write_all(salt_str)
                    .expect("Failed copying salt into buffer");

                // Derive a 32-byte key using PBKDF2 with SHA-512
                let hasher = super::hasher::pbkdf2::Hasher::hash(
                    password,
                    &config.hash_rounds,
                    config.hash_algorithm,
                    Some(salt),
                )?;

                // Convert the key to a fixed-size array
                let key = hex::decode(hasher.hash().as_str()).unwrap();
                let key_array: [u8; 32] = key.try_into().unwrap();

                // Initialize the AES-GCM-SIV cipher
                let cipher = Aes256GcmSiv::new_from_slice(&key_array).unwrap();

                // Generate a random nonce (96 bits)
                let mut nonce = [0u8; 12]; // 96 bits = 12 bytes
                let mut rng = ChaCha12Rng::from_os_rng();
                rng.fill_bytes(&mut nonce);
                let mut nonce_result = Vec::new();
                nonce_result
                    .write_all(&nonce)
                    .expect("Failed copying nonce into buffer");

                let nonce = Nonce::try_from(&nonce[..]).map_err(|_err| {
                    DefaultError::ErrorMessage("Failed parsing nonce from slice".to_string())
                })?;

                // Encrypt the message
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .expect("Encryption failed"); // Output the results
                tracing::debug!("Nonce: {:?}", nonce);
                tracing::debug!("Ciphertext: {:?}", ciphertext);

                Ok(EncryptionResult {
                    ciphertext,
                    nonce: nonce_result,
                    salt: salt_result,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>, // iv?
    pub salt: Vec<u8>,
}

impl EncryptionResult {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn ciphertext_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.ciphertext())
    }

    pub fn nonce_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.nonce())
    }

    pub fn salt_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.salt())
    }
}

pub struct Encrypter;

impl Encrypter {
    ///  Uses impl trait to accept any type that implements EncryptProvider to perform the encryption
    pub fn encrypt<C>(
        plaintext: &str,
        password: &str,
        provider: impl EncryptProvider<Cipher = C>,
        cipher: C,
    ) -> error::Result<EncryptionResult> {
        provider.encrypt(plaintext, password, cipher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_e2e() {
        let provider = Aes256GcmSivEncryptProvide;

        let plaintext = "secret nuke codes go inside the football";
        let mut cipher_config = Aes256GcmSivConfig::default();
        cipher_config.set_hash_rounds(20); // low number of rounds for testing

        let result = Encrypter::encrypt(
            plaintext,
            "password",
            provider,
            Cipher::Aes256GcmSiv(cipher_config),
        );
        let result = result.expect("Encryption failed");
        tracing::info!("Result: {:?}", result);

        let input = &mut crate::decrypter::builder::DecrypterBuilder::new()
            .salt(result.salt)
            .nonce(result.nonce)
            .ciphertext(result.ciphertext)
            .build();

        let provider = crate::decrypter::PBKDF2DecryptProvide;
        let mut cipher_config = crate::decrypter::Aes256GcmSivConfig::default();
        cipher_config.set_hash_rounds(20); // low number of rounds for testing

        let result = crate::decrypter::Decrypter::decrypt(
            input,
            provider,
            crate::decrypter::DecrypterCipher::Aes256GcmSiv(cipher_config),
        );
        let result = result.expect("Decryption failed");

        assert_eq!(
            result.plaintext(),
            "secret nuke codes go inside the football"
        );
    }
}
