use crate::error::DefaultError;
use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use pbkdf2::password_hash::SaltString;

pub struct Aes256GcmSivConfig {
    hash_rounds: u32,
    hash_algorithm: super::hasher::pbkdf2::Algorithm,
}

#[allow(dead_code)]
impl Aes256GcmSivConfig {
    fn set_hash_algorithm(&mut self, hash_algorithm: super::hasher::pbkdf2::Algorithm) {
        self.hash_algorithm = hash_algorithm;
    }
}
/// Default configuration for Aes256GcmSiv
impl Default for Aes256GcmSivConfig {
    fn default() -> Self {
        Self {
            hash_rounds: 20,
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

pub struct Aes256GcmSivEncryptProvide {}

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
                let salt = SaltString::generate(&mut OsRng);
                let salt_hex = hex::encode(salt.as_ref());

                // Derive a 32-byte key using PBKDF2 with SHA-512
                let hasher = super::hasher::pbkdf2::Hasher::hash(
                    password,
                    &config.hash_rounds,
                    config.hash_algorithm,
                    Some(salt),
                )
                .unwrap();

                // Convert the key to a fixed-size array
                let key = hex::decode(hasher.hash().as_str()).unwrap();
                let key_array: [u8; 32] = key.try_into().unwrap();

                // Initialize the AES-GCM-SIV cipher
                let cipher = Aes256GcmSiv::new_from_slice(&key_array).unwrap();

                // Generate a random nonce (96 bits)
                let mut nonce = [0u8; 12]; // 96 bits = 12 bytes
                OsRng.fill_bytes(&mut nonce);
                let nonce = Nonce::from_slice(&nonce); // Convert to Nonce type

                // Encrypt the message
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap(); // Output the results
                tracing::debug!("Nonce: {:?}", nonce);
                tracing::debug!("Ciphertext: {:?}", ciphertext);

                let ciphertext_hex = hex::encode(ciphertext);
                let nonce_hex = hex::encode(nonce);

                Ok(EncryptionResult {
                    ciphertext: ciphertext_hex,
                    nonce: nonce_hex,
                    salt: salt_hex,
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct EncryptionResult {
    pub ciphertext: String,
    pub nonce: String, // iv?
    pub salt: String,
}

pub struct Encrypter {}

impl Encrypter {
    ///  Uses impl trait to accept any type that implements EncryptProvider to perform the encryption
    pub fn encrypt<C>(
        plaintext: &str,
        password: &str,
        provider: impl EncryptProvider<Cipher = C>,
        cipher: C,
    ) -> EncryptionResult {
        let result = provider.encrypt(plaintext, password, cipher).unwrap();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_e2e() {
        // let hash_provider = PBKDF2HashProvide {};
        let provider = Aes256GcmSivEncryptProvide {};

        let plaintext = "secret nuke codes go inside the football";
        let cipher_config = Aes256GcmSivConfig::default();
        let result = Encrypter::encrypt(
            plaintext,
            "password",
            provider,
            Cipher::Aes256GcmSiv(cipher_config),
        );
        tracing::info!("Result: {:?}", result);

        let input = &mut crate::decrypter::builder::DecrypterBuilder::new()
            .salt(result.salt.as_str())
            .nonce(result.nonce.as_str())
            .ciphertext(result.ciphertext.as_str())
            .build();

        let provider = crate::decrypter::PBKDF2DecryptProvide {};
        let cipher_config = crate::decrypter::Aes256GcmSivConfig::default();
        let result = crate::decrypter::Decrypter::decrypt(
            input,
            provider,
            crate::decrypter::DecrypterCipher::Aes256GcmSiv(cipher_config),
        );

        assert_eq!(
            result.plaintext(),
            "secret nuke codes go inside the football"
        );
    }
}
