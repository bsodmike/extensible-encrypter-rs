use crate::error::DefaultError;
use crate::hasher::{HashProvider, HasherKind};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use hmac::Hmac;
use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};
use sha2::Sha512;

pub mod aes256_gcm_siv;

const HASH_ROUNDS: u32 = 20;

pub enum EncrypterKind {
    Aes256GcmSiv,
}

pub trait EncryptProvider {
    type EK;
    type HK;

    fn encrypt(
        &self,
        password: &str,
        hasher: impl HashProvider<Kind = Self::HK>,
        ek: Self::EK,
        hk: Self::HK,
    ) -> Result<EncryptionResult, DefaultError>;
}

pub struct Aes256GcmSivEncryptProvide {}

impl EncryptProvider for Aes256GcmSivEncryptProvide {
    type EK = EncrypterKind;
    type HK = HasherKind;

    fn encrypt(
        &self,
        password: &str,
        hash_provider: impl HashProvider<Kind = Self::HK>,
        encryption_kind: Self::EK,
        hasher_kind: Self::HK,
    ) -> Result<EncryptionResult, DefaultError> {
        match encryption_kind {
            EncrypterKind::Aes256GcmSiv => {
                tracing::info!("Aes256GcmSiv");

                let plaintext = "Hello, world!";

                // A salt for PBKDF2 (should be unique per encryption)
                let salt = SaltString::generate(&mut OsRng);

                // Derive a 32-byte key using PBKDF2 with SHA-512 and 20 rounds
                let hasher = crate::hasher::Hasher::hash(
                    password,
                    &HASH_ROUNDS,
                    hash_provider,
                    HasherKind::PBKDF2,
                );
                assert_ne!(hasher.hash, "".to_string());

                // Convert the key to a fixed-size array
                let key = hex::decode(hasher.hash.as_str()).unwrap();
                let key_array: [u8; 32] = key.try_into().unwrap();

                // Initialize the AES-GCM-SIV cipher
                let cipher = Aes256GcmSiv::new_from_slice(&key_array).unwrap();

                // Generate a random nonce (96 bits)
                let nonce = aes256_gcm_siv::generate_nonce(hasher.hash);

                // Encrypt the message
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap(); // Output the results
                tracing::debug!("Salt: {}", salt);
                tracing::debug!("Nonce: {:?}", nonce);
                tracing::debug!("Ciphertext: {:?}", ciphertext);

                let ciphertext_hex = hex::encode(ciphertext);
                let nonce_hex = hex::encode(nonce);
                let salt_hex = hex::encode(salt.as_ref());

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
    pub fn encrypt<EK, HK>(
        password: &str,
        hasher: impl HashProvider<Kind = HK>,
        provider: impl EncryptProvider<EK = EK, HK = HK>,
        encryption_kind: EK,
        hasher_kind: HK,
    ) -> EncryptionResult {
        let result = provider
            .encrypt(password, hasher, encryption_kind, hasher_kind)
            .unwrap();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::HashProvider;
    use crate::hasher::Hasher;
    use crate::hasher::HasherKind;
    use crate::hasher::PBKDF2HashProvide;
    use tracing_test::traced_test;

    use prettytable::row;
    use prettytable::Table;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_with_impl_trait() {
        let hash_provider = PBKDF2HashProvide {};
        let provider = Aes256GcmSivEncryptProvide {};

        let result = Encrypter::encrypt(
            "password",
            hash_provider,
            provider,
            EncrypterKind::Aes256GcmSiv,
            HasherKind::PBKDF2,
        );
        tracing::info!("Result: {:?}", result);
    }

    #[ignore]
    #[traced_test]
    #[test]
    fn aes256_gcm_siv_with_impl_trait_integration() {
        let hash_provider = PBKDF2HashProvide {};
        let provider = Aes256GcmSivEncryptProvide {};

        let result = Encrypter::encrypt(
            "password",
            hash_provider,
            provider,
            EncrypterKind::Aes256GcmSiv,
            HasherKind::PBKDF2,
        );
        tracing::info!("Result: {:?}", result);

        let input = &mut crate::decrypter::aes256_gcm_siv::DecrypterBuilder::new()
            .salt(result.salt.as_str())
            .nonce(result.nonce.as_str())
            .ciphertext(result.ciphertext.as_str())
            .build();

        let provider = crate::decrypter::PBKDF2DecryptProvide {};
        let result = crate::decrypter::Decrypter::decrypt(
            input,
            provider,
            crate::decrypter::DecrypterKind::Aes256GcmSiv,
        );

        assert_eq!(
            result.plaintext(),
            "secret nuke codes go inside the football"
        );
    }
}
