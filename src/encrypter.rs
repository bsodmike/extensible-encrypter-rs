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
                let hash = crate::hasher::Hasher::hash(
                    password,
                    "salt",
                    &HASH_ROUNDS,
                    hash_provider,
                    HasherKind::PBKDF2,
                );
                assert_ne!(hash.hash, "".to_string());
                let nonce = aes256_gcm_siv::generate_nonce(hash.hash);

                // A salt for PBKDF2 (should be unique per encryption)
                let salt = SaltString::generate(&mut OsRng);

                // Derive a 32-byte key using PBKDF2 with SHA-512 and 20 rounds
                let key = Pbkdf2
                    .hash_password_customized(
                        password.as_bytes(),
                        None,
                        None,
                        pbkdf2::Params {
                            rounds: 20,
                            output_length: 32,
                        },
                        &salt,
                    )
                    .unwrap();

                // Convert the key to a fixed-size array
                let key_hash = key.hash.unwrap();
                let key_bytes = key_hash.as_bytes();
                let key_array: [u8; 32] = key_bytes.try_into().unwrap();

                // Initialize the AES-GCM-SIV cipher
                let cipher = Aes256GcmSiv::new_from_slice(&key_array).unwrap();

                // Encrypt the message
                let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap(); // Output the results
                println!("Salt: {}", salt);
                println!("Nonce: {:?}", nonce);
                println!("Ciphertext: {:?}", ciphertext);

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

    const HASH_ROUNDS: u32 = 2;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_with_impl_trait() {
        let hash_provider = PBKDF2HashProvide {};
        // let hash = Hasher::hash(
        //     "password",
        //     "salt",
        //     &HASH_ROUNDS,
        //     hash_provider,
        //     HasherKind::PBKDF2,
        // );
        // assert_ne!(hash.hash, "".to_string());

        let provider = Aes256GcmSivEncryptProvide {};

        let result = Encrypter::encrypt(
            "password",
            hash_provider,
            provider,
            EncrypterKind::Aes256GcmSiv,
            HasherKind::PBKDF2,
        );
    }
}
