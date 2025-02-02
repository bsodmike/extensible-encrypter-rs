use crate::error::DefaultError;
use crate::hasher::{HashProvider, HasherKind};

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

                let hash = crate::hasher::Hasher::hash(
                    password,
                    "salt",
                    &HASH_ROUNDS,
                    hash_provider,
                    HasherKind::PBKDF2,
                );
                assert_ne!(hash.hash, "".to_string());

                Ok(EncryptionResult {
                    ciphertext: "".to_string(),
                    key: "".to_string(),
                    nonce: "".to_string(),
                    salt: "".to_string(),
                })
            }
        }
    }
}

pub struct EncryptionResult {
    pub ciphertext: String,
    pub key: String,
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
