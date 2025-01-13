// use super::error;
use ::aes::cipher;
use ::aes::cipher::generic_array::GenericArray;
use aes::AesCipher;
use aes_gcm_siv::AesGcmSiv;
use aes_gcm_siv::{
    aead::{AeadInPlace, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use std::fmt::Debug;
use std::io::Read;

pub struct Encrypter {
    config: EncrypterConfig,
}

pub trait Encryptable {
    fn encrypt(&mut self, input: &str) -> String;
    fn decrypt(&mut self, input: &str) -> String;
}

pub struct EncrypterConfig {
    hash_key: String,
    cipher: AesCipher,
}

impl EncrypterConfig {
    pub fn new(hash_key: String) -> Self {
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);

        // Generate nonce
        let mut bytes = hash_key.as_bytes();
        let mut short_nonce = [0u8; 12];
        bytes
            .read_exact(&mut short_nonce)
            .expect("Nonce is too short");
        let nonce: &GenericArray<u8, cipher::consts::U12> = Nonce::from_slice(&short_nonce[..]); // 96-bits; unique per message

        let cipher = AesCipher {
            cipher,
            nonce: *nonce,
        };

        Self { hash_key, cipher }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Hashable;

    #[test]
    fn create_aes_config() {
        const PBKDF_ROUNDS: u32 = 2;
        let buf = [0u8; crate::hasher::KEY_BUFF_SIZE];
        let mut buf_boxed = Box::new(buf);

        let hasher =
            &mut crate::hasher::HashProvider::<crate::hasher::PrfHasher>::new(&mut buf_boxed);
        let pbkdf_key = hasher
            .pbkdf2_gen("password", "salt", &PBKDF_ROUNDS)
            .unwrap();
        let pbkdf_key_hex = hex::encode(pbkdf_key);

        let _config = EncrypterConfig::new(pbkdf_key_hex);
    }
}

pub mod aes {
    use super::*;

    pub struct AesCipher {
        pub cipher: AesGcmSiv<::aes::Aes256>,
        pub nonce: GenericArray<u8, cipher::consts::U12>,
    }
}
