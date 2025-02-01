use super::error;
use crate::aes::AesVecBuffer;
use ::aes::cipher;
use ::aes::cipher::generic_array::GenericArray;
use aes::AesCipher;
use aes_gcm_siv::AesGcmSiv;
use aes_gcm_siv::{
    aead::{AeadInPlace, Buffer, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use std::fmt::Debug;
use std::io::Read;
use std::marker::PhantomData;

pub struct Encrypter<EncryptionProvider> {
    config: EncrypterConfig,
    _provider: PhantomData<EncryptionProvider>,
}

impl<EP> Encrypter<EP> {
    pub fn new(config: EncrypterConfig) -> Self {
        Self {
            _provider: PhantomData,
            config,
        }
    }
}

pub trait Encryptable<EncryptionProvider> {
    fn encrypt(&mut self, input: &str, provider: &mut EncryptionProvider) -> String;
    fn decrypt(
        &mut self,
        ciphertext: &str,
        provider: &mut EncryptionProvider,
    ) -> error::Result<String>;
}

impl<EncryptionProvider> Encryptable<EncryptionProvider> for Encrypter<EncryptionProvider>
where
    EncryptionProvider: AesEncryptionProviderTrait,
{
    fn encrypt(&mut self, input: &str, provider: &mut EncryptionProvider) -> String {
        let config = &self.config;
        let cipher = &config.cipher;
        let plain_text = input;

        provider.perform_encryption(plain_text, cipher)
    }
    fn decrypt(
        &mut self,
        ciphertext: &str,
        provider: &mut EncryptionProvider,
    ) -> error::Result<String> {
        let config = &self.config;
        let cipher = &config.cipher;

        provider.perform_decryption(ciphertext, cipher)
    }
}

pub trait AesEncryptionProviderTrait {
    fn perform_encryption(&mut self, plain_text: &str, cipher: &AesCipher) -> String;
    fn perform_decryption(&mut self, ciphertext: &str, cipher: &AesCipher)
        -> error::Result<String>;
}

pub struct AesEncryptionProvide<'a> {
    pub buffer: crate::aes::AesVecBuffer<'a, ()>,
}

impl<'a> AesEncryptionProvide<'a> {
    fn new() -> Self {
        Self {
            buffer: AesVecBuffer::<()>::new(),
        }
    }

    /// Hex encoded ciphertext
    fn ciphertext_hex(&mut self) -> String {
        let text = hex::encode(self.buffer.inner().to_vec());

        text
    }

    /// Decoded plaintext
    fn plain_text(&mut self) -> error::Result<String> {
        let text = self.buffer.inner().to_vec();

        Ok(String::from_utf8(text)?)
    }
}

impl<'a> AesEncryptionProviderTrait for AesEncryptionProvide<'a> {
    fn perform_encryption(&mut self, plain_text: &str, cipher: &AesCipher) -> String {
        let (cipher, nonce) = (&cipher.cipher, &cipher.nonce);

        // Note: buffer needs 16-bytes overhead for auth tag tag
        self.buffer
            .extend_from_slice(plain_text.as_bytes())
            .unwrap();

        cipher
            .encrypt_in_place(nonce, b"", &mut self.buffer)
            .map_err(|err| -> crate::error::Result<()> {
                let err = format!(
                    "[{}] Failed to encrypt due to {}.",
                    env!("CARGO_CRATE_NAME"),
                    err.to_string(),
                );
                Err(crate::DefaultError::ErrorMessage(err))
            })
            .expect("Encrypt cipher in place");

        self.ciphertext_hex()
    }

    fn perform_decryption(
        &mut self,
        ciphertext: &str,
        cipher: &AesCipher,
    ) -> error::Result<String> {
        let (cipher, nonce) = (&cipher.cipher, &cipher.nonce);

        let decoded = hex::decode(ciphertext)?;
        let buffer_data = aes::AesVecBuffer::<()>::from_vec(decoded);
        self.buffer = buffer_data;

        cipher
            .decrypt_in_place(nonce, b"", &mut self.buffer)
            .map_err(|err| -> crate::error::Result<()> {
                let err = format!(
                    "[{}] Failed to decrypt due to {}.",
                    env!("CARGO_CRATE_NAME"),
                    err.to_string(),
                );
                Err(crate::DefaultError::ErrorMessage(err))
            })
            .expect("Decrypt ciphertext in place");

        Ok(self.plain_text()?)
    }
}

#[cfg(test)]
mod encryptable {
    use super::Encryptable;
    use super::EncrypterConfig;
    use crate::encrypter_internal::AesEncryptionProvide;
    use crate::encrypter_internal::OsRng;
    use crate::hasher::Hashable;
    use aes_gcm_siv::Aes256GcmSiv;
    use aes_gcm_siv::KeyInit;
    use hex_literal::hex;

    use prettytable::row;
    use prettytable::{Cell, Row, Table};

    #[test]
    fn test_encrypter() {
        const PBKDF_ROUNDS: u32 = 2;
        let buf = [0u8; crate::hasher::KEY_BUFF_SIZE];
        let mut buf_boxed = Box::new(buf);

        let hasher =
            &mut crate::hasher::HashProvider::<crate::hasher::PrfHasher>::new(&mut buf_boxed);
        let pbkdf_key = hasher
            .pbkdf2_gen("password", "salt", &PBKDF_ROUNDS)
            .unwrap();
        let pbkdf_key_hex = hex::encode(pbkdf_key);

        let config = EncrypterConfig::new(pbkdf_key_hex);

        // Create Encrypter
        let mut provider = AesEncryptionProvide::new();
        let mut enc = super::Encrypter::<AesEncryptionProvide>::new(config);
        let r = enc.encrypt("secret nuke codes", &mut provider);

        assert_ne!(r, "")
    }

    #[test]
    fn test_decryption() {
        let mut table = Table::new();

        const PBKDF_ROUNDS: u32 = 20;
        let buf = [0u8; crate::hasher::KEY_BUFF_SIZE];
        let mut buf_boxed = Box::new(buf);
        let input_plaintext = "secret nuke codes go inside the football";

        let salt_rng = Aes256GcmSiv::generate_key(&mut OsRng);
        let salt = hex::encode(salt_rng);

        let hasher =
            &mut crate::hasher::HashProvider::<crate::hasher::PrfHasher>::new(&mut buf_boxed);
        let pbkdf_key = hasher
            .pbkdf2_gen("password", salt.as_str(), &PBKDF_ROUNDS)
            .unwrap();
        let pbkdf_key_hex = hex::encode(pbkdf_key);

        let config = EncrypterConfig::new(pbkdf_key_hex.to_string());

        // Create Encrypter
        let mut provider = AesEncryptionProvide::new();
        let mut enc = super::Encrypter::<AesEncryptionProvide>::new(config.clone());
        let ciphertext = enc.encrypt(&input_plaintext, &mut provider);

        let nonce = hex::encode(config.cipher.nonce);
        let pbkdf_key_details = format!("PBKDF2 / SHA-512 with {} rounds", PBKDF_ROUNDS);

        table.add_row(row![pbkdf_key_details.as_str(), pbkdf_key_hex]);
        table.add_row(row!["Salt", salt]);
        table.add_row(row!["AES Key", config.aes_key]);
        table.add_row(row!["Nonce", nonce]);
        table.add_row(row!["Ciphertext", ciphertext]);

        // Perform decrypt
        let key = config.aes_key.clone();
        let config = EncrypterConfig::init(pbkdf_key_hex, key);

        let mut provider = AesEncryptionProvide::new();
        let mut enc = super::Encrypter::<AesEncryptionProvide>::new(config);
        let r = enc.decrypt(&ciphertext, &mut provider).unwrap();

        assert_eq!(r, String::from(input_plaintext));

        // Print the table to stdout
        table.add_row(row!["Decrypted", r]);
        table.printstd();
    }
}

#[derive(Clone)]
pub struct EncrypterConfig {
    pub hash_key: String,
    pub cipher: AesCipher,
    pub aes_key: String,
}

impl EncrypterConfig {
    pub fn new(hash_key: String) -> Self {
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);

        // Generate nonce
        let nonce = generate_nonce(hash_key.clone());

        let cipher = AesCipher { cipher, nonce };
        let key_hex = hex::encode(key);

        Self {
            hash_key,
            cipher,
            aes_key: key_hex,
        }
    }

    pub fn init(hash_key: String, aes_key: String) -> Self {
        let decoded = hex::decode(aes_key).unwrap();
        let key = GenericArray::from_slice(&decoded);
        let cipher = Aes256GcmSiv::new(key);

        // Generate nonce
        let nonce = generate_nonce(hash_key.clone());
        let cipher = AesCipher { cipher, nonce };
        let key_hex = hex::encode(key);

        Self {
            hash_key,
            cipher,
            aes_key: key_hex,
        }
    }
}

pub fn generate_nonce(hash_key: String) -> GenericArray<u8, cipher::consts::U12> {
    let mut bytes = hash_key.as_bytes();
    let mut short_nonce = [0u8; 12];
    bytes
        .read_exact(&mut short_nonce)
        .expect("Nonce is too short");
    let nonce: GenericArray<u8, cipher::consts::U12> = *Nonce::from_slice(&short_nonce[..]);
    // 96-bits; unique per message

    nonce
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
    pub use super::*;

    #[derive(Clone)]
    pub struct AesCipher {
        pub cipher: AesGcmSiv<::aes::Aes256>,
        pub nonce: GenericArray<u8, cipher::consts::U12>,
    }
}
