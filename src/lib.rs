use crate::aes::AesEncrypter;
use crate::error::DefaultError;
use crate::hasher::Hashable;
use aes_gcm_siv::AesGcmSiv;
use prelude::AesEncrypt;
use tracing::trace;

pub mod encrypter;
pub mod error;
pub mod hasher;
pub mod prelude {
    pub use crate::aes::AesEncrypt;
}

pub(crate) mod aes {
    use aes::cipher;
    use aes::cipher::generic_array::GenericArray;
    use aes_gcm_siv::aead::Buffer;
    use aes_gcm_siv::AesGcmSiv;
    use aes_gcm_siv::{
        aead::{AeadInPlace, KeyInit, OsRng},
        Aes256GcmSiv, Nonce,
    };
    use std::io::Read;
    use std::marker::PhantomData;

    #[derive(Debug, Clone)]
    // A is a temporary generic, for future use.
    pub struct AesVecBuffer<'a, A> {
        inner: Vec<u8>,
        _life: PhantomData<&'a A>,
    }

    impl<'a, A> AesVecBuffer<'a, A> {
        pub fn inner(&mut self) -> &mut Vec<u8> {
            &mut self.inner
        }

        pub fn from_vec(vec: Vec<u8>) -> Self {
            Self {
                inner: vec,
                _life: PhantomData,
            }
        }
    }

    impl<'a, A> aes_gcm_siv::aead::Buffer for AesVecBuffer<'a, A> {
        fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm_siv::aead::Result<()> {
            Ok(self.inner.extend(other))
        }

        fn truncate(&mut self, len: usize) {
            self.inner.truncate(len)
        }

        fn len(&self) -> usize {
            self.as_ref().len()
        }

        fn is_empty(&self) -> bool {
            self.as_ref().is_empty()
        }
    }

    impl<'a, A> AsRef<[u8]> for AesVecBuffer<'a, A> {
        fn as_ref(&self) -> &[u8] {
            &self.inner
        }
    }

    impl<'a, A> AsMut<[u8]> for AesVecBuffer<'a, A> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.inner[..]
        }
    }

    impl<'a, A, const N: usize> PartialEq<[u8; N]> for AesVecBuffer<'a, A> {
        fn eq(&self, other: &[u8; N]) -> bool {
            self.inner.eq(other)
        }

        fn ne(&self, other: &[u8; N]) -> bool {
            !self.eq(other)
        }
    }

    pub struct AesEncrypter<'a> {
        cipher: AesGcmSiv<aes::Aes256>,
        nonce: String,
        buffer: AesVecBuffer<'a, ()>,
    }

    impl<'a> AesEncrypter<'a> {
        pub fn new(nonce: String, plaintext: &'a str) -> Self {
            let key = Aes256GcmSiv::generate_key(&mut OsRng);
            let cipher = Aes256GcmSiv::new(&key);

            // Note: buffer needs 16-bytes overhead for auth tag tag
            let inner: Vec<u8> = Vec::new();
            let mut buffer = AesVecBuffer::<()> {
                inner: inner.to_vec(),
                _life: PhantomData,
            };
            buffer.extend_from_slice(plaintext.as_bytes()).unwrap();

            Self {
                cipher,
                nonce,
                buffer,
            }
        }
        pub fn decryptable(
            encrypted_hex: String,
            cipher: AesGcmSiv<::aes::Aes256>,
            nonce: String,
        ) -> Self {
            let decoded_hex = hex::decode(encrypted_hex).unwrap();
            let buf = AesVecBuffer::<()>::from_vec(decoded_hex);

            Self {
                cipher,
                nonce,
                buffer: buf,
            }
        }

        pub fn buffer(&mut self) -> &mut AesVecBuffer<'a, ()> {
            &mut self.buffer
        }

        /// This replaces the underlying buffer and is a distructive operation.  Use with care.
        pub fn _replace_buffer(&mut self, buffer: AesVecBuffer<'a, ()>) {
            self.buffer = buffer;
        }

        pub fn export_cipher_nonce(&self) -> (AesGcmSiv<aes::Aes256>, String) {
            (self.cipher.clone(), self.nonce.clone())
        }

        pub fn encrypt_in_place(&mut self) -> crate::error::Result<()> {
            let mut bytes = self.nonce.as_bytes();
            let mut short_nonce = [0u8; 12];
            bytes.read_exact(&mut short_nonce)?;
            // trace!("Len: {:?}", short_nonce.len());
            let nonce: &GenericArray<u8, cipher::consts::U12> = Nonce::from_slice(&short_nonce[..]); // 96-bits; unique per message

            // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
            Ok(self
                .cipher
                .encrypt_in_place(nonce, b"", &mut self.buffer)
                .map_err(|err| -> crate::error::Result<()> {
                    let err = format!(
                        "[{}] Failed to encrypt due to {}.",
                        env!("CARGO_CRATE_NAME"),
                        err.to_string(),
                    );
                    Err(crate::DefaultError::ErrorMessage(err))
                })
                .expect("Encrypt cipher in place"))
        }

        pub fn decrypt_in_place(&mut self) -> crate::error::Result<()> {
            let mut bytes = self.nonce.as_bytes();
            let mut short_nonce = [0u8; 12];
            bytes.read_exact(&mut short_nonce)?;

            let nonce: &GenericArray<u8, cipher::consts::U12> = Nonce::from_slice(&short_nonce[..]); // 96-bits; unique per message

            // Decrypt `buffer` in-place
            Ok(self
                .cipher
                .decrypt_in_place(nonce, b"", &mut self.buffer)
                .map_err(|err| -> crate::error::Result<()> {
                    let err = format!(
                        "[{}] Failed to decrypt due to {}. ",
                        env!("CARGO_CRATE_NAME"),
                        err.to_string(),
                    );
                    Err(crate::DefaultError::ErrorMessage(err))
                })
                .unwrap())
        }
    }

    pub trait AesEncrypt {
        fn buffer(&mut self) -> Vec<u8>;
        fn decrypt_in_place(&mut self) -> crate::error::Result<()>;
        fn encrypt_in_place(&mut self) -> crate::error::Result<()>;
        fn export_cipher_nonce(&self) -> (AesGcmSiv<::aes::Aes256>, String);
    }

    impl<'a> AesEncrypt for AesEncrypter<'a> {
        fn buffer(&mut self) -> Vec<u8> {
            let buf = AesEncrypter::buffer(self);

            buf.inner().to_vec()
        }

        fn decrypt_in_place(&mut self) -> crate::error::Result<()> {
            AesEncrypter::decrypt_in_place(self)
        }

        fn encrypt_in_place(&mut self) -> crate::error::Result<()> {
            AesEncrypter::encrypt_in_place(self)
        }

        fn export_cipher_nonce(&self) -> (AesGcmSiv<::aes::Aes256>, String) {
            AesEncrypter::export_cipher_nonce(self)
        }
    }
}

pub struct EncrypterState<'a>(&'a str, &'a str);

impl<'a> EncrypterState<'a> {
    pub fn new(password: &'a str, salt: &'a str) -> Self {
        Self(password, salt)
    }
}

pub struct Encrypter {}

impl Encrypter {
    pub fn get_encrypter<'a>(
        state: EncrypterState<'a>,
        plaintext: &'a str,
        rounds: &'a u32,
    ) -> impl AesEncrypt + use<'a> {
        let buf = [0u8; 20];
        let mut buf_boxed = Box::new(buf);

        let hasher = &mut crate::hasher::HashProvider::new(
            &mut buf_boxed,
            crate::hasher::PrfHasher::default(),
        );
        let pbkdf_key = hasher
            .pbkdf2_gen(
                state.0,
                state.1,
                rounds,
                crate::hasher::PrfHasher::default(),
            )
            .unwrap();

        let pbkdf_key_hex = hex::encode(pbkdf_key);
        trace!("Key: {}", &pbkdf_key_hex);

        AesEncrypter::new(pbkdf_key_hex.clone(), plaintext)
    }

    pub fn get_decrypter<'a>(
        encrypted_hex: String,
        cipher: AesGcmSiv<::aes::Aes256>,
        nonce: String,
    ) -> impl AesEncrypt + use<'a> {
        AesEncrypter::decryptable(encrypted_hex, cipher, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn get_pbkdf_key() {
        const PBKDF_ROUNDS: u32 = 2;
        let buf = [0u8; crate::hasher::KEY_BUFF_SIZE];
        let mut buf_boxed = Box::new(buf);

        let hasher = &mut crate::hasher::HashProvider::new(
            &mut buf_boxed,
            crate::hasher::PrfHasher::default(),
        );
        let pbkdf_key = hasher
            .pbkdf2_gen(
                "password",
                "salt",
                &PBKDF_ROUNDS,
                crate::hasher::PrfHasher::default(),
            )
            .unwrap();

        let _pbkdf_key_hex = hex::encode(pbkdf_key);

        // NOTE: Compute hex string for the number of rounds provided above; this affects the pbkdf key
        // and the test will fail if the number of rounds are changed.
        // let hex_string = hex::encode(pbkdf_key1);

        assert_eq!(
            &pbkdf_key,
            &hex!("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e")
        );
    }
}

#[cfg(test)]
mod extended_tests {
    const TESTS_PBKDF_ROUNDS: u32 = 2;

    mod aes {
        use super::TESTS_PBKDF_ROUNDS;
        use crate::aes::AesEncrypt;
        use crate::Encrypter;
        use crate::EncrypterState;

        #[test]
        fn test_encrypt_and_decrypt() {
            let mut enc = Encrypter::get_encrypter(
                EncrypterState::new("password", "salt"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );

            // `buffer` now contains the message ciphertext
            enc.encrypt_in_place().unwrap();
            // println!("Encrypted cipher text: {}", hex::encode(&enc.buffer()));
            assert_ne!(enc.buffer(), b"plaintext message");

            enc.decrypt_in_place().unwrap();
            // let m = enc.buffer().inner();
            // println!(
            //     "Decrypted plaintext: {}",
            //     String::from_utf8(m.to_vec()).unwrap()
            // );
            assert_eq!(enc.buffer(), b"plaintext message");
        }

        #[test]
        fn test_decrypt_with_imported_cipher_nonce() {
            let mut enc = Encrypter::get_encrypter(
                EncrypterState::new("password", "salt"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );
            enc.encrypt_in_place().unwrap();
            let encrypted_buf = hex::encode(&enc.buffer());
            let (cipher, nonce) = enc.export_cipher_nonce();

            let mut enc2 = Encrypter::get_decrypter(encrypted_buf, cipher, nonce);
            enc2.decrypt_in_place().unwrap();

            assert_eq!(enc2.buffer(), b"plaintext message");
        }

        #[should_panic(expected = "[pbkdf_encrypt_core] Failed to decrypt due to aead::Error.")]
        #[test]
        fn test_decrypt_invalid_cipher() {
            let mut enc = Encrypter::get_encrypter(
                EncrypterState::new("password", "salt"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );
            enc.encrypt_in_place().unwrap();
            let encrypted_buf = hex::encode(&enc.buffer());
            let (cipher, _nonce) = enc.export_cipher_nonce();

            // Trigger failure with invalid nonce
            let short_nonce = [0u8; 12];
            let invalid_nonce: String = short_nonce.iter().map(|b| format!("{:02x}", b)).collect();
            let mut decrypter = Encrypter::get_decrypter(encrypted_buf, cipher, invalid_nonce);

            decrypter.decrypt_in_place().unwrap();

            assert_eq!(decrypter.buffer(), b"plaintext message");
        }
    }
}
