use crate::aes::AesEncrypter;
use crate::error::DefaultError;
use encrypter::{Encryptable, Encrypter};
use hmac::{digest::core_api::CoreWrapper, EagerHash, Hmac, HmacCore, KeyInit};
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::{fmt::Debug, marker::PhantomData};
use tracing::trace;

type PrfHasher = Sha512;
const KEY_BUFF_SIZE: usize = 20;

pub mod encrypter;
pub mod error;

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

    #[derive(Debug)]
    /// FIXME: Allow swiching out the `A` array type.
    pub struct AesVecBuffer<'a, A> {
        inner: Vec<u8>,
        _life: PhantomData<&'a A>,
    }

    impl<'a, A> AesVecBuffer<'a, A> {
        pub fn inner(&mut self) -> &mut Vec<u8> {
            &mut self.inner
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

        #[allow(dead_code)]
        pub fn buffer(&mut self) -> &mut AesVecBuffer<'a, ()> {
            &mut self.buffer
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

            // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
            Ok(self
                .cipher
                .decrypt_in_place(nonce, b"", &mut self.buffer)
                .expect("Decrypt cipher in place"))
        }
    }
}

pub struct EncrypterState<'a>(&'a str, &'a str);

impl<'a> EncrypterState<'a> {
    pub fn new(password: &'a str, salt: &'a str) -> Self {
        Self(password, salt)
    }
}

pub fn get_encrypter<'a>(
    state: EncrypterState<'a>,
    plaintext: &'a str,
    rounds: &'a u32,
) -> AesEncrypter<'a> {
    // Create pbkdf
    let buf = [0u8; 20];
    let mut buf_boxed = Box::new(buf);
    let mut encrypter = Encrypter::<()>::new(&mut buf_boxed);
    let pbkdf_key = encrypter.pbkdf_key(state.0, state.1, rounds);
    let pbkdf_key_hex = hex::encode(pbkdf_key);
    trace!("Key: {}", &pbkdf_key_hex);

    AesEncrypter::new(pbkdf_key_hex.clone(), plaintext)
}

fn process_pbkdf_key<H>(
    buf_ptr: &mut Box<[u8; KEY_BUFF_SIZE]>,
    password: &str,
    salt: &str,
    pbkdf_rounds: &u32,
) -> error::Result<()>
where
    CoreWrapper<HmacCore<H>>: KeyInit,
    H: hmac::EagerHash,
    <H as EagerHash>::Core: Sync,
{
    let buf = buf_ptr.as_mut();

    pbkdf2::<Hmac<H>>(
        &password.to_string().as_bytes(),
        &salt.to_string().as_bytes(),
        *pbkdf_rounds,
        buf,
        // fmt
    )
    .expect("HMAC can be initialized with any key length");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn get_pbkdf_key() {
        const PBKDF_ROUNDS: u32 = 2;
        let buf = [0u8; KEY_BUFF_SIZE];
        let mut buf_boxed = Box::new(buf);

        let mut encrypter = Encrypter::<()>::new(&mut buf_boxed);
        let pbkdf_key1 = encrypter.pbkdf_key(
            // RA
            "password",
            "salt",
            &PBKDF_ROUNDS,
        );

        // NOTE: Compute hex string for the number of rounds provided above; this affects the pbkdf key
        // and the test will fail if the number of rounds are changed.
        // let hex_string = hex::encode(pbkdf_key1);

        assert_eq!(
            &pbkdf_key1,
            &hex!("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e")
        );
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;
    const TESTS_PBKDF_ROUNDS: u32 = 2;

    mod aes {
        use super::{get_encrypter, EncrypterState, TESTS_PBKDF_ROUNDS};
        use tracing::trace;

        #[test]
        fn test_encrypt_and_decrypt() {
            let mut enc = get_encrypter(
                EncrypterState::new("password", "salt"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );
            enc.encrypt_in_place().unwrap();
            // `buffer` now contains the message ciphertext
            trace!("Encrypted cipher text: {}", hex::encode(&enc.buffer()));
            assert_ne!(enc.buffer(), b"plaintext message");

            // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
            enc.decrypt_in_place().unwrap();
            let m = enc.buffer().inner();
            trace!(
                "Decrypted plaintext: {}",
                String::from_utf8(m.to_vec()).unwrap()
            );
            assert_eq!(enc.buffer().as_ref(), b"plaintext message");
        }

        #[should_panic]
        #[test]
        fn test_encrypt_and_decrypt_bad_salt() {
            let mut enc = get_encrypter(
                EncrypterState::new("password", "salt"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );
            enc.encrypt_in_place().unwrap();
            // `buffer` now contains the message ciphertext
            trace!("Encrypted cipher text: {}", hex::encode(&enc.buffer()));
            assert_ne!(enc.buffer(), b"plaintext message");

            let mut enc_naughty = get_encrypter(
                EncrypterState::new("password", "salt2"),
                "plaintext message",
                &TESTS_PBKDF_ROUNDS,
            );

            // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
            enc_naughty.decrypt_in_place().unwrap();
            let m = enc.buffer().inner();
            trace!(
                "Decrypted plaintext: {}",
                String::from_utf8(m.to_vec()).unwrap()
            );
            assert_eq!(enc_naughty.buffer().as_ref(), b"plaintext message");
        }
    }
}
