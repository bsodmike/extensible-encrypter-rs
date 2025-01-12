use super::error;
use super::PrfHasher;
use super::KEY_BUFF_SIZE;
use hmac::{digest::core_api::CoreWrapper, EagerHash, Hmac, HmacCore, KeyInit};
use pbkdf2::pbkdf2;
use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug)]
pub(crate) struct Encrypter<'a, S> {
    key: &'a mut Box<[u8; KEY_BUFF_SIZE]>,
    _phat: PhantomData<&'a S>,
}

impl<'a, S> Encrypter<'a, S> {
    pub fn new(buf: &'a mut Box<[u8; KEY_BUFF_SIZE]>) -> Self {
        Self {
            key: buf,
            _phat: PhantomData,
        }
    }
}

pub trait Encryptable {
    type KeyBuf;

    fn pbkdf_key(&mut self, password: &str, salt: &str, rounds: &u32) -> Self::KeyBuf;
}

impl<T> Encryptable for Encrypter<'_, T> {
    type KeyBuf = [u8; KEY_BUFF_SIZE];

    fn pbkdf_key(&mut self, password: &str, salt: &str, rounds: &u32) -> Self::KeyBuf {
        process_pbkdf_key::<PrfHasher>(&mut self.key, password, salt, rounds).unwrap();

        **self.key
    }
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
