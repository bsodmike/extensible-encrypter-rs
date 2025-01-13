use crate::error;
use hmac::{digest::core_api::CoreWrapper, EagerHash, Hmac, HmacCore};
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::{fmt::Debug, marker::PhantomData};

pub type PrfHasher = Sha512;
pub const KEY_BUFF_SIZE: usize = 20;

pub trait Hashable<H> {
    type KeyBuf;

    fn pbkdf2_gen(
        &mut self,
        password: &str,
        salt: &str,
        rounds: &u32,
    ) -> error::Result<Self::KeyBuf>;
}

#[derive(Debug)]
pub struct HashProvider<'a, H> {
    _hasher: PhantomData<H>,
    key: &'a mut Box<[u8; KEY_BUFF_SIZE]>,
}

impl<'a, H> HashProvider<'a, H> {
    pub fn new(buf: &'a mut Box<[u8; KEY_BUFF_SIZE]>) -> Self {
        Self {
            _hasher: PhantomData,
            key: buf,
        }
    }
}

impl<'a, H> Hashable<H> for HashProvider<'a, H>
where
    CoreWrapper<HmacCore<H>>: hmac::KeyInit,
    H: hmac::EagerHash,
    <H as EagerHash>::Core: Sync,
{
    type KeyBuf = [u8; KEY_BUFF_SIZE];

    fn pbkdf2_gen(
        &mut self,
        password: &str,
        salt: &str,
        rounds: &u32,
    ) -> error::Result<Self::KeyBuf>
where {
        pbkdf2::<Hmac<H>>(
            &password.to_string().as_bytes(),
            &salt.to_string().as_bytes(),
            *rounds,
            self.key.as_mut(),
            // fmt
        )
        .expect("HMAC can be initialized with any key length");

        Ok(*self.key.clone())
    }
}
