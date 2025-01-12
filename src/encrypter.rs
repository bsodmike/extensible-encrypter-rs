use super::*;

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
