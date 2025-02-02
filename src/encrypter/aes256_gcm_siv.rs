use crate::aes::AesVecBuffer;
use crate::error::DefaultError;
use ::aes::cipher;
use ::aes::cipher::generic_array::GenericArray;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::AesGcmSiv;
use aes_gcm_siv::{
    aead::{AeadInPlace, Buffer, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use std::fmt::Debug;
use std::io::Read;
use std::marker::PhantomData;

/// Generate a random nonce (96 bits) = 12 bytes
pub fn generate_nonce(hash_key: String) -> GenericArray<u8, cipher::consts::U12> {
    let mut bytes = hash_key.as_bytes();
    let mut short_nonce = [0u8; 12];
    bytes
        .read_exact(&mut short_nonce)
        .expect("Nonce is too short");

    // 96-bits; unique per message
    let nonce: GenericArray<u8, cipher::consts::U12> = *Nonce::from_slice(&short_nonce[..]);

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_example() {}
}
