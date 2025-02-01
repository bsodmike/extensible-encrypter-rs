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

pub struct Decrypter {
    key: String,
    nonce: String,
    ciphertext: String,
}

pub struct DecrypterBuilder {
    key: String,
    nonce: String,
    ciphertext: String,
}

impl DecrypterBuilder {
    pub fn new() -> Self {
        Self {
            key: String::new(),
            nonce: String::new(),
            ciphertext: String::new(),
        }
    }

    pub fn key(mut self, key: &str) -> Self {
        self.key = key.to_string();
        self
    }

    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = nonce.to_string();
        self
    }

    pub fn ciphertext(mut self, ciphertext: &str) -> Self {
        self.ciphertext = ciphertext.to_string();
        self
    }

    pub fn build(self) -> Decrypter {
        Decrypter {
            key: self.key,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
        }
    }
}

pub trait Decryptable {
    fn decrypt(&mut self) -> Result<String, DefaultError>;
}

impl Decryptable for Decrypter {
    fn decrypt(&mut self) -> Result<String, DefaultError> {
        // Convert hex strings to bytes
        let key = hex::decode(&self.key).unwrap();
        let binding = hex::decode(&self.nonce).unwrap();
        let nonce = Nonce::from_slice(binding.as_ref());
        let ciphertext = hex::decode(&self.ciphertext).unwrap();

        // Initialize AES-GCM-SIV
        let cipher = Aes256GcmSiv::new_from_slice(&key).expect("Invalid key length");

        // Decrypt the ciphertext
        match cipher.decrypt(nonce, ciphertext.as_ref()) {
            Ok(plaintext) => {
                println!("Decryption successful!");
                println!(
                    "Decrypted plaintext: {:?}",
                    String::from_utf8(plaintext.clone()).unwrap()
                );
                Ok(String::from_utf8(plaintext).unwrap())
            }
            Err(e) => {
                println!("Decryption failed: {:?}", e);
                Err(DefaultError::ErrorMessage("Decryption failed".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_example() {
        // Convert hex strings to bytes
        let key = "7be4595c40e86cfa210dcb689fccb39aa9674596f367610074f8ad27c00532f3";
        let nonce = "623432663335626432396163";
        let ciphertext = "3a065c2810ef1ae018223be7ace9337da1657c9fb4490660903074861536c8b7ca2085a65b2abcb3f8ec94f2985e2dfeb06b0f3f66d6751a";

        let mut decrypter = DecrypterBuilder::new()
            .key(key)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build();

        let plaintext = decrypter.decrypt().unwrap();
        assert_eq!(plaintext, "secret nuke codes go inside the football");
    }
}
