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

pub struct Decrypter {
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl Decrypter {
    pub fn from_payload(payload: &impl DecrypterPayload) -> Self {
        Self {
            salt: payload.salt().to_string(),
            nonce: payload.nonce().to_string(),
            ciphertext: payload.ciphertext().to_string(),
        }
    }
}

pub trait DecrypterPayload {
    fn salt(&self) -> &str;
    fn nonce(&self) -> &str;
    fn ciphertext(&self) -> &str;
}

impl DecrypterPayload for &mut Decrypter {
    fn salt(&self) -> &str {
        &self.salt
    }

    fn nonce(&self) -> &str {
        &self.nonce
    }

    fn ciphertext(&self) -> &str {
        &self.ciphertext
    }
}

pub struct DecrypterBuilder {
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl DecrypterBuilder {
    pub fn new() -> Self {
        Self {
            salt: String::new(),
            nonce: String::new(),
            ciphertext: String::new(),
        }
    }

    pub fn salt(mut self, key: &str) -> Self {
        self.salt = key.to_string();
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
            salt: self.salt,
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
        let salt = hex::decode(&self.salt).unwrap();
        let binding = hex::decode(&self.nonce).unwrap();
        let nonce = Nonce::from_slice(binding.as_ref());
        let ciphertext = hex::decode(&self.ciphertext).unwrap();

        // Initialize AES-GCM-SIV
        let cipher = Aes256GcmSiv::new_from_slice(&salt).expect("Invalid key length");

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
        let salt = "7be4595c40e86cfa210dcb689fccb39aa9674596f367610074f8ad27c00532f3";
        let nonce = "623432663335626432396163";
        let ciphertext = "3a065c2810ef1ae018223be7ace9337da1657c9fb4490660903074861536c8b7ca2085a65b2abcb3f8ec94f2985e2dfeb06b0f3f66d6751a";

        let mut decrypter = DecrypterBuilder::new()
            .salt(salt)
            .nonce(nonce)
            .ciphertext(ciphertext)
            .build();

        let plaintext = decrypter.decrypt().unwrap();
        assert_eq!(plaintext, "secret nuke codes go inside the football");
    }
}
