use crate::error;
use aes_gcm_siv::aead::OsRng;
use pbkdf2::{
    password_hash::{Ident, PasswordHasher, SaltString},
    Pbkdf2,
};

pub enum Algorithm {
    Pbkdf2Sha256,
    Pbkdf2Sha512,
}

pub struct Hasher;

impl Hasher {
    ///   Hash a password using PBKDF2 with SHA-256 or SHA-512
    ///  
    ///   # Arguments
    ///  
    ///   * `password` - The password to hash
    ///   * `rounds` - The number of rounds to hash the password
    ///   * `algorithm` - The algorithm to use for hashing
    ///   * `override_salt` - Salt is optional, if not provided a random salt will be generated, this
    ///   should be the default usage.  This is included for testing purposes.
    ///
    pub fn hash(
        password: &str,
        rounds: &u32,
        algorithm: Algorithm,
        override_salt: Option<SaltString>,
    ) -> error::Result<HasherResult>
where {
        // A salt for PBKDF2 (should be unique per encryption)
        let mut salt = SaltString::generate(&mut OsRng);
        if let Some(value) = override_salt {
            salt = SaltString::from_b64(value.as_str()).expect("salt is base64 encoded");
        }

        // Derive a 32-byte key using PBKDF2 with SHA-512
        let algo = match algorithm {
            Algorithm::Pbkdf2Sha256 => Ident::new("pbkdf2-sha256").expect("use SHA-256"),
            Algorithm::Pbkdf2Sha512 => Ident::new("pbkdf2-sha512").expect("use SHA-512"),
        };
        let key = Pbkdf2
            .hash_password_customized(
                password.as_bytes(),
                Some(algo),
                None,
                pbkdf2::Params {
                    rounds: *rounds,
                    output_length: 32,
                },
                &salt,
            )
            .expect("32-byte key generated");

        // Convert the key to a fixed-size array
        let key_hash = key.hash.unwrap();
        let key_bytes = key_hash.as_bytes();
        let key_array: [u8; 32] = key_bytes.try_into().unwrap();
        let hash_hex = hex::encode(key_array);

        let result = HasherResult::new(hash_hex, salt.to_string());

        Ok(result)
    }
}

pub struct HasherResult {
    hash: String,
    salt: String,
}

impl HasherResult {
    pub fn new(hash: String, salt: String) -> Self {
        Self { hash, salt }
    }

    pub fn hash(&self) -> String {
        self.hash.to_string()
    }

    pub fn salt(&self) -> String {
        self.salt.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::pbkdf2::Algorithm;
    use pbkdf2::password_hash::SaltString;

    use super::Hasher;

    #[test]
    fn assert_32_byte_key_length() {
        const PBKDF_ROUNDS: u32 = 2;

        // NOTE: uses a static salt value for testing purposes
        let result = Hasher::hash(
            "password",
            &PBKDF_ROUNDS,
            Algorithm::Pbkdf2Sha512,
            Some(SaltString::from_b64("salt").unwrap()),
        )
        .unwrap();

        let decoded_hash = hex::decode(&result.hash).unwrap();
        assert_eq!(decoded_hash.len(), 32_usize);
        assert_eq!(
            &result.hash,
            &"8eb89352a0724cd4dfd8230e895c0ed0182574c37a1173b40489366cd0a78723".to_string()
        );
        assert_eq!(result.salt, "salt".to_string());
    }
}
