use crate::error::DefaultError;
use pbkdf2::Hashable;

pub mod pbkdf2;

pub enum HasherKind {
    PBKDF2,
    Argon2,
}

pub struct PBKDF2Hasher {}
pub struct Argon2Hasher {}

pub trait HashProvider {
    type Kind;

    fn hash(
        &self,
        password: &str,
        salt: &str,
        rounds: &u32,
        kind: Self::Kind,
    ) -> Result<HasherResult, DefaultError>;
}

pub struct PBKDF2HashProvide {}

impl HashProvider for PBKDF2HashProvide {
    type Kind = HasherKind;

    fn hash(
        &self,
        password: &str,
        salt: &str,
        rounds: &u32,
        kind: Self::Kind,
    ) -> Result<HasherResult, DefaultError> {
        match kind {
            HasherKind::PBKDF2 => {
                tracing::info!("PBKDF2");

                let buf = [0u8; pbkdf2::KEY_BUFF_SIZE];
                let mut buf_boxed = Box::new(buf);

                let hasher = &mut pbkdf2::HashProvider::<pbkdf2::PrfHasher>::new(&mut buf_boxed);
                let hash = hasher.pbkdf2_gen(password, salt, &rounds).unwrap();
                let hash_hex = hex::encode(hash);

                Ok(HasherResult::new(
                    hash_hex,
                    password.to_string(),
                    salt.to_string(),
                ))
            }
            HasherKind::Argon2 => {
                tracing::info!("Argon2");

                Ok(HasherResult::default())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct HasherResult {
    pub hash: String,
    pub password: String,
    pub salt: String,
}

impl HasherResult {
    pub fn new(hash: String, password: String, salt: String) -> Self {
        Self {
            hash,
            password,
            salt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HasherKind;
    use super::*;
    use tracing_test::traced_test;

    use prettytable::row;
    use prettytable::Table;

    const HASH_ROUNDS: u32 = 2;

    #[traced_test]
    #[test]
    fn pbkdf2_hasher_with_impl_trait() {
        let pbkdf2 = PBKDF2HashProvide {};
        let mut table = Table::new();

        fn get_hasher(hasher: impl HashProvider<Kind = HasherKind>) -> HasherResult {
            hasher
                .hash("password", "salt", &HASH_ROUNDS, HasherKind::PBKDF2)
                .unwrap()
        }

        let hash = get_hasher(pbkdf2);
        assert_ne!(hash.hash, "".to_string());

        let pbkdf_key_details = format!("PBKDF2 / SHA-512 with {} rounds", HASH_ROUNDS);
        table.add_row(row![pbkdf_key_details.as_str(), hash.hash]);
        table.add_row(row!["Password", hash.password]);
        table.add_row(row!["Salt", hash.salt]);

        // table.printstd();
    }
}
