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
    ) -> Result<String, DefaultError>;
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
    ) -> Result<String, DefaultError> {
        match kind {
            HasherKind::PBKDF2 => {
                tracing::info!("PBKDF2");

                let buf = [0u8; pbkdf2::KEY_BUFF_SIZE];
                let mut buf_boxed = Box::new(buf);

                let hasher = &mut pbkdf2::HashProvider::<pbkdf2::PrfHasher>::new(&mut buf_boxed);
                let hash = hasher.pbkdf2_gen(password, salt, &rounds).unwrap();

                Ok(hex::encode(hash))
            }
            HasherKind::Argon2 => {
                tracing::info!("Argon2");

                Ok("".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HasherKind;
    use super::*;
    use tracing_test::traced_test;

    const HASH_ROUNDS: u32 = 2;

    #[traced_test]
    #[test]
    fn get_hasher_with_impl_trait() {
        let pbkdf2 = PBKDF2HashProvide {};

        fn get_hasher(hasher: impl HashProvider<Kind = HasherKind>) -> String {
            hasher
                .hash("password", "salt", &HASH_ROUNDS, HasherKind::PBKDF2)
                .unwrap()
        }

        let hash = get_hasher(pbkdf2);
        assert_ne!(hash, "".to_string());
    }
}
