use crate::error::DefaultError;

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
        rounds: &u32,
        kind: Self::Kind,
    ) -> Result<HasherResult, DefaultError> {
        match kind {
            HasherKind::PBKDF2 => {
                tracing::info!("PBKDF2");

                let hash =
                    pbkdf2::Hasher::hash(password, &rounds, pbkdf2::Algorithm::Pbkdf2Sha512, None)
                        .unwrap();

                Ok(HasherResult::new(
                    hash.hash(),
                    password.to_string(),
                    hash.salt(),
                ))
            }
            HasherKind::Argon2 => {
                tracing::info!("Argon2");

                Ok(HasherResult::default())
            }
        }
    }
}

pub struct Hasher {}
impl Hasher {
    pub fn hash<HK>(
        password: &str,
        rounds: &u32,
        provider: impl HashProvider<Kind = HK>,
        kind: HK,
    ) -> HasherResult {
        provider.hash(password, rounds, kind).unwrap()
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
        let mut table = Table::new();

        let pbkdf2 = PBKDF2HashProvide {};
        let hash = Hasher::hash("password", &HASH_ROUNDS, pbkdf2, HasherKind::PBKDF2);
        assert_ne!(hash.hash, "".to_string());

        let pbkdf_key_details = format!("PBKDF2 / SHA-512 with {} rounds", HASH_ROUNDS);
        table.add_row(row![pbkdf_key_details.as_str(), hash.hash]);
        table.add_row(row!["Password", hash.password]);
        table.add_row(row!["Salt", hash.salt]);

        // table.printstd();
    }
}
