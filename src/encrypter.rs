use crate::error::DefaultError;

pub mod aes256_gcm_siv;

pub enum EncrypterKind {
    Aes256GcmSiv,
}

pub trait EncryptProvider {
    type Kind;

    fn encrypt(&self, kind: Self::Kind) -> Result<EncryptionResult, DefaultError>;
}

pub struct Aes256GcmSivEncryptProvide {}

impl EncryptProvider for Aes256GcmSivEncryptProvide {
    type Kind = EncrypterKind;

    fn encrypt(&self, kind: Self::Kind) -> Result<EncryptionResult, DefaultError> {
        match kind {
            EncrypterKind::Aes256GcmSiv => {
                tracing::info!("Aes256GcmSiv");

                Ok(EncryptionResult {
                    ciphertext: "".to_string(),
                    key: "".to_string(),
                    nonce: "".to_string(),
                    salt: "".to_string(),
                })
            }
        }
    }
}

pub struct EncryptionResult {
    pub ciphertext: String,
    pub key: String,
    pub nonce: String, // iv?
    pub salt: String,
}

pub struct Encrypter {}

impl Encrypter {
    ///  Uses impl trait to accept any type that implements EncryptProvider to perform the encryption
    pub fn encrypt<EK>(provider: impl EncryptProvider<Kind = EK>, kind: EK) -> EncryptionResult {
        let result = provider.encrypt(kind).unwrap();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    use prettytable::row;
    use prettytable::Table;

    #[traced_test]
    #[test]
    fn aes256_gcm_siv_with_impl_trait() {
        let provider = Aes256GcmSivEncryptProvide {};

        let result = Encrypter::encrypt(provider, EncrypterKind::Aes256GcmSiv);
    }
}
