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
