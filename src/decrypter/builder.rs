pub struct Decrypter {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Decrypter {
    pub fn from_payload(payload: &impl DecrypterPayload) -> Self {
        Self {
            salt: payload.salt().clone(),
            nonce: payload.nonce().clone(),
            ciphertext: payload.ciphertext().clone(),
        }
    }
}

pub trait DecrypterPayload {
    fn salt(&self) -> &Vec<u8>;
    fn nonce(&self) -> &Vec<u8>;
    fn ciphertext(&self) -> &Vec<u8>;
}

impl DecrypterPayload for &mut Decrypter {
    fn salt(&self) -> &Vec<u8> {
        &self.salt
    }

    fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }

    fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

pub struct DecrypterBuilder {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl DecrypterBuilder {
    pub fn new() -> Self {
        Self {
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
        }
    }

    pub fn salt(mut self, key: Vec<u8>) -> Self {
        self.salt = key;
        self
    }

    pub fn nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.ciphertext = ciphertext;
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
