use base64::{engine::general_purpose, Engine as _};
use extensible_encrypter::prelude::*;

#[macro_use]
extern crate prettytable;
use prettytable::Table;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = encrypter::Aes256GcmSivEncryptProvide;

    let plaintext = "secret nuke codes go inside the football";
    let nonce_rounds = 100_000; // this is quicker for testing
    let mut cipher_config = encrypter::Aes256GcmSivConfig::default();
    cipher_config.set_hash_rounds(nonce_rounds);

    let result = encrypter::Encrypter::encrypt(
        plaintext,
        "password",
        provider,
        encrypter::Cipher::Aes256GcmSiv(cipher_config),
    );
    let cipher_b64 = general_purpose::STANDARD.encode(result.ciphertext);
    let nonce_b64 = general_purpose::STANDARD.encode(result.nonce);
    let salt_b64 = general_purpose::STANDARD.encode(result.salt);

    let mut table = Table::new();
    table.add_row(row!["Cipher", cipher_b64]);
    table.add_row(row![
        format!("Nonce (IV)\nRounds {}", nonce_rounds),
        nonce_b64
    ]);
    table.add_row(row!["Salt", salt_b64]);

    // Print the table to stdout
    table.printstd();

    Ok(())
}
