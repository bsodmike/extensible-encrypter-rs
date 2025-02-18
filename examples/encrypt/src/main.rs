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

    let mut table = Table::new();
    table.add_row(row!["Cipher", result.ciphertext_b64()]);
    table.add_row(row![
        format!("Nonce (IV)\nRounds {}", nonce_rounds),
        result.nonce_b64()
    ]);
    table.add_row(row!["Salt", result.salt_b64()]);

    // Print the table to stdout
    table.printstd();

    Ok(())
}
