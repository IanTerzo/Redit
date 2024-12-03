use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use crate::words::WORDS;
use itertools::Itertools;

const ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);

pub fn encrypt(data: Vec<u8>, passphrase: String) -> String {
    let fernet = fernet::Fernet::new(&key_from_passphrase(passphrase)).unwrap();
    return fernet.encrypt(&data);
}

pub fn decrypt(data: &str, passphrase: String) -> Result<Vec<u8>, fernet::DecryptionError> {
    let fernet = fernet::Fernet::new(&key_from_passphrase(passphrase)).unwrap();
    return fernet.decrypt(&data);
}

pub fn generate_passphrase(len: u8) -> String {
    let mut passphrase: String = "".to_string();
    let mut rand = [0u8; 255];
    getrandom::fill(&mut rand).expect("Unable to initialize passphrase backing array");
    let seed: Vec<u16> = rand.into_iter().tuples().map(|(m, n)| ((m as u16) * 256 + n as u16) & 1023).collect::<Vec<_>>();
    for i in 0..len {
        let s = seed[i as usize];
        passphrase.push_str(WORDS[s as usize]);
        if i < len - 1 {
            passphrase.push_str("-");
        }
    }
    return passphrase;
}

fn key_from_passphrase(passphrase: String) -> String {
    let hashed = blake3::hash(passphrase.as_bytes());
    let encoded = ENGINE.encode(&hashed.to_string()[.. 32]);
    return encoded;
}

