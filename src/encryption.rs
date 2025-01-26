use crate::words::WORDS;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, Params, PasswordHasher,
};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use itertools::Itertools;
use rand::Rng;

use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

const ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);

pub fn generate_private_key() -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key")
}

pub fn generate_public_key(key: RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(&key)
}

pub fn public_key_to_string(ref key: RsaPublicKey) -> String {
    let data: Vec<u8> = key.to_pkcs1_der().unwrap().into_vec();
    ENGINE.encode(data)
}

pub fn public_key_from_string(key: String) -> Option<RsaPublicKey> {
    let data = match ENGINE.decode(key) {
        Ok(data) => data,
        Err(_) => return None,
    };
    let key = match RsaPublicKey::from_pkcs1_der(&data) {
        Ok(data) => data,
        Err(_) => return None,
    };
    Some(key)
}

pub fn generate_salt() -> String {
    let mut rand = [0u8; 511];
    getrandom::fill(&mut rand).expect("Unable to initialize passphrase backing array");
    ENGINE.encode(rand)
}

pub fn derive_key(passphrase: &str) -> [u8; 32] {
    // Argon2 requires a salt, but in our case we can only provide a fixed salt.
    // Even with a fixed salt argon is better than other hashing alhgorithms that dont take a salt
    let salt = SaltString::from_b64("OWQzczU4ZzEwZGQ3NXM1YTVmbzFqazI").unwrap(); // random pre generated string
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(65536, 4, 1, Some(32)).unwrap(),
    );

    let password_hash = argon2.hash_password(passphrase.as_bytes(), &salt).unwrap();
    let key = password_hash.hash.unwrap();

    key.as_bytes().try_into().expect("Invalid key length")
}

pub fn encrypt_with_passphrase(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    cipher.encrypt(nonce, data).expect("encryption failure!")
}

pub fn decrypt_with_passphrase(encrypted_data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let decrypted = cipher
        .decrypt(nonce, encrypted_data)
        .expect("decryption failure!");

    decrypted
}
