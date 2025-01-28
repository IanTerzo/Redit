use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use base64::{
	alphabet,
	engine::{self, general_purpose},
	Engine as _,
};

use crate::words::WORDS;
use itertools::Itertools;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

// Create cryptography engine
const ENGINE: engine::GeneralPurpose =
engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);

pub fn generate_private_key() -> RsaPrivateKey {
	let mut rng = rand::thread_rng();
	RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key")
}

pub fn generate_public_key(key: RsaPrivateKey) -> RsaPublicKey {
	RsaPublicKey::from(&key)
}

// Turn the public_key to a string for sharing
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

// Function to turn the password into a hash, necessary for Aes256Gcm encryption
pub fn derive_key(passphrase: &str) -> [u8; 32] {
	// Argon2 requires a salt, but in our case we can only provide a fixed salt
	// Even with a fixed salt argon is better than other hashing alghorithms that don't take a salt
	let salt = SaltString::from_b64("OWQzczU4ZzEwZGQ3NXM1YTVmbzFqazI").unwrap(); // random, base64 encoded, pre generated string
	let argon2 = Argon2::new(
		argon2::Algorithm::Argon2id,
		argon2::Version::V0x13,
		Params::new(65536, 4, 1, Some(32)).unwrap(),
	);

	let password_hash = argon2.hash_password(passphrase.as_bytes(), &salt).unwrap();
	let key = password_hash.hash.unwrap();

	key.as_bytes().try_into().expect("Invalid key length")
}

// Functions to encrypt and decrypt data using a key, (for file sharing)

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

mod tests {
	use super::*;

	#[allow(dead_code)]
	fn encrypt(data: Vec<u8>, passphrase: String) -> String {
		let fernet = fernet::Fernet::new(&key_from_passphrase(passphrase)).unwrap();
		return fernet.encrypt(&data);
	}

	#[allow(dead_code)]
	fn decrypt(data: &str, passphrase: String) -> Result<Vec<u8>, fernet::DecryptionError> {
		let fernet = fernet::Fernet::new(&key_from_passphrase(passphrase)).unwrap();
		return fernet.decrypt(&data);
	}

	#[allow(dead_code)]
	fn generate_passphrase(len: u8) -> String {
		let mut passphrase: String = "".to_string();
		let mut rand = [0u8; 511];
		getrandom::fill(&mut rand).expect("Unable to initialize passphrase backing array");
		let seed: Vec<u16> = rand
			.into_iter()
			.tuples()
			.map(|(m, n)| ((m as u16) * 256 + n as u16) & 1023)
			.collect::<Vec<_>>();
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
		let encoded = ENGINE.encode(&hashed.to_string()[..32]);
		return encoded;
	}

	#[test]
	fn passphrase_range() {
		for i in 0..255 {
			generate_passphrase(i);
		}
	}

	#[test]
	fn round_trip() {
		for _ in 1..1024 {
			let passphrase = generate_passphrase(4);
			let payload = generate_passphrase(255).as_bytes().to_vec();
			let encoded = encrypt(payload.clone(), passphrase.clone());
			let decoded = decrypt(&encoded, passphrase).unwrap();
			assert_eq!(payload, decoded);
		}
	}

	#[test]
	fn test_derive_key() {
		let passphrase = "my_secure_passphrase";
		//TODO: upadte
		let expected_key: [u8; 32] = [253, 233, 239, 148, 133, 120, 140, 215, 64, 76, 154, 25, 230, 68, 113, 252, 222, 74, 244, 76, 219, 189, 251, 69, 223, 4, 177, 49, 109, 163, 49, 95];

		let derived_key = derive_key(passphrase);

		assert_eq!(
			derived_key, expected_key,
			"The derived key should match the expected key."
		);
	}

	#[test]
	fn test_encrypt_decrypt_with_passphrase() {
		let passphrase = "my_secure_passphrase";
		let data = b"Hello, this is a test message!";

		let key = derive_key(passphrase);

		let encrypted_data = encrypt_with_passphrase(data, &key);

		let decrypted_data = decrypt_with_passphrase(&encrypted_data, &key);

		assert_eq!(
			data.to_vec(),
			decrypted_data,
			"Decrypted data should match the original data."
		);
	}
}

