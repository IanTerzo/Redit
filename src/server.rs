use crate::types::{ClientConnectionInfo, UploaderInfo};
use rand::prelude::*;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::{clone, str};
use crate::types;

// Move to encrypt?

pub fn gen_private_key() -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key")
}

pub fn gen_public_key(key: RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey::from(&key)
}

pub fn upload_files() {
    //Nils tar det
}

pub fn host(uploader_info: UploaderInfo, password: Option<String>, private_key: RsaPrivateKey) {
    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    println!("Hosting...");

    let mut buf = [0; 1024];
    loop {
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        let packet_data = &buf[..amt];
        let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Received undeserializable packet: {:?}", e);
                continue
            }
        };

        println!("{:?}", packet);

        match packet {
            types::ReditPacket::RequestUploaderInfo(_) => {
                // respond with the uploader info. (includes the public key)
                let serialized = bincode::serialize(&uploader_info).unwrap();
                socket
                    .send_to(&serialized, src)
                    .expect("Couldn't send data");

                continue;
            }
            types::ReditPacket::ClientConnectionInfo(res) => {
                let decypted_key = private_key
                    .decrypt(Pkcs1v15Encrypt, &res.encrypted_password)
                    .expect("Failed to decrypt passowrd");

                let decrypted_password =
                    String::from_utf8(decypted_key).expect("failed to create password string");

                if let Some(password_ref) = password.as_ref() {
                    if decrypted_password == *password_ref {
                        println!("Correct Password");
                        // Do stuff, upload_files()
                    } else {
                        println!("Wrong password");
                        // Nej
                    }
                } else {
                    panic!("You must provide a password");
                }
            }
            unexpected => {
                println!("Received unexpected packet {:?}", unexpected);
            }
        }
    }
}

