use crate::types::{ClientConnectionInfo, UploaderInfo};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write};
use crate::types;
use crate::encryption;

pub fn upload_files() {
    //Nils tar det
}

pub fn host(uploader_info: UploaderInfo, password: Option<String>, private_key: RsaPrivateKey) {
    let listener = TcpListener::bind("0.0.0.0:6969").unwrap();
    println!("Hosting...");

    let mut salt_mappings: std::collections::HashMap<SocketAddr, String> = Default::default();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0; 1024];
                let amt = stream.read(&mut buf).unwrap();

                let packet_data = &buf[..amt];
                let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
                    Ok(data) => data,
                    Err(e) => {
                        println!("Received undeserializable packet: {:?}", e);
                        continue;
                    }
                };

                println!("{:?}", packet);

                match packet {
                    types::ReditPacket::RequestUploaderInfo(_) => {
                        // respond with the uploader info. (includes the public key)
                        let src = stream.peer_addr().unwrap();
                        let salt = match salt_mappings.get(&src) {
                            Some(salt) => salt.to_owned(),
                            None => {
                                let salt = encryption::generate_salt();
                                salt_mappings.insert(src, salt.clone());
                                salt
                            }
                        };

                        let mut local_uploader_info = uploader_info.clone();
                        local_uploader_info.hashed_connection_salt = Some(salt);

                        let serialized = bincode::serialize(&local_uploader_info).unwrap();
                        stream.write_all(&serialized).expect("Couldn't send data");

                        continue;
                    }
                    types::ReditPacket::ClientConnectionInfo(res) => {
                        let decypted_key = private_key
                            .decrypt(Pkcs1v15Encrypt, &res.encrypted_password)
                            .expect("Failed to decrypt password");

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
            Err(e) => {
                println!("Failed to accept connection: {}", e);
            }
        }
    }
}