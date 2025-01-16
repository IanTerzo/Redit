use crate::encryption;
use crate::types;
use crate::types::Payload;
use crate::types::{ClientConnectionInfo, UploaderInfo};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::net::{SocketAddr, UdpSocket};

use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tar::Builder;

fn read_file(file_path: String) -> Vec<u8> {
    // Specify the file path

    // Read the file contents
    let contents = fs::read(file_path).unwrap();

    contents
}

fn read_dir(file_path: String, tar_path: String) -> Vec<u8> {
    let tar_gz = File::create(tar_path.clone()).unwrap();

    // Wrap it with a GzEncoder for gzip compression
    let enc = GzEncoder::new(tar_gz, Compression::default());

    let mut tar = Builder::new(enc);

    tar.append_dir_all(".", file_path).unwrap();

    tar.finish().unwrap();

    let contents = fs::read(tar_path).unwrap();

    contents
}

pub fn upload_files() {
    //Nils tar.gz det

    let path_str = "./testdir"; // Replace with your path

    let path = Path::new(path_str.clone());

    let mut content: Vec<u8> = vec![];

    if path.is_dir() {
        let tar_path = format!(
            "./tars/{}.tar.gz",
            path.file_stem().unwrap().to_string_lossy()
        );
        content = read_dir(path_str.to_string().clone(), tar_path);
    } else if path.is_file() {
        content = read_file(path_str.to_string().clone());
    }

    println!("{:#?}", content);
}

pub fn host(
    uploader_info: UploaderInfo,
    files_path: String,
    password: Option<String>,
    private_key: RsaPrivateKey,
) {
    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    println!("Hosting...");

    let mut buf = [0; 1024];

    let mut salt_mappings: std::collections::HashMap<SocketAddr, String> = Default::default();

    loop {
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

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
                socket
                    .send_to(&serialized, src)
                    .expect("Couldn't send data");

                continue;
            }
            types::ReditPacket::RequestPayload(res) => {
                let decypted_key = private_key
                    .decrypt(Pkcs1v15Encrypt, &res.hashed_password)
                    .expect("Failed to decrypt passowrd");

                let decrypted_password =
                    String::from_utf8(decypted_key).expect("failed to create password string");

                if let Some(password_ref) = password.as_ref() {
                    if decrypted_password == *password_ref {
                        println!("Correct Password");

                        let response_payload = Payload {
                            success: true,
                            payload_count: 12,
                            data: Vec::new(),
                        };

                        let serialized = bincode::serialize(&response_payload).unwrap();
                        socket
                            .send_to(&serialized, src)
                            .expect("Couldn't send data");
                    } else {
                        println!("Wrong password");

                        let response_payload = Payload {
                            success: false,
                            payload_count: 0,
                            data: Vec::new(),
                        };

                        let serialized = bincode::serialize(&response_payload).unwrap();
                        socket
                            .send_to(&serialized, src)
                            .expect("Couldn't send data");
                    }
                } else {
                    panic!("You must provide a password");
                }
            }
            types::ReditPacket::ClientConnectionInfo(res) => {}
            unexpected => {
                println!("Received unexpected packet {:?}", unexpected);
            }
        }
    }
}
