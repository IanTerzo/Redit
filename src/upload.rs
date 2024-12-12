use crate::types::{ClientConnectionInfo, UploaderInfo};
use rand::prelude::*;

use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::str;

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
pub fn host(uploader_info: UploaderInfo, password: Option<String>) {
    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    println!("Listening for incoming packets on 6969");

    let mut buf = [0; 1024];
    loop {
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        println!("Received packet from: {}", src);

        let packet_data = &buf[..amt];
        println!("{}", str::from_utf8(packet_data).unwrap());

        // Check if the host got a message.
        let message: Option<&str> = match str::from_utf8(packet_data) {
            Ok(message) => Some(message),
            Err(_) => None,
        };

        if let Some(message) = message {
            if message == "c" {
                // respond with the uploader info. (includes the public key)
                let serialized = bincode::serialize(&uploader_info).unwrap();
                socket
                    .send_to(&serialized, src)
                    .expect("Couldn't send data");

                continue;
            }
        }

        if !uploader_info.public {
            // password sharing, then give encrypted files
            let res = bincode::deserialize::<ClientConnectionInfo>(&buf[..amt]).unwrap();

            println!("{:#?}", res.password); // Debug

            // decrypt res.password
            if res.password
                == password
                    .clone()
                    .expect("You must provide a password if the files aren't public!")
            {

                // give the files encrypted with the password
            }
        } else {
            // give the files unecncrypted
        }
    }
}
