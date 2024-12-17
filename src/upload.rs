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
    println!("Hosting...");

    let mut buf = [0; 1024];
    loop {
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        println!("Received packet from: {}", src);

        let packet_data = &buf[..amt];
        let (req_id, data) = packet_data.split_at(1);
        let req_id: u8 = req_id[0];

        println!("{}", req_id);

        if req_id == 1 {
            // respond with the uploader info. (includes the public key)
            let serialized = bincode::serialize(&uploader_info).unwrap();
            socket
                .send_to(&serialized, src)
                .expect("Couldn't send data");

            continue;
        } else if req_id == 2 {
            // password sharing, then give encrypted files
            let res = bincode::deserialize::<ClientConnectionInfo>(data).unwrap();

            println!("{:#?}", res.encrypted_password); // Debug

        // decrypt res.password
        // if res.password
        //     == password
        //         .clone()
        //         .expect("You must provide a password if the files aren't public!")
        // {

        // give the files encrypted with the password
        // }
        } else if req_id == 3 {
            if !uploader_info.public {
                continue;
            }
        }
    }
}
