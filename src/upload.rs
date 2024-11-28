use std::net::{Ipv4Addr, UdpSocket, SocketAddr};
use std::str;
use serde::{Serialize, Deserialize};

pub fn host(uploader_info: UploaderInfo) {

    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    println!("Listening for incoming packets on 6969");

    let mut buf = [0; 1024];
    loop {

        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        println!("Received packet from: {}", src);

        let packet_data = &buf[..amt];

           if packet_data.len() == 1{
                let serialized = bincode::serialize(&uploader_info).unwrap();
                socket.send_to(&serialized, src).expect("Couldn't send data");
                println!("responding");
            }

    }
}

