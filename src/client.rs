use crate::types::{self, Payload};
use crate::{
    types::{ClientConnectionInfo, RequestPayload, ServerConnectionInfo, UploaderInfo},
    utils::get_local_ip,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

pub fn request_and_await_payload(
    host_ip: IpAddr,
    encrypted_password: Vec<u8>,
    filename: String,
    chunk: u32,
) -> Payload {
    let socket = UdpSocket::bind("0.0.0.0:6970")
        .map_err(|e| e.to_string())
        .unwrap();

    let host_addr: SocketAddr = SocketAddr::new(host_ip, 6969);

    request_payload(
        socket.try_clone().unwrap(),
        host_addr,
        encrypted_password,
        filename,
        chunk,
    );

    await_payload(socket, host_addr)
}

pub fn request_payload(
    socket: UdpSocket,
    uploader_addr: SocketAddr,
    hashed_password: Vec<u8>,
    filename: String,
    payload_index: u32,
) {
    let request_payload = RequestPayload {
        hashed_password: hashed_password,
        hashed_filename: filename,
        payload_index: payload_index,
    };

    let payload = bincode::serialize(&types::ReditPacket::RequestPayload(request_payload)).unwrap();

    socket
        .send_to(&payload, uploader_addr)
        .map_err(|e| e.to_string())
        .unwrap();
}

pub fn await_payload(socket: UdpSocket, uploader_addr: SocketAddr) -> Payload {
    let mut buf = [0; 16384];

    loop {
        let (amt, src) = match socket.recv_from(&mut buf) {
            Ok((amt, src)) => (amt, src),
            Err(e) => {
                println!("Failed to receive packet, trying again: {}", e);
                continue;
            }
        };

        let packet_data = &buf[..amt];
        let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Recieved a corrupt packet: {}", e);
                continue;
            }
        };

        println!("{:?}", packet);

        match packet {
            types::ReditPacket::Payload(payload) => {
                if src.ip() == uploader_addr.ip() {
                    // Make sure it's from the right person
                    return payload;
                }
            }
            unexpected => {
                println!("Received unexpected packet {:?}", unexpected);
                continue;
            }
        }
    }
}
