use crate::types::{self, Payload};
use crate::types::RequestPayload;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use crate::logger::log_error;

pub fn request_and_await_payload(
	host_ip: IpAddr,
	encrypted_password: Vec<u8>,
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
		chunk,
	);

	await_payload(socket, host_addr)
}

pub fn request_payload(
	socket: UdpSocket,
	uploader_addr: SocketAddr,
	hashed_password: Vec<u8>,
	payload_index: u32,
) {
	let request_payload = RequestPayload {
		hashed_password: hashed_password,
		payload_index: payload_index,
	};

	let payload = bincode::serialize(&types::ReditPacket::RequestPayload(request_payload)).unwrap();

	socket
		.send_to(&payload, uploader_addr)
		.map_err(|e| e.to_string())
		.unwrap();
}

pub fn await_payload(socket: UdpSocket, uploader_addr: SocketAddr) -> Payload {
	let mut buf = [0; 49152];

	loop {
		let (amt, src) = match socket.recv_from(&mut buf) {
			Ok((amt, src)) => (amt, src),
			Err(e) => {
				log_error(&format!("Failed to receive packet: {}", e));
				continue;
			}
		};

		let packet_data = &buf[..amt];
		let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
			Ok(data) => data,
			Err(e) => {
				log_error(&format!("Received a corrupt packet: {:?}", e));
				continue;
			}
		};

		match packet {
			types::ReditPacket::Payload(payload) => {
				if src.ip() == uploader_addr.ip() {
					// Make sure it's from the right person
					return payload;
				}
			}
			unexpected => {
				log_error(&format!("Received an unexpected packet: {:?}", unexpected));
				continue;
			}
		}
	}
}

