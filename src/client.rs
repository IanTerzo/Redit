use crate::{
    types::{ClientConnectionInfo, ServerConnectionInfo, UploaderInfo},
    utils::get_local_ip,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    thread,
    time::Duration,
};
use crate::types;

pub fn connect_to_host(
    ip_address: IpAddr,
    encrypted_password: Vec<u8>,
) -> Result<ClientConnectionInfo, String> {
    let local_ip = get_local_ip();

    let request_id: u8 = 2;
    let connection_info = ClientConnectionInfo {
        encrypted_password: encrypted_password,
    };
    let mut serialized_data = bincode::serialize(&connection_info).unwrap();
    let mut payload = Vec::with_capacity(1 + serialized_data.len());
    payload.push(request_id);
    payload.append(&mut serialized_data);

    let socket = UdpSocket::bind("0.0.0.0:6970").map_err(|e| e.to_string())?;
    let addr: SocketAddr = SocketAddr::new(ip_address, 6969);
    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;
    let listener_thread = thread::spawn(move || wait_for_host(socket_clone, 1000, addr));

    socket.send_to(&payload, addr).map_err(|e| e.to_string())?;

    // Wait for the host thread to finish and collect the results
    listener_thread
        .join()
        .map_err(|_| "Failed to join listener thread".to_string())?
}

fn wait_for_host(
    socket: UdpSocket,
    timeout: u64,
    uploader_addr: SocketAddr,
) -> Result<ClientConnectionInfo, String> {
    let mut buf = [0; 1024];

    // Set a read timeout of 100 milliseconds
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout)))
        .map_err(|e| e.to_string())?;

    loop {
        let (amt, src) = match socket.recv_from(&mut buf) {
            Ok((amt, src)) => (amt, src),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return Err("".to_string());
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
                continue
            },
        };

        let packet_data = &buf[..amt];
        let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
            Ok(data) => data,
            Err(_) => continue
        };

        println!("{:?}", packet);

        match packet {
            types::ReditPacket::ClientConnectionInfo(client_connection_info) => {
                if src.ip() == uploader_addr.ip() {
                    return Ok(client_connection_info);
                }
            },
            unexpected => {
                println!("Received unexpected packet {:?}", unexpected);
            }
        }
    }
}

