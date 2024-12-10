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

pub fn connect_to_host(
    ip_address: IpAddr,
    encrypted_password: String,
) -> Result<ClientConnectionInfo, String> {
    let local_ip = get_local_ip();

    let connection_info = ClientConnectionInfo {
        password: encrypted_password,
    };

    let socket = UdpSocket::bind("0.0.0.0:6970").map_err(|e| e.to_string())?;
    let addr: SocketAddr = SocketAddr::new(ip_address, 6969);
    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;
    let listener_thread = thread::spawn(move || wait_for_host(socket_clone, 1000, addr));

    let connection_info_bytes = bincode::serialize(&connection_info).map_err(|e| e.to_string())?;
    socket
        .send_to(&connection_info_bytes, addr)
        .map_err(|e| e.to_string())?;

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
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                if src.ip() == uploader_addr.ip() {
                    match bincode::deserialize::<ClientConnectionInfo>(&buf[..amt]) {
                        Ok(res) => return Ok(res),
                        Err(e) => println!("Failed to deserialize packet: {}", e),
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout occurred, break the loop
                break;
            }
            Err(e) => println!("Failed to receive packet: {}", e),
        }
    }

    Err("No valid packets received".to_string())
}
