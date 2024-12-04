use std::{io, net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket}, thread, time::Duration};
use crate::{utils::get_local_ip, types::{ClientConnectionInfo, UploaderInfo, ServerConnectionInfo}};

pub fn connect_to_host(uploader_info: UploaderInfo, password: Option<String>) -> Result<ClientConnectionInfo, String> {
    let local_ip = get_local_ip();

    let ipv4 = match local_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => return Err("Local IP address is not IPv4".to_string()),
    };

    let connection_info = ClientConnectionInfo {
        password: password,
        client_ip_address: ipv4,
    };

    let socket = UdpSocket::bind("0.0.0.0:6970").map_err(|e| e.to_string())?;
    let addr: SocketAddr = SocketAddr::new(uploader_info.ip_address.into(), 6969);
    let socket_clone = socket.try_clone().map_err(|e| e.to_string())?;
    let listener_thread = thread::spawn(move || get_response_from_host(socket_clone, 1000, uploader_info.ip_address));

    let connection_info_bytes = bincode::serialize(&connection_info).map_err(|e| e.to_string())?;
    socket.send_to(&connection_info_bytes, addr).map_err(|e| e.to_string())?;

    // Wait for the host thread to finish and collect the results
    listener_thread.join().map_err(|_| "Failed to join listener thread".to_string())?
}

fn get_response_from_host(socket: UdpSocket, timeout: u64, uploader_ip: Ipv4Addr) -> Result<ClientConnectionInfo, String> {
    let mut buf = [0; 1024];

    // Set a read timeout of 100 milliseconds
    socket.set_read_timeout(Some(Duration::from_millis(timeout)))
        .map_err(|e| e.to_string())?;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                if src.ip() == uploader_ip {
                    match bincode::deserialize::<ClientConnectionInfo>(&buf[..amt]) {
                        Ok(res) => return Ok(res),
                        Err(e) => println!("Failed to deserialize packet: {}", e),
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // Timeout occurred, break the loop
                break;
            }
            Err(e) => println!("Failed to receive packet: {}", e),
        }
    }

    Err("No valid packets received".to_string())
}

pub fn wait_for_client_connection(password: Option<String>) -> Result<ServerConnectionInfo, String> {
    let socket = UdpSocket::bind("0.0.0.0:6970").map_err(|e| e.to_string())?;
    let mut buf = [0; 1024];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                match bincode::deserialize::<ClientConnectionInfo>(&buf[..amt]) {
                    Ok(client_info) => {
                        println!("Received ClientConnectionInfo: {:?}", client_info);

                        let server_info;
                        // Check for password
                        if client_info.password == password {
                            server_info = ServerConnectionInfo {
                                success: true,
                            };
                            // Send files here
                        } else {
                            server_info = ServerConnectionInfo {
                                success: false,
                            };
                        }

                        // Serialize ServerConnectionInfo
                        let server_info_bytes = bincode::serialize(&server_info).map_err(|e| e.to_string())?;

                        // Send ServerConnectionInfo back to the client
                        socket.send_to(&server_info_bytes, src).map_err(|e| e.to_string())?;

                        return Ok(server_info);
                    }
                    Err(e) => println!("Failed to deserialize packet: {}", e),
                }
            }
            Err(e) => println!("Failed to receive packet: {}", e),
        }
    }
}