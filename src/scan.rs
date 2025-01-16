use crate::types;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;
use std::{io::{self, Read, Write}, thread};

use crate::types::{ReditPacket, UploaderInfo};

use crate::utils::get_local_ip;

const PORT: u16 = 6969;

pub fn scan_network(timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let local_ip = get_local_ip();
    let octets = match local_ip {
        IpAddr::V4(ipv4) => ipv4.octets(),
        IpAddr::V6(_) => {
            println!("IPv6 is not supported");
            return Vec::new();
        }
    };

    // Start the host thread
    let listener = TcpListener::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");
    listener.set_nonblocking(true).expect("Failed to set non-blocking");
    let listener_thread = thread::spawn(move || receive_uploader_info(listener, timeout));

    // Connect to every IP in the subnet
    if local_ip.is_ipv4() {
        for c in 1..255 {
            let ip = Ipv4Addr::new(octets[0], octets[1], 3, c);
            if ip == local_ip {
                continue;
            }

            let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);
            let packet = types::ReditPacket::RequestUploaderInfo(types::RequestUploaderInfo {
                public_key: Some("".to_string()),
            });

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout)) {
                let _ = stream.write_all(&bincode::serialize(&packet).unwrap());
            }
        }
    }

    // Wait for the host thread to finish and collect the results
    let hosts = listener_thread
        .join()
        .expect("Failed to join listener thread");

    hosts
}

fn receive_uploader_info(listener: TcpListener, timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let mut hosts = Vec::new();
    let start_time = std::time::Instant::now();

    loop {
        if start_time.elapsed().as_millis() > timeout as u128 {
            break;
        }

        match listener.accept() {
            Ok((mut stream, addr)) => {
                let mut buf = [0; 2048];
                match stream.read(&mut buf) {
                    Ok(_amt) => match bincode::deserialize::<UploaderInfo>(&buf) {
                        Ok(res) => {
                            println!("{}: {:?}", addr, res.hashed_connection_salt);
                            hosts.push((res, addr.ip()));
                        }
                        Err(e) => {
                            println!("Failed to deserialize packet: {}", e);
                        }
                    },
                    Err(e) => {
                        println!("Failed to read from stream: {}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No connection yet, continue looping
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                println!("Failed to accept connection: {}", e);
            }
        }
    }

    hosts
}