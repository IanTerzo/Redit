use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};
use crate::types;

use crate::types::{
    ReditPacket,
    UploaderInfo
};

use crate::utils::get_local_ip;

const PORT: u16 = 6969;

pub fn scan_network(timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let local_ip = get_local_ip();
    let subnet = match local_ip {
        IpAddr::V4(ipv4) => get_subnet(ipv4),
        IpAddr::V6(_) => {
            println!("IPv6 is not supported");
            return Vec::new();
        }
    };

    // Start the host thread
    let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT))
        .expect("Couldn't bind to address");
    let socket_clone = socket.try_clone()
        .expect("Failed to clone socket");
    let listener_thread = thread::spawn(move || host(socket_clone, timeout));

    // Broadcast a packet to every IP in the subnet
    for ip in subnet {
        if ip == local_ip {
            continue;
        }

        let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);
        let packet = types::ReditPacket::RequestUploaderInfo(types::RequestUploaderInfo {
            public_key: Some("".to_string()),
        });

        let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
    }

    // Wait for the host thread to finish and collect the results
    let hosts = listener_thread
        .join()
        .expect("Failed to join listener thread");

    hosts
}

fn get_subnet(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut subnet = Vec::new();
    let octets = local_ip.octets();
    for i in 1..=254 {
        subnet.push(Ipv4Addr::new(octets[0], octets[1], octets[2], i));
    }
    subnet
}

fn host(socket: UdpSocket, timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let mut buf = [0; 1024];
    let mut hosts = Vec::new();

    // Set a read timeout of 100 milliseconds
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout)))
        .expect("Failed to set read timeout");

    loop {
        match socket.recv_from(&mut buf) {
            Ok((_amt, src)) => match bincode::deserialize::<UploaderInfo>(&buf) {
                Ok(res) => {
                    hosts.push((res, src.ip()));
                }
                Err(e) => {
                    println!("Failed to deserialize packet: {}", e);
                }
            },
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout occurred, continue the loop
                break;
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
            }
        }
    }

    hosts
}
