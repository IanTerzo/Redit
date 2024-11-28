use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::{io, thread};
use std::time::Duration;
use local_ip_address::local_ip;

use crate::types::UploaderInfo;

const PORT: u16 = 20674;

pub fn scan_network(timeout: u64) -> Vec<UploaderInfo> {
    let local_ip = get_local_ip();
    let subnet = match local_ip {
        IpAddr::V4(ipv4) => get_subnet(ipv4),
        IpAddr::V6(_) => {
            println!("IPv6 is not supported");
            return Vec::new();
        }
    };

    // Start the host thread
    let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");
    let socket_clone = socket.try_clone().expect("Failed to clone socket");
    let listener_thread = thread::spawn(move || host(socket_clone, timeout));

    // Broadcast a packet to every IP in the subnet
    for ip in subnet {
        if ip == local_ip {
            continue;
        }
        println!("Connecting to {:?}", ip);
        let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);
        let message: [u8; 1] = [255];

        let _ = socket.send_to(&message, addr);
    }

    // Wait for the host thread to finish and collect the results
    let hosts = listener_thread
        .join()
        .expect("Failed to join listener thread");

    hosts
}

fn get_local_ip() -> IpAddr {
    match local_ip() {
        Ok(ip) => {
            return ip;
        }
        Err(e) => {
            println!("Failed to get local IP address: {}", e);
            // Return a default IP address in case of error
            return IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        }
    }
}

fn get_subnet(local_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut subnet = Vec::new();
    let octets = local_ip.octets();
    for i in 1..=254 {
        subnet.push(Ipv4Addr::new(octets[0], octets[1], octets[2], i));
    }
    subnet
}

fn host(socket: UdpSocket, timeout: u64) -> Vec<UploaderInfo> {
    let mut buf = [0; 1024];
    let mut hosts = Vec::new();

    // Set a read timeout of 100 milliseconds
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout)))
        .expect("Failed to set read timeout");

    loop {

        match socket.recv_from(&mut buf) {
            Ok((_amt, _src)) => {

                match bincode::deserialize::<UploaderInfo>(&buf) {
                    Ok(res) => {
                        hosts.push(res);
                    }
                    Err(e) => {
                        println!("Failed to deserialize packet: {}", e);
                    }
                }
            }
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

