use crate::logger::{log_error, log_info};
use crate::types::{ReditPacket, RequestUploaderInfo, UploaderInfo, PORT};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};

use crate::utils::get_local_ip;

pub fn scan_network(timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let local_ip = get_local_ip();

    // Store the ips octets in an iterator for later use
    let octets = match local_ip {
        IpAddr::V4(ipv4) => ipv4.octets(),
        IpAddr::V6(_) => {
            log_info("IPv6 is not supported");
            return Vec::new();
        }
    };

    // Start waiting for the hosts reponses on a separate thread (listener_thread)
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", PORT)).expect("Couldn't bind to address");
    let socket_clone = socket.try_clone().expect("Failed to clone socket");
    let listener_thread = thread::spawn(move || recieve_uploader_info(socket_clone, timeout));

    // Broadcast a RequestUploaderInfo to every IP in the subnet
    for c in 1..255 {
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], c);

        // Avoid broadcasting to your own ip
        if ip == local_ip {
            continue;
        }

        let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);
        let packet = ReditPacket::RequestUploaderInfo(RequestUploaderInfo {
            public_key: Some("".to_string()),
        });

        let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
    }

    // Wait for the listener thread to finish and collect the results
    let hosts = listener_thread
        .join()
        .expect("Failed to join listener thread");

    hosts
}

fn recieve_uploader_info(socket: UdpSocket, timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let mut buf = [0; 64 * 1024];
    let mut hosts = Vec::new();

    // Stop awaiting if there are no responses after the timeout
    // By default it is 100 milliseconds
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout)))
        .expect("Failed to set read timeout");

    loop {
        let (_amt, src) = match socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout occurred, break the loop.
                break;
            }
            Err(e) => {
                log_error(&format!("Failed to receive packet: {}", e));
                continue;
            }
        };

        let uploader_info = match bincode::deserialize::<UploaderInfo>(&buf) {
            Ok(res) => res,
            Err(e) => {
                log_error(&format!("Failed to deserialize packet: {}", e));
                continue;
            }
        };

        // Add the hosts UploaderInfo and IP to hosts.
        hosts.push((uploader_info, src.ip()));
    }

    hosts
}

mod tests {
    use super::*;

    #[test]
    fn test_scan() {
        scan_network(100);
    }
}
