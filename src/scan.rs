use crate::logger::{log_error, log_info};
use crate::types::{ReditPacket, RequestUploaderInfo, UploaderInfo, PORT};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};

use crate::utils::get_local_ip;

pub fn scan_network(timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    let local_ip = get_local_ip();
    let octets = match local_ip {
        IpAddr::V4(ipv4) => ipv4.octets(),
        IpAddr::V6(_) => {
            log_info("IPv6 is not supported");
            return Vec::new();
        }
    };

    // Start the host thread
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", PORT)).expect("Couldn't bind to address");
    let socket_clone = socket.try_clone().expect("Failed to clone socket");
    let listener_thread = thread::spawn(move || recieve_uploader_info(socket_clone, timeout));

    // Broadcast a packet to every IP in the subnet
    if local_ip.is_ipv4() {
        for c in 1..255 {
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], c);
            if ip == local_ip {
                continue;
            }

            let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);
            let packet = ReditPacket::RequestUploaderInfo(RequestUploaderInfo {
                public_key: Some("".to_string()),
            });

            let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
        }
    }

    // Wait for the host thread to finish and collect the results
    let hosts = listener_thread
        .join()
        .expect("Failed to join listener thread");

    hosts
}

fn recieve_uploader_info(socket: UdpSocket, timeout: u64) -> Vec<(UploaderInfo, IpAddr)> {
    // TODO: Ditch the buf and print the uploader infos as they come.
    let mut buf = [0; 64 * 1024];
    let mut hosts = Vec::new();

    // Set a read timeout of 100 milliseconds to stop awaiting if there are no responses after 100 milliseconds
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout)))
        .expect("Failed to set read timeout");

    loop {
        match socket.recv_from(&mut buf) {
            // Deserialize as UploaderInfo
            Ok((_amt, src)) => match bincode::deserialize::<UploaderInfo>(&buf) {
                Ok(res) => {
                    // Add the hosts UploaderInfo and ip to hosts
                    hosts.push((res, src.ip()));
                }
                Err(e) => {
                    log_error(&format!("Failed to deserialize packet: {}", e));
                }
            },
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout occurred, break the loop.
                break;
            }
            Err(e) => {
                log_error(&format!("Failed to receive packet: {}", e));
            }
        }
    }

    hosts
}
