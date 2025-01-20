use crate::client::request_and_await_payload;
use crate::encryption::public_key_from_string;
use crate::types;
use rand::rngs::OsRng;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};

use crate::types::UploaderInfo;

use crate::utils::get_local_ip;

const PORT: u16 = 6969;

pub fn scan() {
    let availible_hosts = scan_network(10000);
    println!("{:#?}", availible_hosts); // Visa upp dem fint.
    println!("Choose a host to connect to 0 - 10: ");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let index: usize = input.trim().parse().unwrap();
    let selected = availible_hosts[index].clone();

    let filename = selected.0.file_name;
    let is_public = selected.0.public;

    if is_public == false {
        // TODO: move to encryption module
        let host_public_key_string = selected.0.public_key.unwrap(); // This should always be present if public is false
        let host_public_key = public_key_from_string(host_public_key_string).unwrap();

        println!("password: ");
        let mut password = String::new();
        io::stdin()
            .read_line(&mut password)
            .expect("Failed to read line");

        let password = password.trim();

        let mut rng = OsRng;

        let encrypted_password = host_public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
            .unwrap();

        let mut data = Vec::new();

        let first_payload = request_and_await_payload(selected.1, encrypted_password.clone(), 0); // Request the payload at index 0

        if !first_payload.success {
            println!("Failed to recieve payload info from host");
            return;
        }

        println!("{:#?}", first_payload);

        let payload_count = first_payload.payload_count;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(filename)
            .unwrap();

        file.write_all(&first_payload.data).unwrap();
        let bar = indicatif::ProgressBar::new(payload_count.into());
        bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40} {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        for index in 1..payload_count {
            bar.inc(1);
            let payload = request_and_await_payload(selected.1, encrypted_password.clone(), index);
            data.extend(payload.data.clone());
            file.write_all(&payload.data).unwrap();
        }
        bar.finish();
    } else {
        println!("Cannot connect to a private host")
    }
}

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
    let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");
    let socket_clone = socket.try_clone().expect("Failed to clone socket");
    let listener_thread = thread::spawn(move || recieve_uploader_info(socket_clone, timeout));

    // Broadcast a packet to every IP in the subnet
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
                    println!("{}: {:?}", src, res.hashed_connection_salt);
                    // Add the hosts UploaderInfo and ip to hosts
                    hosts.push((res, src.ip()));
                }
                Err(e) => {
                    println!("Failed to deserialize packet: {}", e);
                }
            },
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout occurred, break the loop.
                break;
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
            }
        }
    }

    hosts
}
