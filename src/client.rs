use crate::encryption::{decrypt_with_passphrase, derive_key, public_key_from_string};
use crate::logger::{log_error, log_info};
use crate::scan::scan_network;
use crate::types::{PackagingType, Payload, ReditPacket, RequestPayload, PAYLOAD_SIZE, PORT};
use rand::rngs::OsRng;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::{SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

fn resolve_payload(packet: ReditPacket) -> Option<Payload> {
    match packet {
        ReditPacket::Payload(payload) => {
            return Some(payload);
        }
        _ => {
            return None;
        }
    }
}

fn pipeline_receive(
    socket: UdpSocket,
    tx: mpsc::Sender<Payload>,
    start: u32,
    end: u32,
    start_byte: u64,
    end_byte: u64,
    payloads_in_transit: Arc<Mutex<HashSet<u32>>>,
) {
    let mut buf = [0; 524288];
    let mut payloads_received: HashSet<u32> = Default::default();

    let bar = indicatif::ProgressBar::new(end.into());
    bar.set_style(
	indicatif::ProgressStyle::default_bar()
	    .template("[{elapsed_precise}] {wide_bar} {binary_bytes}/{binary_total_bytes} {bytes_per_sec} [{eta}]")
	    .unwrap()
	    .progress_chars("#>-"),
    );
    bar.set_position(start_byte);
    bar.set_length(end_byte);

    loop {
        match socket.recv_from(&mut buf) {
            Ok((_response_size, _respondee_address)) => {
                match bincode::deserialize::<ReditPacket>(&buf) {
                    Ok(res) => {
                        let payload = match resolve_payload(res) {
                            Some(payload) => payload,
                            None => continue,
                        };
                        payloads_received.insert(payload.index);
                        payloads_in_transit.lock().unwrap().remove(&payload.index);
                        bar.inc(payload.data.len().try_into().unwrap());
                        match tx.send(payload) {
                            Ok(_) => {}
                            Err(_) => {}
                        };
                    }
                    Err(e) => {
                        log_error(&format!("Failed to deserialize packet: {}", e));
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                log_error(&format!("Failed to receive packet: {}", e));
            }
        }
        let payloads_remaining: usize = usize::try_from(end).unwrap()
            - payloads_received.len()
            - usize::try_from(start).unwrap();
        if payloads_remaining == 0 {
            break;
        }
    }

    bar.finish();
}

pub fn get_payloads_via_pipeline(
    server_addr: IpAddr,
    hashed_password: Vec<u8>,
    start: u32,
    end: u32,
    start_byte: u64,
    end_byte: u64,
    mut file: fs::File,
    password: &str,
) {
    let payloads_in_transit: Arc<Mutex<HashSet<u32>>> = Default::default();
    let payloads_in_transit_c = payloads_in_transit.clone();
    let (tx, rx) = mpsc::channel::<Payload>();

    log_info(&format!("Binding to address 0.0.0.0:{}", PORT));
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", PORT)).expect("Couldn't bind to address");
    let listener_socket = socket.try_clone().unwrap();

    let server_socket: SocketAddr = SocketAddr::new(server_addr, 6969);

    let listener = thread::spawn(move || {
        pipeline_receive(
            listener_socket,
            tx,
            start,
            end,
            start_byte,
            end_byte,
            payloads_in_transit_c,
        );
    });

    let key = derive_key(password);

    for index in start..end {
        loop {
            let payloads_in_transit_count = payloads_in_transit.lock().unwrap().len();
            if payloads_in_transit_count > 10 {
                thread::sleep(Duration::from_millis(20))
            } else {
                break;
            }
        }
        payloads_in_transit.lock().unwrap().insert(index);

        let request_payload: RequestPayload = RequestPayload {
            hashed_password: hashed_password.clone(),
            payload_index: index,
        };
        let request_payload =
            bincode::serialize(&ReditPacket::RequestPayload(request_payload)).unwrap();

        socket
            .send_to(&request_payload, server_socket)
            .map_err(|e| e.to_string())
            .unwrap();

        match rx.try_recv() {
            Ok(payload) => {
                match file.seek(SeekFrom::Start(
                    u64::from(payload.index) * u64::from(PAYLOAD_SIZE),
                )) {
                    Ok(_) => {}
                    Err(_) => file
                        .flush()
                        .expect("Unable to flush output file due to error"),
                };
                let data = decrypt_with_passphrase(&payload.data, &key);
                file.write(&data).unwrap();
            }
            Err(_) => {}
        }
    }
    match rx.try_recv() {
        Ok(payload) => {
            let key = derive_key(password);
            let data = decrypt_with_passphrase(&payload.data, &key);
            file.write(&data).unwrap();
        }
        Err(_) => {}
    }

    listener.join().unwrap();
}

pub fn scan() {
    let availible_hosts = scan_network(10000);
    for (index, host) in availible_hosts.clone().iter().enumerate() {
        log_info(&format!(
            "{} - Filename: {}, Host: {}",
            index, host.0.file_name, host.0.name
        ));
    }
    log_info("Choose a host to connect to 0 - 10: ");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let index: usize = input.trim().parse().unwrap();
    let selected = availible_hosts[index].clone();

    let host_info = selected.0;
    let host_ip = selected.1;

    let mut filename = host_info.file_name;
    let is_public = host_info.public;

    if PackagingType::Tarred == host_info.packaging {
        filename = format!("{}.tar.gz", filename);
    }

    if is_public == false {
        let host_public_key_string = host_info.public_key.unwrap();
        let host_public_key = public_key_from_string(host_public_key_string).unwrap();

        log_info("password: ");
        let mut password = String::new();
        io::stdin()
            .read_line(&mut password)
            .expect("Failed to read line");

        let password = password.trim();

        let mut rng = OsRng;

        let encrypted_password = host_public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
            .unwrap();

        let first_payload = request_and_await_payload(host_ip, encrypted_password.clone(), 0);

        if !first_payload.success {
            log_error("Failed to receive payload info from host");
            return;
        }

        let payload_count = first_payload.payload_count;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(filename.clone())
            .unwrap();

        file.write_all(b"").unwrap();
        drop(file);

        let mut file: fs::File = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(filename)
            .unwrap();

        let encrypted_data = &first_payload.data;

        let key = derive_key(password);
        let data = decrypt_with_passphrase(encrypted_data, &key);
        file.write_all(&data).unwrap();

        get_payloads_via_pipeline(
            host_ip,
            encrypted_password.clone(),
            1,
            payload_count,
            0,
            host_info.files_size.try_into().unwrap(),
            file,
            password,
        );
    } else {
        log_info("Cannot connect to a private host");
    }
}

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

    let payload = bincode::serialize(&ReditPacket::RequestPayload(request_payload)).unwrap();

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
        let packet: ReditPacket = match bincode::deserialize(packet_data) {
            Ok(data) => data,
            Err(e) => {
                log_error(&format!("Received a corrupt packet: {:?}", e));
                continue;
            }
        };

        match packet {
            ReditPacket::Payload(payload) => {
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
