use crate::client::request_and_await_payload;
use crate::encryption::public_key_from_string;
use crate::logger::{log_error, log_info};
use crate::types::{self, PackagingType};
use rand::rngs::OsRng;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::exit;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

use crate::types::UploaderInfo;

use crate::utils::get_local_ip;

const PORT: u16 = 6969;

fn resolve_payload(packet: types::ReditPacket) -> Option<types::Payload> {
    match packet {
	types::ReditPacket::Payload(payload) => {
	    return Some(payload);
	}
	_ => {
	    return None;
	}
    }
}

fn pipeline_receive(
    socket: UdpSocket,
    tx: mpsc::Sender<types::Payload>,
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
		match bincode::deserialize::<types::ReditPacket>(&buf) {
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
) {
    let payloads_in_transit: Arc<Mutex<HashSet<u32>>> = Default::default();
    let payloads_in_transit_c = payloads_in_transit.clone();
    let (tx, rx) = mpsc::channel::<types::Payload>();

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

	let request_payload: types::RequestPayload = types::RequestPayload {
	    hashed_password: hashed_password.clone(),
	    payload_index: index,
	};
	let request_payload =
	    bincode::serialize(&types::ReditPacket::RequestPayload(request_payload)).unwrap();

	socket
	    .send_to(&request_payload, server_socket)
	    .map_err(|e| e.to_string())
	    .unwrap();

	match rx.try_recv() {
	    Ok(payload) => {
		file.write(&payload.data).unwrap();
	    }
	    Err(_) => {}
	}
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

    let mut filename = selected.0.file_name;
    let is_public = selected.0.public;

    if PackagingType::Tarred == selected.0.packaging {
	filename = format!("{}.tar.gz", filename);
    }

    if is_public == false {
	// TODO: move to encryption module
	let host_public_key_string = selected.0.public_key.unwrap(); // This should always be present if public is false
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

	let first_payload = request_and_await_payload(selected.1, encrypted_password.clone(), 0); // Request the payload at index 0

	if !first_payload.success {
	    log_error("Failed to receive payload info from host");
	    return;
	}

	let payload_count = first_payload.payload_count;

	let mut file = OpenOptions::new()
	    .write(true)
	    .create(true) // Create the file if it doesn't exist
	    .open(filename.clone())
	    .unwrap();

	// Optionally, write nothing to the file to ensure it's empty

	file.write_all(b"").unwrap();
	drop(file);

	let mut file: fs::File = OpenOptions::new()
	    .write(true)
	    .create(true)
	    .append(true)
	    .open(filename)
	    .unwrap();

	file.write_all(&first_payload.data).unwrap();

	get_payloads_via_pipeline(
	    selected.1,
	    encrypted_password.clone(),
	    1,
	    payload_count,
	    0,
	    selected.0.files_size.try_into().unwrap(),
	    file,
	);
    } else {
	log_info("Cannot connect to a private host");
    }
}

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
