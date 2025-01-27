#![allow(dead_code, unused)]

use std::thread;
use std::sync::mpsc;
use std::collections::HashSet;
use std::net::{UdpSocket, IpAddr, Ipv4Addr, SocketAddr};
use crate::types::{ReditPacket, ScanStore, RequestScanStore, UploaderInfo, RequestUploaderInfo};
use std::io;
use std::fs;
use std::io::BufRead;
use std::io::Write;
use std::time::Duration;
use crate::utils::get_local_ip;
use crate::logger::{log_error, log_info};

const PORT: u16 = 6969;

pub fn resolve_packet(packet: ReditPacket, address_channel: mpsc::Sender<Option<IpAddr>>, uploader_channel: mpsc::Sender<Option<(UploaderInfo, IpAddr)>>, address: SocketAddr) {
	log_info(&format!("<- {:?}", packet));
	match packet {
		ReditPacket::ScanStore(scan_store) => {
			for record in scan_store.store.iter() {
				address_channel.send(Some(*record));
			}
		}
		ReditPacket::UploaderInfo(uploader) => {
			uploader_channel.send(Some((uploader, address.ip())));
		}
		_ => { }
	}
}

pub fn request_packet(socket: &UdpSocket, addr: SocketAddr) {
	let packet = ReditPacket::RequestScanStore(RequestScanStore {});

	log_info(&format!("-> {:?}", packet));
	let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
}

pub fn request_uploader_info(socket: &UdpSocket, addr: SocketAddr) {
	let packet = ReditPacket::RequestUploaderInfo(RequestUploaderInfo {
		public_key: Some("".to_string()),
	});

	log_info(&format!("-> {:?}", packet));
	let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
}

pub fn scan_receive(socket: &UdpSocket, address_channel: mpsc::Sender<Option<IpAddr>>, uploader_channel: mpsc::Sender<Option<(UploaderInfo, IpAddr)>>) {
	let mut buf = [0; 1024];

	loop {
		match socket.recv_from(&mut buf) {
			Ok((_response_size, respondee_address)) => match bincode::deserialize::<ReditPacket>(&buf) {
				Ok(res) => {
					resolve_packet(res, address_channel.clone(), uploader_channel.clone(), respondee_address);
				}
				Err(e) => {
					log_error(&format!("Failed to deserialize packet: {}", e));
				}
			},
			Err(ref e)
			if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
			{
				break;
			}
			Err(e) => {
				log_error(&format!("Failed to receive packet: {}", e));
			}
		}
	}
}

pub fn scan(uploader_channel: mpsc::Sender<Option<(UploaderInfo, IpAddr)>>) {
	let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");

	log_info("Scanning efficiently");
	scan_efficient(socket.try_clone().unwrap(), uploader_channel.clone(), 3);
	log_info("Scanning iteratively");
	scan_iterative(socket, uploader_channel.clone());

	uploader_channel.send(None);
}

pub fn submit_scan_store(socket: &UdpSocket, addr: SocketAddr) {
	log_info("Submitting scan store");
	let scan_store_persistent = match fs::OpenOptions::new().create(true).read(true).open("scan_store.txt") {
		Ok(file) => file,
		Err(_) => return
	};

	let mut scan_store_staging: HashSet<IpAddr> = Default::default();
	let scan_store_reader = io::BufReader::new(scan_store_persistent);
	for line in scan_store_reader.lines() {
		let line = match line {
			Ok(line) => line,
			Err(_) => return
		};
		let addr: IpAddr = match line.parse() {
			Ok(addr) => addr,
			Err(_) => return
		};
		scan_store_staging.insert(addr);
	}

	let packet = ReditPacket::ScanStore(ScanStore {
		store: scan_store_staging,
	});

	let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
}

pub fn scan_efficient(socket: UdpSocket, uploader_channel: mpsc::Sender<Option<(UploaderInfo, IpAddr)>>, depth: u32) {
	if depth == 0 {
		return;
	}

	/* Set up listener thread. */
	let (address_channel_tx, address_channel_rx) = mpsc::channel::<Option<IpAddr>>();
	let recipient_uploader_channel = uploader_channel.clone();
	let recipient_socket = socket.try_clone().unwrap();
	let recipient = thread::spawn(move || {
		scan_receive(&recipient_socket, address_channel_tx, recipient_uploader_channel);
	});

	let scan_store_persistent = match fs::OpenOptions::new().create(true).read(true).open("scan_store.txt") {
		Ok(file) => file,
		Err(_) => return
	};

	let scan_store_reader = io::BufReader::new(scan_store_persistent);
	for line in scan_store_reader.lines() {
		let line = match line {
			Ok(line) => line,
			Err(_) => return
		};
		let addr: SocketAddr = match line.parse() {
			Ok(addr) => addr,
			Err(_) => return
		};
		request_packet(&socket, addr);
	}

	/* Allow leeway for respondees to respond. */
	thread::sleep(Duration::from_millis(2000));
	let mut scan_store_staging: HashSet<IpAddr> = Default::default();
	let mut scan_store_persistent = match fs::OpenOptions::new().write(true).open("scan_store.txt") {
		Ok(file) => file,
		Err(_) => return
	};

	while let Ok(Some(record)) = address_channel_rx.recv() {
		scan_store_staging.insert(record);
		if scan_store_staging.contains(&record) {
			continue;
		}
		let socket_address: SocketAddr = SocketAddr::new(record.into(), PORT);
		request_uploader_info(&socket, socket_address);
		writeln!(scan_store_persistent, "{}", record.to_string());
	}

	recipient.join().unwrap();

	scan_efficient(socket, uploader_channel, depth - 1);
}

pub fn scan_iterative(socket: UdpSocket, uploader_channel: mpsc::Sender<Option<(UploaderInfo, IpAddr)>>) -> HashSet<IpAddr> {
	let local_ip = get_local_ip();
	let octets = match local_ip {
		IpAddr::V4(ipv4) => ipv4.octets(),
		IpAddr::V6(_) => {
			log_info("IPv6 is not supported");
			return Default::default();
		}
	};

	/* Set up listener thread. */
	let (tx, rx) = mpsc::channel::<Option<IpAddr>>();
	let (address_channel_tx, address_channel_rx) = mpsc::channel::<Option<IpAddr>>();
	let recipient_socket = socket.try_clone().unwrap();
	let recipient_address_channel_tx = address_channel_tx.clone();
	let recipient = thread::spawn(move || {
		scan_receive(&recipient_socket, recipient_address_channel_tx, uploader_channel);
	});

	if local_ip.is_ipv4() {
		for b in 1..4 {
			for c in 1..255 {
				let ip = Ipv4Addr::new(octets[0], octets[1], b, c);
				if ip == local_ip {
					continue;
				}

				let addr: SocketAddr = SocketAddr::new(ip.into(), PORT);

				request_packet(&socket, addr);
			}
			thread::sleep(Duration::from_millis(100));
		}
	}

	thread::sleep(Duration::from_millis(2000));
	let mut scan_store_staging: HashSet<IpAddr> = Default::default();
	while let Ok(scan_store) = rx.recv() {
		for record in scan_store {
			address_channel_tx.send(Some(record));
			scan_store_staging.insert(record);
			let socket_address: SocketAddr = SocketAddr::new(record.into(), PORT);
			request_uploader_info(&socket, socket_address);
		}
	}

	recipient.join().unwrap();
	return scan_store_staging;
}

