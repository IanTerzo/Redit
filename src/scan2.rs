use std::thread;
use std::sync::mpsc;
use std::collections::HashSet;
use std::net::{UdpSocket, IpAddr, SocketAddr};
use crate::types::{ReditPacket, RequestScanStore};
use std::io;
use std::fs;
use std::io::BufRead;
use std::time::Duration;

const PORT: u16 = 6969;

fn resolve_packet(packet: ReditPacket) -> Option<HashSet<IpAddr>> {
	match packet {
		ReditPacket::ScanStore(scan_store) => {
			return Some(scan_store.store);
		}
		_ => { return None; }
	}
}

fn request_packet(socket: &UdpSocket, addr: SocketAddr) {
	let packet = ReditPacket::RequestScanStore(RequestScanStore {
	});

	let _ = socket.send_to(&bincode::serialize(&packet).unwrap(), addr);
}

fn scan_receive(tx: mpsc::Sender<HashSet<IpAddr>>) {
	let mut buf = [0; 1024];
	let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");

	loop {
		match socket.recv_from(&mut buf) {
			Ok((_response_size, _respondee_address)) => match bincode::deserialize::<ReditPacket>(&buf) {
				Ok(res) => {
					let scan_store = match resolve_packet(res) {
						Some(scan_store) => scan_store,
						None => continue
					};
					match tx.send(scan_store) {
						Ok(_) => {},
						Err(_) => {}
					};
				}
				Err(e) => {
					println!("Failed to deserialize packet: {}", e);
				}
			},
			Err(ref e)
			if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
			{
				break;
			}
			Err(e) => {
				println!("Failed to receive packet: {}", e);
			}
		}
	}
}

fn scan() {
	scan_efficient(3);
	scan_iterative();
}

fn scan_efficient(depth: u32) {
	if depth == 0 {
		return;
	}

	/* Set up listener thread. */
	let (tx, rx) = mpsc::channel::<HashSet<IpAddr>>();
	let recipient = thread::spawn(move || {
		scan_receive(tx);
	});


	let scan_store_persistent = match fs::OpenOptions::new().create(true).read(true).open("scan_store.txt") {
		Ok(file) => file,
		Err(_) => return
	};

	let socket = UdpSocket::bind(format!("0.0.0.0:{:?}", PORT)).expect("Couldn't bind to address");
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
	for scan_store in rx.recv() {
		for record in scan_store {
			scan_store_staging.insert(record);
		}
	}

	recipient.join().unwrap();

	scan_efficient(depth - 1);
}

fn scan_iterative() {

}

