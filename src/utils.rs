use std::net::{IpAddr, Ipv4Addr};

use local_ip_address::local_ip;
use crate::logger::log_error;

pub fn get_local_ip() -> IpAddr {
	match local_ip() {
		Ok(ip) => {
			return ip;
		}
		Err(e) => {
			log_error(&format!("Failed to get local IP address: {}", e));
			// Return a default IP address in case of error
			return IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
		}
	}
}

