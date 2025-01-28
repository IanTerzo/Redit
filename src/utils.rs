use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::logger::log_error;
use local_ip_address::local_ip;

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

#[derive(Clone)]
pub struct CancellationToken {
	cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
	#[inline]
	pub fn should_cancel(&self) -> bool {
		self.cancelled.load(Ordering::Acquire)
	}
}

#[derive(Clone)]
pub struct Canceller {
	cancelled: Arc<AtomicBool>,
}

impl Canceller {
	#[inline]
	pub fn cancel(&self) {
		self.cancelled.store(true, Ordering::Release);
	}
}

#[inline]
pub fn cancellation_token() -> (Canceller, CancellationToken) {
	let cancelled = Arc::new(AtomicBool::new(false));
	(
		Canceller {
			cancelled: Arc::clone(&cancelled),
		},
		CancellationToken { cancelled },
	)
}

mod tests {
	#[allow(unused_imports)]
	use super::*;

	#[test]
	fn test_get_local_ip() {
		get_local_ip();
	}
}

