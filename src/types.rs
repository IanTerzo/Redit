use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub const PAYLOAD_SIZE: u32 = 32768;
pub const PORT: u16 = 6969;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RequestUploaderInfo {
	pub public_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq, Hash)]
pub enum PackagingType {
	None,
	Tarred,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq, Hash)]
pub struct UploaderInfo {
	pub public: bool,
	pub name: String,
	pub files_size: u64,
	pub file_name: String,
	pub packaging: PackagingType,
	pub public_key: Option<String>,
	pub hashed_connection_salt: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestPayload {
	pub hashed_password: Vec<u8>,
	pub payload_index: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Payload {
	pub success: bool,
	pub index: u32,
	pub payload_count: u32,
	pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ClientConnectionInfo {
	pub encrypted_password: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ServerConnectionInfo {
	pub success: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestScanStore {}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ScanStore {
	pub store: HashSet<IpAddr>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[repr(u16)]
pub enum ReditPacket {
	RequestUploaderInfo(RequestUploaderInfo) = 0,
	UploaderInfo(UploaderInfo) = 1,
	RequestPayload(RequestPayload) = 2,
	Payload(Payload) = 3,
	ClientConnectionInfo(ClientConnectionInfo) = 4,
	ServerConnectionInfo(ServerConnectionInfo) = 5,
	RequestScanStore(RequestScanStore) = 6,
	ScanStore(ScanStore) = 7,
}

