use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RequestUploaderInfo {
    pub public_key: Option<String>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UploaderInfo {
    pub public: bool,
    pub name: String,
    pub files_size: i32,
    pub public_key: Option<String>,
    pub hashed_connection_salt: Option<String>
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestPayload {
    pub hashed_password: String,
    pub hashed_filename: String,
    pub payload_index: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Payload {
    pub success: bool,
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

#[derive(Serialize, Deserialize, Debug, PartialEq )]
#[repr(u16)]
pub enum ReditPacket {
    RequestUploaderInfo(RequestUploaderInfo) = 0,
    UploaderInfo(UploaderInfo) = 1,
    RequestPayload(RequestPayload) = 2,
    Payload(Payload) = 3,
    ClientConnectionInfo(ClientConnectionInfo) = 4,
    ServerConnectionInfo(ServerConnectionInfo) = 5,
}

