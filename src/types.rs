use serde::{Serialize, Deserialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UploaderInfo {
    pub public: bool,
    pub name: String,
    pub files_size: i32,
    pub public_key: Option<String>,
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

pub struct ClientConnectionInfo {
    pub password: Option<String>,
    pub client_ip_address: Ipv4Addr,
}

pub struct ServerConnectionInfo {
    pub success: bool,
}