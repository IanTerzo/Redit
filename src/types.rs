use serde::{Serialize, Deserialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UploaderInfo {
    pub public: bool,
    pub name: String,
    pub files_size: i32,
    pub ip_address: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientConnectionInfo {
    pub client_ip_address: Ipv4Addr,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConnectionInfo {
    pub(crate) success: bool,
}