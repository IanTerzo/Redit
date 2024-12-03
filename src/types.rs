use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct UploaderInfo {
    pub public: bool,
    pub name: String,
    pub files_size: i32
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

