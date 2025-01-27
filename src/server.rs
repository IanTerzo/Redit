use crate::encryption::{
    derive_key, encrypt_with_passphrase, generate_private_key, generate_public_key, generate_salt,
    public_key_to_string,
};
use crate::logger::{log_error, log_info};
use crate::scan;
use crate::types;
use crate::types::Payload;
use crate::types::UploaderInfo;
use crate::types::PAYLOAD_SIZE;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

// Read a chunk of a file starting from `start` ending at `end`
fn read_file_chunk(file_path: &Path, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path).unwrap();

    file.seek(SeekFrom::Start(start)).unwrap();

    let chunk_size = (end - start) as usize;
    let mut buffer = vec![0; chunk_size];
    file.read_exact(&mut buffer).unwrap();

    Ok(buffer)
}

pub fn host(is_public: bool, file_path_buf: PathBuf, name: String, password: Option<String>) {
    // Trim the password
    let password = password.as_deref().unwrap_or("").trim().to_string();

    // Generate private and public key
    let private = generate_private_key();
    let public = generate_public_key(private.clone());

    // Turn the file path buffer to a Path
    let mut file_path = file_path_buf.as_path();

    // Specify packaging type as Tarred if file is a directory
    let packaging_type = if file_path.is_dir() {
        types::PackagingType::Tarred
    } else {
        types::PackagingType::None
    };

    let info = UploaderInfo {
        public: is_public,
        name,
        file_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
        packaging: packaging_type,
        files_size: 3,
        public_key: Some(public_key_to_string(public)),
        hashed_connection_salt: None,
    };

    let tar_path = format!(
        "./tars/{}.tar.gz",
        file_path.file_stem().unwrap().to_string_lossy()
    );

    // If it is a directory set the tar path as file path
    if file_path.is_dir() {
        tar_dir(file_path.to_string_lossy().into_owned(), tar_path.clone());
        file_path = Path::new(&tar_path)
    }

    start_listener(info, &file_path, Some(password), private)
}

// Make a tar of the directory

fn tar_dir(file_path: String, tar_path: String) {
    let tar_gz = File::create(tar_path.clone()).unwrap();
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);

    tar.append_dir_all(".", file_path).unwrap();
    tar.finish().unwrap();
}

fn on_request_uploader_info(
    socket: UdpSocket,
    src: SocketAddr,
    uploader_info: UploaderInfo,
    salt_mappings: &mut std::collections::HashMap<SocketAddr, String>,
    file_size: u64,
) {
    let salt = salt_mappings
        .entry(src)
        .or_insert_with(generate_salt)
        .clone();

    // Update uploader_info with the salt
    let mut local_uploader_info = uploader_info;
    local_uploader_info.hashed_connection_salt = Some(salt);
    local_uploader_info.files_size = file_size;

    let serialized = bincode::serialize(&local_uploader_info).unwrap();
    socket
        .send_to(&serialized, src)
        .expect("Couldn't send data");
}

fn on_request_payload(
    socket: UdpSocket,
    src: SocketAddr,
    private_key: RsaPrivateKey,
    hashed_password: Vec<u8>,
    password: Option<String>,
    chunk_count: u64,
    payload_index: u32,
    file_size: u64,
    file_path: &Path,
) {
    // Decrypt the hashed password from the client
    let decrypted_key = match private_key.decrypt(Pkcs1v15Encrypt, &hashed_password) {
        Ok(key) => key,
        Err(_) => {
            log_error("Failed to decrypt password");
            return;
        }
    };

    let decrypted_password = match String::from_utf8(decrypted_key) {
        Ok(password) => password,
        Err(_) => {
            log_error("Failed to create password string");
            return;
        }
    };

    // Check if a password is provided by the host
    let password_ref = match password.as_ref() {
        Some(p) => p,
        None => {
            log_error("You must provide a password!");
            return;
        }
    };

    // Validate the clients password
    if decrypted_password != *password_ref {
        log_error("Wrong password");

        // Send back success false if the password is not provided
        let response_payload = Payload {
            success: false,
            index: 0,
            payload_count: 0,
            data: Vec::new(),
        };

        if let Ok(serialized) = bincode::serialize(&types::ReditPacket::Payload(response_payload)) {
            if let Err(_) = socket.send_to(&serialized, src) {
                log_error("Couldn't send data");
            }
        }
        return;
    }

    // Calculate the data range
    let chunk = payload_index as u64;
    let data_start = chunk * u64::from(PAYLOAD_SIZE);
    let data_end = (chunk + 1) * u64::from(PAYLOAD_SIZE).min(file_size);

    // Read and encrypt the file chunk
    let data = match read_file_chunk(&file_path, data_start.into(), data_end.into()) {
        Ok(data) => data,
        Err(_) => {
            log_error("Failed to read file chunk");
            return;
        }
    };

    let key = derive_key(password_ref);
    let encrypted_data = encrypt_with_passphrase(&data, &key);

    // Create and send the response payload
    let response_payload = Payload {
        success: true,
        index: payload_index,
        payload_count: chunk_count.try_into().unwrap_or(0),
        data: encrypted_data,
    };

    if let Ok(serialized) = bincode::serialize(&types::ReditPacket::Payload(response_payload)) {
        if let Err(_) = socket.send_to(&serialized, src) {
            log_error("Couldn't send data");
        }
    }
}

pub fn start_listener(
    uploader_info: UploaderInfo,
    file_path: &Path,
    password: Option<String>,
    private_key: RsaPrivateKey,
) {
    let file_size: u64 = std::fs::metadata(file_path).unwrap().len();
    let chunk_count = file_size.div_ceil(PAYLOAD_SIZE.into());

    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    log_info("Hosting...");

    let mut buf = [0; 1024];

    let mut salt_mappings: std::collections::HashMap<SocketAddr, String> = Default::default();

    // Listen for incoming packets

    loop {
        let (amt, src) = socket.recv_from(&mut buf).unwrap();

        let packet_data = &buf[..amt];
        let packet: types::ReditPacket = match bincode::deserialize(packet_data) {
            Ok(data) => data,
            Err(e) => {
                log_error(&format!("Received undeserializable packet: {:?}", e));
                continue;
            }
        };

        match packet {
            types::ReditPacket::RequestUploaderInfo(_) => on_request_uploader_info(
                socket.try_clone().unwrap(),
                src,
                uploader_info.clone(),
                &mut salt_mappings,
                file_size,
            ),
            types::ReditPacket::RequestScanStore(_) => scan::submit_scan_store(&socket, src),
            types::ReditPacket::RequestPayload(res) => on_request_payload(
                socket.try_clone().unwrap(),
                src,
                private_key.clone(),
                res.hashed_password,
                password.clone(),
                chunk_count,
                res.payload_index,
                file_size,
                file_path,
            ),
            unexpected => log_error(&format!("Received unexpected packet {:?}", unexpected)),
        }
    }
}
