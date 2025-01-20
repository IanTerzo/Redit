use crate::encryption::{
    generate_private_key, generate_public_key, generate_salt, public_key_to_string,
};
use crate::logger::{log_error, log_info};
use crate::scan2;
use crate::types;
use crate::types::Payload;
use crate::types::UploaderInfo;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

fn read_file_chunk(file_path: &Path, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path).unwrap();

    file.seek(SeekFrom::Start(start)).unwrap();

    let chunk_size = (end - start) as usize;
    let mut buffer = vec![0; chunk_size];
    file.read_exact(&mut buffer).unwrap();

    Ok(buffer)
}

pub fn host(is_public: bool, file_path_buf: PathBuf, name: String, password: Option<String>) {
    let password = password.as_deref().unwrap_or("").trim().to_string();

    let private = generate_private_key();
    let public = generate_public_key(private.clone());

    let file_path = file_path_buf.as_path();

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

    start_listener(info, &file_path, Some(password), private)
}

fn tar_dir(file_path: String, tar_path: String) {
    let tar_gz = File::create(tar_path.clone()).unwrap();

    // Wrap it with a GzEncoder for gzip compression
    let enc = GzEncoder::new(tar_gz, Compression::default());

    let mut tar = Builder::new(enc);

    tar.append_dir_all(".", file_path).unwrap();

    tar.finish().unwrap();
}

pub fn start_listener(
    uploader_info: UploaderInfo,
    file_path: &Path,
    password: Option<String>,
    private_key: RsaPrivateKey,
) {
    let mut file_path = file_path;

    let tar_path = format!(
        "./tars/{}.tar.gz",
        file_path.file_stem().unwrap().to_string_lossy()
    );
    if file_path.is_dir() {
        tar_dir(file_path.to_string_lossy().into_owned(), tar_path.clone());
        file_path = Path::new(&tar_path)
    }

    let metadata = std::fs::metadata(file_path).unwrap();
    let file_size = u32::try_from(metadata.len()).unwrap();
    let chunk_count = file_size.div_ceil(16384);

    let socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    log_info("Hosting...");

    let mut buf = [0; 1024];

    let mut salt_mappings: std::collections::HashMap<SocketAddr, String> = Default::default();

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
            types::ReditPacket::RequestUploaderInfo(_) => {
                // respond with the uploader info. (includes the public key)
                let salt = match salt_mappings.get(&src) {
                    Some(salt) => salt.to_owned(),
                    None => {
                        let salt = generate_salt();
                        salt_mappings.insert(src, salt.clone());
                        salt
                    }
                };

                let mut local_uploader_info = uploader_info.clone();
                local_uploader_info.hashed_connection_salt = Some(salt);

                let serialized = bincode::serialize(&local_uploader_info).unwrap();
                socket
                    .send_to(&serialized, src)
                    .expect("Couldn't send data");

                continue;
            }
            types::ReditPacket::RequestScanStore(_) => {
                scan2::submit_scan_store(&socket, src);
            }
            types::ReditPacket::RequestPayload(res) => {
                let decypted_key = private_key
                    .decrypt(Pkcs1v15Encrypt, &res.hashed_password)
                    .expect("Failed to decrypt password");

                let decrypted_password =
                    String::from_utf8(decypted_key).expect("failed to create password string");

                if let Some(password_ref) = password.as_ref() {
                    if decrypted_password != *password_ref {
                        log_error("Wrong password");

                        let response_payload = Payload {
                            success: false,
					index: 0,
                            payload_count: 0,
                            data: Vec::new(),
                        };

                        let serialized =
                            bincode::serialize(&types::ReditPacket::Payload(response_payload))
                                .unwrap();
                        socket
                            .send_to(&serialized, src)
                            .expect("Couldn't send data");

                        continue;
                    }

                    log_info("Correct Password");

                    let chunk = res.payload_index;

                    let data_start = chunk * 16384;

                    let mut data_end = (chunk + 1) * 16384;
                    if (chunk + 1) * 16384 > file_size {
                        data_end = file_size
                    }

                    let data =
                        read_file_chunk(&file_path, data_start.into(), data_end.into()).unwrap();

                    let response_payload = Payload {
                        success: true,
						index: res.payload_index,
                        payload_count: chunk_count,
                        data: data.clone(),
                    };

                    log_info(&format!("{:#?}", data));

                    let serialized =
                        bincode::serialize(&types::ReditPacket::Payload(response_payload)).unwrap();
                    socket
                        .send_to(&serialized, src)
                        .expect("Couldn't send data");
                } else {
                    panic!("You must provide a password");
                }
            }
            types::ReditPacket::ClientConnectionInfo(_res) => {}
            unexpected => {
                log_error(&format!("Received unexpected packet {:?}", unexpected));
            }
        }
    }
}

