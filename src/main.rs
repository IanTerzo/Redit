mod client;
mod encryption;
mod scan;
mod scan2;
mod server;
mod types;
mod utils;
mod words;
use argh::FromArgs;
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use types::UploaderInfo;
use std::path::Path;

/// Redit file sharing
#[derive(FromArgs)]
struct Cli {
    /// verbose output
    #[argh(switch, short = 'V')]
    verbose: bool,

    /// subcommand
    #[argh(subcommand)]
    command: Option<Commands>,
}

/// Subcommands
#[derive(FromArgs)]
#[argh(subcommand)]
enum Commands {
    Scan(ScanCommand),
    Host(HostCommand),
}

/// Scan network for Redit distributors
#[derive(FromArgs)]
#[argh(subcommand, name = "scan")]
struct ScanCommand {}

/// Host file on local network via Redit
#[derive(FromArgs)]
#[argh(subcommand, name = "host")]
struct HostCommand {
    #[argh(positional)]
    path: std::path::PathBuf,

    #[argh(positional)]
    name: String,

    /// make the content available to everyone
    #[argh(switch)]
    no_passphrase: bool,

    /// use a custom passphrase forcibly
    #[argh(option)]
    passphrase: Option<String>,
}

fn main() {
    let cli: Cli = argh::from_env();

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(_command) => {
                let availible_hosts = scan::scan_network(10000);
                println!("{:#?}", availible_hosts); // Visa upp dem fint.
                println!("Choose a host to connect to 0 - 10: ");

                let mut input = String::new();

                io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read line");

                let index: usize = input.trim().parse().unwrap();
                let selected = availible_hosts[index].clone();

                let filename = selected.0.file_name;
                let is_public = selected.0.public;

                if is_public == false {
                    // TODO: move to encryption module
                    let host_public_key_string = selected.0.public_key.unwrap(); // This should always be present if public is false
                    let host_public_key =
                        encryption::public_key_from_string(host_public_key_string).unwrap();

                    println!("password: ");
                    let mut password = String::new();
                    io::stdin()
                        .read_line(&mut password)
                        .expect("Failed to read line");

                    let password = password.trim();

                    let mut rng = OsRng;

                    let encrypted_password = host_public_key
                        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
                        .unwrap();

                    let mut data = Vec::new();

                    let first_payload = client::request_and_await_payload(
                        selected.1,
                        encrypted_password.clone(),
                        0,
                    ); // Request the payload at index 0

                    if !first_payload.success {
                        println!("Failed to recieve payload info from host");
                        return;
                    }

                    println!("{:#?}", first_payload);

                    let payload_count = first_payload.payload_count;

                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(true)
                        .open(filename)
                        .unwrap();

                    file.write_all(&first_payload.data).unwrap();

                    for index in 1..payload_count {
                        let payload = client::request_and_await_payload(
                            selected.1,
                            encrypted_password.clone(),
                            index,
                        );
                        data.extend(payload.data.clone());
                        file.write_all(&payload.data).unwrap();
                    }
                } else {
                    //idk
                }
            }
            Commands::Host(command) => {
                let password = command
                    .passphrase
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_string();

                let private = encryption::generate_private_key();
                let public = encryption::generate_public_key(private.clone());

                let info = UploaderInfo {
                    public: command.no_passphrase,
                    name: command.name,
                    file_name: Path::new(&command.path).file_stem().unwrap().to_string_lossy().to_string(),
                    files_size: 3,
                    public_key: Some(encryption::public_key_to_string(public)),
                    hashed_connection_salt: None,
                };

                server::host(info, "testdir".to_string(), Some(password), private)
            }
        }
    }
}
