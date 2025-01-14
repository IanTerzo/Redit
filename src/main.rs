mod client;
mod encryption;
mod scan;
mod server;
mod types;
mod utils;
mod words;
use argh::FromArgs;
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use std::io;
use types::UploaderInfo;
// move gen_private_key and gen_public_key to encryption
use client::connect_to_host;
use server::{gen_private_key, gen_public_key};
// This souldn't be done here
use base64::{decode, encode};
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
            // Nils fixar detta
            Commands::Scan(_command) => {
                let availible_hosts = scan::scan_network(1000);
                println!("{:#?}", availible_hosts); // Visa upp dem fint.
                println!("Choose a host to connect to 0 - 10: ");

                let mut input = String::new();

                io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read line");

                let index: usize = input.trim().parse().unwrap();
                let selected = availible_hosts[index].clone();
                if selected.0.public == false {
                    // TODO: move to encryption module
                    let host_public_key_string = selected.0.public_key.unwrap(); // This should always be present if public is false
                    let decoded_der = decode(host_public_key_string).unwrap(); // Base64 decode
                    let host_public_key = RsaPublicKey::from_pkcs1_der(&decoded_der).unwrap();

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

                    client::connect_to_host(selected.1, encrypted_password);
                } else {
                    //idk
                }
            }
            Commands::Host(_command) => {
                println!("Password");
                // Todo: Ask if it needs to be private or public, it assumes private now

                let mut password = String::new();

                io::stdin()
                    .read_line(&mut password)
                    .expect("Failed to read line");

                let password = password.trim().to_string();
                let private = gen_private_key();
                let public = gen_public_key(private.clone()).to_pkcs1_der().unwrap();
                let public_string = encode(public);

                let info = UploaderInfo {
                    public: false,
                    name: "Ian".to_string(),
                    files_size: 3,
                    public_key: Some(public_string),
                    hashed_connection_salt: Some("fdsfd".to_string()),
                };

                server::host(info, Some(password), private)
            }
        }
    }
}
